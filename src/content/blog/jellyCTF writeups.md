---
author: atch2203
pubDatetime: 2024-06-24
title: jellyCTF
featured: false
draft: false
tags:
  - other
  - writeups
description: jellyCTF writeups
---
Sometime during the middle of last week I decided to actually start playing CTFs, and I remember dungwinix mentioned that jellyc.tf was going on for 2 weeks and that it was good for beginners (aka me). 

> go check his writeups at https://dungwinux.github.io/-blog/security/2024/06/24/jellyctf.html, he actually was the first solo team to full clear w/o hints

I used a lot of hints (almost all of them), but I was able to solve 10/10 web, 6/8 osint, 3/3 pwn, 8/10 crypto, 6/7 forensics, 5/5 misc, 3/3 rev.
![my "awards"](@assets/images/writeups/jellyctf/awardssmall.png)
<div align="center" style="color:#888888"><em>My "awards"</em></div>

<div id="toc" />
TOC:
- <a href="#web">web</a>
- <a href="#forensics">forensics</a>
- <a href="#crypto">crypto</a>
- <a href="#misc">misc</a>
- <a href="#osint">osint</a>
- <a href="#pwn">pwn</a>
- <a href="#rev">rev</a>
# web
<a href="#toc">back to TOC</a>
<div id="web" />
##### do_not_trust
Opening robots.txt gives us
```
User-agent: *
Disallow: /
# jellyCTF{g0d_d4mn_cL4nk3r5}
```

### vlookup_hot_singles
For the first stage, our goal is to impersonate the user "jelly" by modifying the JWT token. In the files provided, we are given the secret `singaQu5aeWoh1vuoJuD]ooJ9aeh2soh`, so we just copy the token into a [jwt.io](jwt.io) and modify the "user" field to "jelly". Sending a request to the /admin page with the new token gives us the flag, and access to part 2.
![alt text](https://github.com/atch2203/jellyctf/blob/main/web/vlookup_hot_singles/part1req.png?raw=true)
flag: `jellyCTF{i_am_b3c0m3_awawa_d3str0y3r_0f_f3m4135}`
##### vlookup_hot_singles_2
In the admin panel, there is a space to upload a spreadsheet and have the server send it back with columns added. I remembered a trick stolenfootball ([shoutout](https://stolenfootball.github.io/)) where you can unzip microsoft docx/xlsx files, so I made a blank spreadsheet and did that. The resulting files are xml, meaning that it's probably some xxe attack. Using a hint shows that the payload has to be in `docProps/core.xml`, and putting the xxe in there gives us the flag.

flag: `jellyCTF{th1s_1snt_a_r3d_0n3_r1gh7?}`

##### factory_clicker
The files provided show that there is an `/increment` endpoint for post requests, so just send a post request with a large number.
![alt text](https://github.com/atch2203/jellyctf/blob/main/web/factory_clicker/factoryoverload.png?raw=true)
flag: `flag jellyCTF{keep_on_piping_jelly}`

##### bro_visited_his_site_2
You can do SSTI with the `word` parameter, and our goal is to get to `FileIO`, which can be done with this chain: `dict.__base__.__subclasses__()[114].__subclasses__()[1].__subclasses__()[0]('/app/flag.txt').read()`

flag: `jellyCTF{rc3p1lled_t3mpl4te_1nj3ct10nmaxx3r}`

##### bro_visited_his_site
For some reason, this one was harder than its sequel, and using the [hint](https://ctftime.org/writeup/10895) basically gave the solution: `url_for.__globals__['current_app'].config['FLAG']`

flag: `jellyCTF{f1agp1ll3d_t3mpl4te_1nj3ct10nmaxx3r}`

##### aidoru
The goal here is to get to find the secret uuid of `"jelly"`. Looking at the other uuids, they look like a hash, and putting them in a hash cracker shows that it's md5. The md5 of jelly is `328356824c8487cf314aa350d11ae145`, and going to [https://aidoru.jellyc.tf/static/secret_data/328356824c8487cf314aa350d11ae145.json](https://aidoru.jellyc.tf/static/secret_data/328356824c8487cf314aa350d11ae145.json) gives the flag.

flag: `jellyCTF{u_r_the_p3rfect_ultimate_IDOR}`

##### awafy_me
This is a simple code injection; just put `a; ls` and then `a; cat flag.txt`
flag: `jellyCTF{c3rt1fied_aw4t15tic}`

##### awascii_validator
Our goal is to get our payload to `debug()`, but it is translated from awascii before it is sent to debug. Translating `;ls` results in `awawawawawawa awa awawa awa awa awa awa awawa awawa awa awa`, and sending it in shows that the flag is in `./flag`. To translate `;cat flag`, I used the python code form awafy_me (which for some reason prints backwards)
![alt text](https://github.com/atch2203/jellyctf/blob/main/web/awascii_validator/Screenshot%202024-06-18%20215128.png?raw=true)
flag: `jellyCTF{m4st3rs_1n_awat1sm}`
##### pentest_on_stream
A simple xss is easy to do, but to access the obs json file is more difficult. Using the hint led to the obs documentation, which shows that `window.obsstudio.getScenes` is what we want.
Inputting 
```html
<script>
window.obsstudio.getScenes(function (scenes) {
    document.getElementById("name").innerHTML=scenes[1];
});
</script>
```
gives the flag: `jellyCTF{y0u_CANT_ju5t_d0_that_dud3}`
# forensics
<a href="#toc">back to TOC</a>
##### alien_transmission
<div id="forensics" />
Popping the mp3 into a spectrum analyzer shows the flag:
![alt text](https://github.com/atch2203/jellyctf/blob/main/forensics/alientransmission/jelly.png?raw=true)
flag: `jellyCTF{youre_hearing_things}`

##### mpreg4
Popping the file into a hex editor shows that it should be an mp4 file, so changing the `2avc1mpreg4` to `2avc1mp4` fixes the video.
flag: `jellyCTF{i_can_fix_her}`

#####

# crypto
<a href="#toc">back to TOC</a>
<div id="crypto" />


# misc
<a href="#toc">back to TOC</a>
<div id="misc" />

# osint
<a href="#toc">back to TOC</a>
<div id="osint" />

# pwn
<a href="#toc">back to TOC</a>
<div id="pwn" />

# rev
<div id="rev" />

