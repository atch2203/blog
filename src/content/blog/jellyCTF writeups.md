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

##### vlookup_hot_singles_2
In the admin panel, there is a space to upload a spreadsheet and have the server send it back with columns added. I remembered a trick stolenfootball ([shoutout](https://stolenfootball.github.io/)) where you can unzip microsoft docx/xlsx files, so I made a blank spreadsheet and did that. The resulting files are xml, meaning that it's probably some xxe attack. 

# forensics
<a href="#toc">back to TOC</a>
<div id="forensics" />

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

