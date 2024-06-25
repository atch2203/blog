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

check out [dungwinix](https://dungwinux.github.io/-blog/security/2024/06/24/jellyctf.html) for an unintended+easier solution

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

##### mpreg
Popping the file into a hex editor shows that it should be an mp4 file, so changing the `2avc1mpreg4` to `2avc1mp4` fixes the video.
flag: `jellyCTF{i_can_fix_her}`

##### the_REAL_truth
The image definitely has data encoded in it, but I wasn't able to figure it out without a hint. Filtering the red channel (since there's a cyan bar at the top) gives the flag in the data + some excerpt from [jelly's wiki](https://virtualyoutuber.fandom.com/wiki/Jelly_Hoshiumi). 
flag: `jellyCTF{th3_w0man_in_th3_r3d_ch4nn3l}`

Fun fact the text in the caard.co is also taken from the Profile section of her wiki

##### the_REAL_truth_2
Fun fact: I stumbled across `image_02` somehow without looking at `sitemap.xml`
XORing the images gives the flag
![flag](https://github.com/atch2203/jellyctf/blob/main/forensics/the_real_truth/Screenshot_20240619_024223.png?raw=true)
flag: `jellyCTF{tw0_h41v3s_m4k3_a_wh0L3}`

##### head_empty
I used the hint to figure out to use volatility3, and after watching a [guide](https://dfir.science/2022/02/Introduction-to-Memory-Forensics-with-Volatility-3), you just dump the password hashes and crack it with hashcat to get `jellynerd2`
flag: `jellyCTF{jellynerd2}`

##### head_empty_2
This one probably took me the longest(out of the ones I solved), with many dead ends.
I attempted to dump the files of the mspaint process and binwalk it, showing that there were a lot of png images. Unfortunately, they were just the microsoft app icons.

I also attempted to binwalk the entire memory dump, which did give false hope
`206700544     0xC520000       PC bitmap, Windows 3.x format,, 129 x 115 x 24`
but the bitmap was garbage data.

Using the hint showed that you needed to dump the memory of the process,  so I did
`p vol.py -f ../memory.dmp windows.memmap --dump --pid 4700 > ../memdump.txt`

Eventually, I stumbled across a post of [literally the same challenge](https://github.com/h4x0r/ctf-writeups/blob/master/Google-CTF-2016/For1/README.md) which just recommended to put the memory dump in gimp and scroll through it until you found "a contigeous block of non-random data". 
Doing so with width=1000 and height=6000, showed that there was indeed such a block in the memory, although upside down. Tuning to width=300 (the same dimensions as the [twitter post](https://x.com/jellyhoshiumi/status/1785919609872474201)) gave the complete image.
![alt text](https://github.com/atch2203/jellyctf/blob/main/forensics/headempty/evenbetterflip.png?raw=true)

flag: `jellyCTF{pa1nt_pr1nc355}`

# crypto
<a href="#toc">back to TOC</a>
<div id="crypto" />
##### cult_classic_1
This was just a series of mini-crypto puzzles:
1) The first letter of each line reads `PRINCESS`
2) b64->rot-3 gives `If you can decode this, you can have the next key: BIGNERD`
3) Vig decode `KMRYCTWG{` with it's corresponding `JELLYCTF{` gives `BIGNERD` as the key. Decoding the whole thing gives `NOT BAD, HERES A FLAG FOR YOUR EFFORTS SO FAR: JELLYCTF{THIS_IS_JUST_A_WARM_UP} HOWEVER YOUR JOURNEY IS NOT OVER, TAKE THIS KEY AND PROCEED FORWARD: ALIEN`
flag: `JELLYCTF{THIS_IS_JUST_A_WARM_UP}`
##### cult_classic_2
4) [brute forcing] a playfair cipher gives `ALIEN->ACOUSTIC` as one of the possibilities
5) Using a hint shows that you need to look at [luminary's lyrics](https://www.youtube.com/watch?v=1x6oPy3Hwcw), and each `#.#` corresponds to line.col. Decoding gives "Capitalize megalencephaly for the next ..."
6) Decoding a bacon cipher (with complete alphabet) gives `THEFINALPASSWORDISSADGIRL`
flag: `jellyctf{jelly_was_probably_older_than_these_ciphers}`

##### cipher_check
each clue corresponds to something in the form of `ANSWER____`, and filling in the board gives `follow moist duel xqc in detail on special lineup event he won mate in 6 moves!` Following the moves of the [game](https://www.youtube.com/watch?v=e91M0XLX7Jw) and putting the corresponding letters of the squares in order gives `istillloveit`.
flag: `jellyCTF{istillloveit}`

##### exclusively_yours
XORing the hex with `jellyCTF` results in ``
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

