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
<div id="forensics" />
##### alien_transmission
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
XORing the hex with `jellyCTF` shows that the flag is XORed with itself shifted 3 bytes to the left. A script can reverse that:
```python
c = "06 1C 2F 38 3F 38 2C 29 09 0A 16 2D 1C 16 2B 31 17 1B 2D 0A 16 0F 18 1C 11"
c = c.split()
c = [int(i, 16) for i in c]
res = ""
key = "jel"
for i in range(len(c)):
    k = key[-3]
    next = c[i]^ord(k)
    key += chr(next)
    res += k
print(res)
```
flag: `jellyCTF{xorry_not_xorry}`

##### dizzy_fisherman
Here we are able to input the base for two people's AES encryption key. If you input 2 (or any number for that matter) you can easily brute force the exponent and get the key.
```python
from Crypto.Util import number
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def brute_force(base, res, mod):
    b = base
    for i in range(2, 10000+1):
        b = (b*base)%mod
        if b == res: return i

p = 63579193433447636138142180956143903452427972074605894864703396671022456098599
g = 2
pa = 12216650520779549051085807383600007441099464649139735571057936351615978497631
pb = 268435456 # thats crazy

cip = "7c78e0ee6710a27b97cfb37501e02cc0e4f8cf921ecb9a891793622361efaa6cc7618b790239761506f8f83fa49b974ac7618b790239761506f8f83fa49b974a"

sa = brute_force(g, pa, p)
sb = brute_force(g, pb, p)
key = pow(pa, sb, p)

encoded_key = key.to_bytes(32, byteorder='big')
cipher = AES.new(encoded_key, AES.MODE_ECB)

pt = cipher.decrypt(bytes.fromhex(cip))
print(pt)
```
flag: `jellyCTF{SOS_stuck_in_warehouse}`
##### really_special_awawawas
Using the [hint](https://crypto.stackexchange.com/questions/74891/decrypting-multi-prime-rsa-with-e-n-and-factors-of-n-given) showed that the RSA encryption used more than 2 primes.
I first read up a bit on how to break RSA:
- [stackoverflow](https://stackoverflow.com/questions/58750417/how-to-decrypt-an-rsa-encryption)
- [wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Decryption)

```python
n = 40095322948381328531315369020145890848992927830000776301309425505
e = 65537
cip = 35622053067320123838840878683947610930876835359945867019927573838

from sympy.ntheory import factorint
factors = factorint(n)
print(factors)
# {5: 1, 23: 1, 460465412038271581: 1, 757179525420813109550252454787205779901919127: 1}

factors = [(5,1), (23,1), (460465412038271581,1), (757179525420813109550252454787205779901919127,1)]
d = inverse(e, carmichael_lambda(factors))
print(d)
# 287458461584463336135331697997301511216944981741119712297623893

m = pow(cip,d,n)
h = hex(m)
print(h)
print(bytes.fromhex(h[2:]).decode())
```
flag: `jellyCTF{awawas_4_every1}`
##### the_brewing_secrets
The `rand()` function is seeded with the current time in seconds, so we can easily copy and use the number to build the passcode.
```python
passcodeLength = 6
bitmask = (1 << passcodeLength) - 1

libc = CDLL("libc.so.6")

# p = process("./a.out", stdin=PTY, stdout=PTY)
p = remote(host='chals.jellyc.tf', port=6000)

s = int(time.time())
# print(s)

libc.srand(s)
for i in range(10):
  r = libc.rand()
  # print(f"r{i} {r}")
  passcode = r & bitmask
  print(f"passcode{i} {bin(passcode)}")
  print(p.recvuntil(b"passcode"))
  p.sendline(bin(passcode)[2:].encode('utf-8'))

print(p.recvuntil(b"}"))

p.interactive()
```
flag: `jellyCTF{mad3_w1th_99_percent_l0v3_and_1_percent_sad_g1rl_t3ars}`
##### cherry
The goal here is to get three cherries, which corresponds to solving a linear system
```
19*a + 32*b + 347*c = -10992 (mod m)
22*a + 27*b + 349*c = -30978 (mod m)
19*a + 29*b + 353*c = -12520 (mod m)
```
Solving the system with sagemath gives the amount of spins we need to do for each mode for various modulo offsets:
```
sage: solve_mod([19*a + 32*b + 347*c == -30983,22*a + 27*b + 349*c == -7390,19*a + 29*b + 353*c == -481],m)
[(10469, 7226, 14158)]
sage: solve_mod([19*a + 32*b + 347*c == -10992,22*a + 27*b + 349*c == -30978,19*a + 29*b + 353*c == -12520],m)
[(4194, 29860, 25598)]
sage: solve_mod([19*a + 32*b + 347*c == -25974,22*a + 27*b + 349*c == -26744,19*a + 29*b + 353*c == -9122],m)
[(20582, 3380, 26344)]
```
At this point it look like spinning that many times will get the awascii32 lines to show the flag, and we can do that by modifying the code:
```js
function playCoin(n){
  spinMode = n;
  if (n == 0)       spinCounts = [10469, 7226, 14158];//slotSpins = [ 19,  22,  19];    you_won_c
  else if (n == 1)    spinCounts = [4194, 29860, 25598];//slotSpins = [ 32,  27,  29];   jellyCTF{
  else if (n == 2)    spinCounts = [20582, 3380, 26344];//slotSpins = [347, 349, 353];   herries!}
  updatePlaintextDisplay();
  updateModeDisplay();
}
```
![flag](https://github.com/atch2203/jellyctf/blob/main/crypto/cherry_dist/WWWWW.png?raw=true)
flag: `jellyCTF{you_won_cherries!}`

# misc
<div id="misc" />
<a href="#toc">back to TOC</a>
##### welcome
This was the hardest challenge ever
flag: `jellyCTF{L1k3_th15}`

##### watch_streams
Going to the description of [jelly's ctf stream](https://www.youtube.com/watch?v=QH8LKkIVHzI) gives the flag
flag: `jellyCTF{jerrywashere123}`

##### this_is_canon
Looks like huffman encoding, but I only have a vague idea of how it exactly works.
It took me a while to figure out what each character corresponded to in binary.
```python
out = "1000001010010011101111101011101011111010000010100100110000111001110111010000111011100111110100111100100110101111000001110010110110010001100011011001000011001110011101000110101100010110011111111"
flag = ""

class Node:
    # z is 0, o is 1
    def __init__(self, c=None):
        self.c = c
        self.z = None
        self.o = None


trees = {
    '_':"000",
    'e':"001",
    'l':"010",
    'y':'011',
    'j':'1000',
    'o':'1001',
    'r':'1010',
    'a':'10110',
    'c':'10111',
    'd':'11000',
    's':'11001',
    't':'11010',
    'u':'11011',
    'w':'11100',
    'f':'111010',
    'h':'111011',
    'k':'111100',
    'm':'111101',
    '{':'111110',
    '}':'111111'
}

root = Node()
for ch in trees:
    v = trees[ch]
    h = root
    for p in v:
        if p == '1':
            if h.o:
                h = h.o
            else:
                h.o = Node()
                h = h.o
        else:
            if h.z:
                h = h.z
            else:
                h.z = Node()
                h = h.z
    h.c = ch

it = root
for b in out:
    if it.c:
        flag += it.c
        it = root
    if b == '1':
        it = it.o
    else:
        it = it.z

print(flag)
```
flag: `jellyctf{jelly_your_homework_was_due_yesterday}`

##### is_jelly_stuck
Solving the crossword shows that you have to go to [Baba is you](https://hempuli.itch.io/baba-is-you-level-editor-beta) with the level code `jieu-dkxx`
I forgot to take a screenshot of the level, but you have to get the cat to sleep again with the "cat is sleep" thing facing horizontally, and from there you can push it down and be in the same block as "is".
The flag is made by matching the letters of the crossword with your movements (like cipher_check)
flag: `jellyCTF{krodflakarkt_k__aliases_c_led_ls}`

##### just_win_lol


# osint
<a href="#toc">back to TOC</a>
<div id="osint" />

# pwn
<a href="#toc">back to TOC</a>
<div id="pwn" />

# rev
<div id="rev" />

