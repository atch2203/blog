---
author: atch2203
pubDatetime: 2024-05-07
title: Old Cybersec Workshop Notes
featured: false
draft: false
tags:
  - cybersec
  - notes
description: Compilation of old notes I took at various UMass Cybersec Workshops
---

# Caesar Creek Hardware Workshop

Taken 04/02/2024

# What is Caesar Creek (cc-sw)

US offensive security contractor
~100 employees
Areas they work in:

- Hardware sec
- rev
- VR
- Exploit dev
- protocol analysis
- tool development
  Their targets are broad/change(usb, wifi, apks, bluetooth, etc), so not always comfortable/specialized

Cool benefits: snacks, gym membership, housing,

### Resume

Good stuff for resume for Caesar creek:

- OS, computer architecture, security classes (usually for upperclassmen)
- Programming
- networking!!!!
  Projects are more important! (They don't have to be big/important to anybody; literally anything works)
- if no projects, caesar creek also has challenges on their career portal
- also show that you've done ctfs
  Skills to have: Ghidra/IDA, GDB, Assembly, Wireshark, Python, C, C++, ROP/Shellcode/pwntools

Good resources:

- csaw.io/ctf
- dreamhack.io
- pwnable.kr
- pwnable.tw
- pwnable.xyz
- microcorruption.com

Application/interview process

- Virtual
  - CC-SW overview
  - resume review
  - technical challenges
- onsite
  - meet people
  - hands on technical interview
  - call with CEO

# The technical talk

#### What is fault injection?

By messing with the voltage for a short time, you can cause undefined behavior
Types:

- Voltage glitching: messing with voltage
- Clock glitching: inserting clock cycles
- EMP glitching

### Target: STM32

has different RDP(read out protection) levels

- rdp 0, all unlocked
- rdp 1, can read ram+peripherals, but no flashing
- rdp 2, flashing locked, debug locked, ram locked

They have a voltage regulator, but it can be bypassed through Vcap1 and Vcap2
The basic idea:

- when the cpu does a compare between 0 and 1, we can change the voltage so it works

How the specific attack works

- drop from rdp2 to rdp1, done during bootrom exec and gives bootloader access
- then go from rdp1 to rdp0 through the system memory thing

### rdp2 to rdp1

two variables: where to place glitch (relative to a trigger), how long to pull down voltage(but not too long)

- note that this will not be consistent; _undefined behavior_ means that same vars will not give same result

There is no accurate trigger (reset line has 20microsecond var)

- Power analysis is accurate: start the countdown when a certain power consumption/pattern happens

Steps to take

1. power on
2. wait for trigger/power peak
3. wait x clock cycles
4. pull down
5. check if in rdp1

Issue with voltage glitching: it has a chance to brick
Solution: use EMP using PicoEMP

- problems: what shape of EMP coil? where to place EMP?

Now instead of iterating over time (known from voltage glitch), you just need to iterate over placement(xyz) of EMP and shape of coil

- it works, but it's not as consistent

### rdp1 to rdp0

extracted firmware with openOCD
steps to test 0) run 1st glitch 1) write payload for GO command (when using it)

1. send read command (later changed to GO command)
2. send emp to 'set' rdp to 0
3. send place to read
4. hopefully works

note that 1st glitch has to happen every time you want to run second

- however, by pulling reset line up momentarily you can bypass 1st glitch while in bootloader

---

# From CTFs to real world bugs

taken 11/07/2023

### differences

- size & complexity: rl is bigger and complex
- attack surface is less clear: ctf is cmd line, etc, rl is net traffic, etc
- known vulns: ctf usually doesn't have prev info, rl applications do
- mindset: ctf is guaranteed vuln, rl is not; know when to give up

- rl exploits require chaining together vulns
- rl exploits usually are automated, ctf is not

### approaching targets

- figure out existing research; existing vulns
  - even in industry you'll have to scavenge for old github repos/websites
  - google translate works; not all people use english
- identify attack vectors
  - things that are important
  - things that look exploitable (maybe from reserach)
- figure out the map of target; how things communicate/work

### manually(looking at code) finding bugs

self-contained: easy vuln from insecure thing (gets(), unprotected eval, unsanitized input)

invariant based: common patterns, eg thread modifying buffer or use after free

### automated bug hunting

automated static analysis: using filters to find specific things that could be vuln (functions that take char\* input), decompiler scripting, variant analysis(looking for a specific known bug pattern)

fuzzing: random input

other: using print statements or debugger in source code to figure out what's going on, dbi framework to determine flow of data (eg wireshark packet tracing)

### triaging crashes

usually not used with ctfs  
sometimes can help with figuring out where a bug could happen, but is very tedious

## chosing targets

- straightforward tiny codebases
  - good for learning/feeling good
- well documented open source
  - lots of posts/information about it
  - can pull request to fix
- poor security embedded devices
  - closed source, usually not audited/patched
  - company usually won't care

## examples

### router

hardware uart didn't lead to anything  
ping webpage had command injection  
you could access ping webpage with no session token

### music player

used an open source fuzzer to communicate with kernel (by reading/writing from random files) until it crashed  
triaged crash and found the source code on google
found buffer overflow in source code

---

# OSINT

taken 12/27/2023

short for open-source intelligence  
used for information gathering

- it's also a job, people do osint on bad actors and govs use it to figure out
- can also be used to audit opsec
  doesn't include "hacking techniques" (eg dirbuster, stuff that would be considered malicious)

# OSINT tools

Different search engines sometimes give different results  
eg internet explorer or duckduckgo can have different results

## Google dorking:

- site:kkms.us
  - filters results to the domain
    [cheat sheet](https://gist.github.com/sundowndev/283efaddbcf896ab405488330d1bbc06)

### dorking in general

search engines in general (eg twitter search, other)

## wayback machine

You can take snapshots yourself in case you don't want something to get deleted

## google caching

just put "cache:" in front of the url eg "cache:https://www.merriam-webster.com/dictionary/test"  
also in google search results click the three dots next to a result and then in the list there will be "cached" option  
![Alt text](@assets/images/osint.png)  
google saves some websites as caches, bascially a snapshot like wayback machine

## view source

both ctrl+u and ctrl+shift+i  
-ctrl+u better for searching
-ctrl+shift+i better for debugging, finding element

## querying apis manually

eg onedrive api will give metadata of files  
search up the api docs to figure out information

## exiftool

it's cool  
metadata, geolocation, date

## shodan.io

search engine for internet devices/iot stuff  
gives a lot of info; ports open(nmap scan), cloud provider, domain info, subdomains, etc

# other stuff

not all links are the same, you can tell if a link changes

Common links:

- robots.txt
- sitemap.xml
- .git

there's a tool online to determine if an email address exists

you can unzip .docx for more data

you can find a lot of stuff online

- github
- instagram
- twitter
- linkedin
- dropbox/file hosts

From this stuff you can find names/potential passwords, and determine if a person has an insecure password

- [epieos.com](https://epieos.com/): finds social media/accounts related to an email

online dns tools

- https://mxtoolbox.com/SuperTool.aspx
- subdomain finders

# Kali tools

### sherlock

takes a username and looks for it on plenty of social media websites (a **lot** of websites)  
there's similar tools online, sherlock is not the only one

### harvester

osint on a company/domain
gets webpages, company emails, etc

## maltego ce (very powerful for osint)

takes in various information (email, name, url)
and will try to find connected information (like a tree)  
works by specifying transformations to find related images, websites, etc  
a lot of the time it will give out garbage (especially for all transformations)  
utilized other tools (wayback, 10 pages of google)

## dns tools

- whois: info on domain; who registered, when, where, phones, emails
- nslookup: gets ip of domain and vice versa
