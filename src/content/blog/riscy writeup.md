---
author: atch2203
pubDatetime: 2025-04-22
title: riscy writeup
featured: false
draft: true
tags:
  - cybersec
  - writeups
description: Writeup for a pwn challenge in UMassCTF 2025
---
Looking at the challenge, we are greeted with two files: `qemu.txt` and `riscy`.

![[Pasted image 20250422165817.png]]

`qemu.txt` is simply an instruction file for running riscv64 using qemu.
```text
You may want to use qemu-riscv64 to run this program.  
qemu-riscv64 -g 4444 riscy  
gdb-multiarch riscy  
"target remote :4444"
```

## Static analysis