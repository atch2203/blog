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

`riscy`, on the other hand, is the program that we're supposed to pwn. IDA doesn't have out of the box support for riscv, so I put it in ghidra, giving us the decompiled code.
![[Pasted image 20250422170114.png]]

## Static analysis
```c
void main(void){
  ssize_t readsize;
  ulong funcptr;
  undefined buf [516];
  int readsizeint;
  
  gp = &__global_pointer$;
  memset(&funcptr,0,0x208);
  printf("Hmm, riscy business happning at %p\n",&funcptr);
  puts("What do you want?");
  readsize = read(0,&funcptr,8);
  readsizeint = (int)readsize;
  if (readsizeint < 1) {
    puts("read error!");
    exit(1);
  }
  puts("You better not let this get more riscy");
  readsize = read(0,buf,0x200);
  readsizeint = (int)readsize;
  if (readsizeint < 1) {
    puts("read error!");
    exit(1);
  }
  (*(code *)(funcptr & 0xfffffffffffffffe))(1);
  exit(1);
}
```
Ess



## Dynamic analysis
Let's confirm what we think is happening. We are specifically looking for a few things:
- what is read/written into the first local variable (the function pointer)
- what is read/written into the buffer
- most importantly, what happens when our function pointer is called