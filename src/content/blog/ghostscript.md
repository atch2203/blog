---
author: atch2203
pubDatetime: 2025-10-23
title: Ghostscript CVE-2025-27835 Analysis
featured: false
draft: true
tags:
  - cybersec
description: An analysis of the exploit chain in CVE-2025-27835
---

Outline:
- *background of this: cs367, highly recommend it - overview of class*
- *final project - analyze and recreate cve*
- *we looked at CVE-676767676767 - really recent at the time*
- *background on cve/target*
	- *ghostscript - pdf generation tool - open source; used in many other apps*
	- *cve author - focused on ghostscript*
- *the exploit goal*
	- *dnosafer/exec shell commands bit - history*
- *the vulnerable code - buffer overflow*
- *how to get there?*
	- *setup - fonts* 
- the actual buffer overflow - what is hits
- type confusion
- arb rd and wr
- traversing dl heap to find config object
- setting bit
- boom we're done
- link to richard's fixing

<style>
img[alt=altText]{
max-height:30vh;
width:auto;
}
</style>

# Some background
This project was done in a group of 5 people for CS 367 (Reverse Engineering and Exploit Development). **I highly recommend CS 367 for anybody that can take it**, as it teaches how to understand assembly, memory, and exploit chaining at a fundamental level that is generalizable outside of specific frameworks (simple ret2win, house of balls, etc). The class also exercises your ability to think outside the box to construct solutions (and as a small bonus, you'll get a lot of useful real world advice from the GOAT Professor Lurene).

For the final project, our group selected a CVE to analyze and recreate. Since we had some high expectations from the professor (all 5 of our members were in the cybersec club), we decided to go big with a very recent CVE in Ghostscript: CVE-2025-27835.

## What is Ghostscript?
To put it shortly, Ghostscript is a PDF rendering tool and Postscript interpreter that allows you to generate and modify PDF files with Postscript commands. It's used in many applications that deal with PDFs, such as Inkscape, GIMP, LibreOffice, and more. Because of this, Ghostscript is a high valuable target for exploitation.

You can find old releases of Ghostscript at https://github.com/ArtifexSoftware/ghostpdl-downloads/releases. The version our CVE exploits is `10.04.0`.

### The goal: -dSAFER to -dNOSAFER
[Since version 9.50](https://ghostscript.readthedocs.io/en/gs10.05.0/Use.html#dsafer), Ghostscript defaults to the `-dSAFER` flag, which places controls on file read/write access and shell command execution. As you will see later, the goal of this CVE is "disable" the `-dSAFER` flag by setting the `path_control_active` variable from `1` to `0`, thereby allowing shell commands to be run.

The author of the CVE that we looked at also released several other CVEs in Ghostscript around the same time. 
- [CVE-2025-27835](https://bugs.ghostscript.com/show_bug.cgi?id=708131) - the CVE we examined
- [CVE-2025-27832](https://bugs.ghostscript.com/show_bug.cgi?id=708133)
- [CVE-2025-27831](https://bugs.ghostscript.com/show_bug.cgi?id=708132)
- [CVE-2025-27836](https://bugs.ghostscript.com/show_bug.cgi?id=708192)
- [CVE-2025-27830](https://bugs.ghostscript.com/show_bug.cgi?id=708241)
- [CVE-2025-27833](https://bugs.ghostscript.com/show_bug.cgi?id=708259)
- [CVE-2025-27837](https://bugs.ghostscript.com/show_bug.cgi?id=708238)
- [CVE-2025-27834](https://bugs.ghostscript.com/show_bug.cgi?id=708253)

Looking at the exploit code, they all seem to be doing some magic before finally calling a shell command in the form `(%pipe%id) (w) file`. 

## CVE-2025-27835
> It seems that in the conversion of glyphs to Unicode, there was once a transition from counting in shorts to counting in bytes, and the function `zbfont.c:gs_font_map_glyph_to_unicode` mistakenly copies twice the amount of data. The result is an overflow of the destination buffer.
- zhutyra, PoC author

The vulnerability is simply a buffer overflow in a line in `zbfont.c`. The code incorrectly assumes that length of the unicode string is in shorts and not bytes.
```diff
zbfont.c
- memcpy(unicode_return, v->value.const_bytes, l * sizeof(short));
+ memcpy(unicode_return, v->value.const_bytes, l);
```
However, making an exploit for this is not so trivial. We have two questions to answer:
- How do we even get to this vulnerable code with attacker controlled buffers?
- How can we gain control once we utilize this primitive?

As shown in a [short blog post](https://www.cve.news/cve-2025-27835/) about this CVE, to get to the vulnerable code in `zbfont.c`, we need to set the `FontName.Encoding` to use a really large string *in the encoding function*.
```postscript
%!  
% Create a font with a very large glyph name.
10 dict begin
  /Encoding 256 array def
   1 255 {Encoding exch /.longglyphnamelongglyphnamelongglyphname exch put} for
  /FontType 1 def
  /FontName /ExploitFont def
end
/ExploitFont exch definefont pop

% Try to use the glyph (triggers conversion)
newpath 100 100 moveto (A) show
showpage
```

We can also see a similar structure in the exploit (setting a font with a large, except with some special formatting to weaponize this crash:
```postscript
...
/Myfont  
<<  
   /FontName /Myfont  
   /FontType 1  
   /FontMatrix [1 0 0 1 0 0]  
   /Private << /lenIV -1 /Subrs [ <0E> ] >>  
   /Decoding 0  
   /Encoding [ /cs0 /cs1 /cs2 ]  
   /CharStrings <<  
       /.notdef <0E>  
       /cs0 { TEXT 0 1 put /TARGET 312500 array def TARGET REFIDX OBJARR put }  
       /cs1 <0E>  
       /cs2 { DONE }  
   >>  
   ...
>>  
.buildfont1  
/FONT exch def  
/FONTNAME exch def  
  
FONT setfont  

...
  
FONT /FontInfo get /GlyphNames2Unicode get 1 SOURCE1 put  
FONT /CharStrings get /.notdef undef  
TEXT 0 0 put  
TEXT 1 2 put  
0 750 moveto  
TEXT show  
...
```
You can see that instead of making an arbitrarily long string as our overflow, we use a target array and place a target object at a specific index in the array.

I won't go into how this postscript code results in use getting to the vulnerable code path since I mainly focused on getting control from the buffer overflow.

# The fun stuff - from overflow to control
In addition to finding how to get to `zbfont.c`, we also need to figure out how each buffer was set up to


## The setup before the overflow

> image of before the overflow


> image of the buffer sizes/offsets



> image of the overflow
- the actual buffer overflow - what is hits
- type confusion
- arb rd and wr
- traversing dl heap to find config object
- setting bit
- boom we're done
- link to richard's fixing