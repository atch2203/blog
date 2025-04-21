---
author: atch2203
pubDatetime: 2025-04-21
title: The quest for unbreakable diabolo LED sticks
featured: false
draft: false
tags:
  - other
description: A journey of trials, errors, and RGB LEDs (with a side of magforce rings)
---
<style>
img[alt=altText]{
max-height:40vh;
width:auto;
}
</style>

# Links
[Diabolo rings](https://cad.onshape.com/documents/ef44f07510415427593272c5/w/335d813986e4bbf1b998e1ed/e/3d402b5cbd4970cf173c050d?renderMode=0&uiState=67dc828452500464e79a29ff)

[LED stick attachment CAD](https://cad.onshape.com/documents/2f172437386052dd5692cff2/w/3c3cbeae348244a1abd02d45/e/f236c0c66763af97218da1e9?renderMode=0&uiState=67dc802656e2f57f79daf283)

[BoM for custom sticks](https://docs.google.com/spreadsheets/d/1AGBjD4QgN3zay3sqjv-TY1QxXT6H7o_dQcXg4EoeE98/edit?usp=sharing)

[CAD for custom sticks](https://cad.onshape.com/documents/1d5338fab54cf7945d5026d9/w/bd0ecd5b70426e0669c48a16/e/12736169232025d556fdddc3?renderMode=0&uiState=680557fb16208c54fe85de3b)

[Code for custom sticks]()

Soldering/wiring image can be seen <a href="#wiring">here</a>

## Now onto how I got here...
I think that most people can agree that everything looks better if you add LEDs to it, and diabolo is no exception.
<video style="margin: auto;" width="50%" autoplay muted controls>
  <source src="/blog/assets/bigdawg.mp4" type="video/mp4">
</video>
<div align="center" style="color:#888888"><em>Shoutout to Bryant "big dawg" Lam</em></div>

However, I have an issue: Sundia's LED stick attachments are way to easy to break (especially if you hit the ground with them).
![altText](@assets/images/ledsticks/brokenattachment.jpg)
<div align="center" style="color:#888888"><em>You vs the guy she tells you not to worry about</em></div>

Since I wanted to do integrals with them (since I'm not good at vertax), I took it upon myself to make my own.

And thus began the quest for the unbreakable LED sticks...


## A humble beginning
In an effort to reduce my own work as much as possible, I attempted to copy and reuse as many parts of Sundia's LED attachment as much as possible. Unfortunately, the board with the LEDs on it was firmly epoxied in place, so I could only reuse the end cap.
![altText](@assets/images/ledsticks/ledapart.jpg)
<div align="center" style="color:#888888"><em>The end goal (for now)</em></div>

By the end of all of my test prints, I had a prototype of something that could 1) emit light and 2) be attached to the end of an LED stick. All that remained was to convert it to clear TPU and iron out the inner dimensions of the attachment.

![altText](@assets/images/ledsticks/ledprototype.jpg)
![altText](@assets/images/ledsticks/firstledattachment.jpg)
<div align="center" style="color:#888888"><em>First prototype working!</em></div>

![altText](@assets/images/ledsticks/noinfill.jpg)
<div align="center" style="color:#888888"><em>What happens when you do a mini-gen with no infill</em></div>

## The end...?
I was able to print the attachments out of clear TPU using the all campus makerspace's printers, and they worked like a charm.
![altText](@assets/images/ledsticks/comparison.jpg)
![altText](@assets/images/ledsticks/comparisondark.jpg)
<div align="center" style="color:#888888"><em>Not too bad!</em></div>

While my own LED attachment was better in some ways, it was worse than Sundia's in others:
- While it never broke, it also flew off the LED stick if you hit it too hard (or swung it too fast)
- The wire contact with the end cap wasn't very reliable, especially if you hit the attachment frequently

Both of these issues posed too much of an issue to be usable for vertax and integrals (where making a mistake leads to a dangerous projectile). Additionally, while it is similar in brightness to Sundia's LED sticks, it was a lot dimmer than their LED yoyo attachments.

![altText](@assets/images/ledsticks/dimbutterfly.jpg)
<div align="center" style="color:#888888"><em>The brightness (and image quality) is pitiful</em></div>

With no easy path forward, the first chapter on the LED stick saga concluded, and I moved on to greater endeavors.

## Onwards to fully custom LED sticks
Not satisfied with the TPU attachments, I thought to myself:
> If the attachment point between the LED attachment and the stick was the point of failure, what if we just made the whole stick ourselves and put LEDs along the whole thing?

And so I got back to work, designing a whole stick from scratch, attempting to design a better mounting mechanism:
![altText](@assets/images/ledsticks/attachmentpoint.png)
![altText](@assets/images/ledsticks/diywhole.jpg)
<div align="center" style="color:#888888"><em>A twist type locking mechanism</em></div>

To help maintain rigidity of the stick, I first tried PLA, but that broke quickly (more specifically, after 1 hit against the ground), so I switched to TPU with metal rods inside.
![altText](@assets/images/ledsticks/plastick.jpg)
<div align="center" style="color:#888888"><em>PLA after "lightly" touching the ground</em></div>

![altText](@assets/images/ledsticks/floppystick.png)
<div align="center" style="color:#888888"><em>Left hand: floppy stick (no metal rods)<br />Right hand: TPU stick with metal rods</em></div>

![altText](@assets/images/ledsticks/metalrods.jpg)
<div align="center" style="color:#888888"><em>TPU stick with metal rods inside</em></div>


These sticks *technically* functioned, but they were horrible to use for integrals since they were 55 grams each (leading to everything being painfully slow). For reference, plastic sticks are typically 37 grams each, and carbon sticks are around 30-33 grams each.

Also, now that the point of failure between the attachment and stick was fixed, we discovered a new point of failure: the end cap and the LED attachment exploding (no photo evidence, but the batteries flew over 30 feet away from where we were yoyoing).

In lieu of becoming another public safety hazard and wanting to avoid having to figure out how to cut over 20 grams off of a 3d print, I had to scrap these sticks and come up with a more novel approach.

![altText](@assets/images/ledsticks/interestingfailure.jpg)
<div align="center" style="color:#888888"><em>An interesting print failure for your visual amusement</em></div>

## The redemption of fully custom sticks

It was apparent that 3d printing is not the way, at least for making the whole stick. However, [Chris Pho](https://www.linkedin.com/in/christopher-pho/) showed me a diabolo group ([diabololution](https://www.instagram.com/diabolution/)) that made LED sticks by using clear tubing, which immediately gave me the idea to put a microcontroller and battery in a polycarbonate tube. 
Finding small and light parts was a challenge, but I eventually settled on Adafruit's Trinket M0 (15.3mm wide), 14250 batteries (14mm wide), and 16mm IDx18mm OD polycarbonate tubing. 

Throughout a few days, I came up with a simple design.
![altText](@assets/images/ledsticks/stickcad.png)
While the parts were shipping, I also soldered a prototype for the neopixel/electronics assembly.
![altText](@assets/images/ledsticks/firstneopixel.jpg)

Then I put it in the pipe when it arrived, and it worked immediately!
![altText](@assets/images/ledsticks/firstneopixelinpipenolight.jpg)
![altText](@assets/images/ledsticks/firstneopixelinpipe.jpg)

All that was left was to clean up the wiring a little and make a second stick. I also added a button for debugging/controlling the lights, since reflashing code was an absolute pain. <div id="wiring"></div>

![altText](@assets/images/ledsticks/schematic.jpg)
<div align="center" style="color:#888888"><em>Schematic; it's a lot more compact IRL (see below)</em></div>

Shoutout to the CICS Makerspace for letting me use their soldering irons and electronics.
![altText](@assets/images/ledsticks/incrediblefirstwiring.jpg)![altText](@assets/images/ledsticks/secondwiring.jpg)
<div align="center" style="color:#888888"><em>The difference in neatness is (almost) apparent</em></div>

![altText](@assets/images/ledsticks/secondwiringback.jpg)
![altText](@assets/images/ledsticks/firstledpair.jpg)
<div align="center" style="color:#888888"><em>First pair of LED sticks done!</em></div>

However, these sticks were still too heavy (43 grams) and had an unreasonable amount of drag/air resistance, so I had to optimize. Since there was plenty of empty space in the neopixel section, I decided to add a thinner pipe in that section (which also made the sticks look more like Sundia's normal sticks).

![altText](@assets/images/ledsticks/finalweight.jpg)
<div align="center" style="color:#888888"><em>36 grams!</em></div>

![altText](@assets/images/ledsticks/finalpair.jpg)

And that brings us to where I am today. 

<video style="margin: auto;" width="50%" autoplay muted controls>
  <source src="/blog/assets/poi.mp4" type="video/mp4">
</video>

## So what next?
I still have plans to make them better, since the drag/air resistance still feels off compared to normal sundia sticks. Here is a list of improvements that I'm planning to make sometime in the future:
- Use thin neopixels (5mm wide) and 6mm IDx8mm OD tubing for the thin part of the stick
	- This may cause flex issues, since I'm already feeling some flex with the 11mm IDx13mm OD tubing
- Make a version with no microcontroller and static lights (to decrease weight/thickness)
- Add a rubber button "cover" (like you see on gamepad buttons)
	- Right now, I have to use a screwdriver/something pointy to press the button, since it is fully contained within the stick

## Side quest: magforce rings
While at practice, I noticed that some TASC members used plastic rings for their magforces. However, the rings only came with certain magforces from our Sundia USA dealer, so I decided to figure out how to 3d print our own. One thing led to another, and I ended up designing rings for magforces, evos, and falcons. To be honest, designing the patterns in the rings took longer than tuning them due to my bad graphic/artistic design skills.
