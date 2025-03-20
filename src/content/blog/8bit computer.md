---
author: atch2203
pubDatetime: 2025-03-19
title: How to take apart an 8 bit computer
featured: false
draft: true
tags:
  - other
description: template
---
Last semester, I took an honors colloquium for CS 335: Inside the Box: How Computers Work. The main section of the class was all about the different levels of technology that goes into a computer, from how transistors work to logic gates to processor components and more. For the colloquium project, I teamed up with [Sagnik Pal](http://www-edlab.cs.umass.edu/~sagnikpal/) to build an 8 bit computer out of some (not so) basic chips.

# Separating the modules
For this tutorial, you will need one (1) 8 bit computer. (Unfortunately, I only remembered to take photos as I was disassembling it). If you want to build an 8 bit computer, you can follow these steps in reverse order.

Our whole computer consists of 8-9 main modules:
- clock
- RAM
- registers
- ALU
- LCD display
- program ROM + program counter
- instruction decoder
- the bus


TODO illustrate this with labels for modules
![[rotated-20250218_161732.jpg]]
<div align="center" style="color:#888888"><em>Our computer running a Fibonacci program</em></div>

Spanning between these modules are control signal wires, data wires, and power wires. Everything else is (mostly) self contained in each of the modules.

![[rotated-20250218_161732.jpg]]
<div align="center" style="color:#888888"><em>TODO label spanning connections</em></div>

## Removing control signal wires and the bus
The first step in disassembling the 8 bit computer is to remove all the control signal wires. These connect every module to the instruction decoder/control unit and the clock, so you want to get rid of them first so they don't get in the way of the rest of the disassembly.

Now it's a lot easier to see each of the modules and their connections.
![[rotated-20250218_162312.jpg]]
<div align="center" style="color:#888888"><em>The computer without control signals</em></div>

At this point, if you ever want to debug your computer, you can wire the signals to positive/negative power manually and single step the clock. This helps a lot when trying to debug whether each instruction has the right control signals.

We can also remove the wires connecting everything to the bus. In this basic computer, there is a single bus that all data is passed through, including ALU outputs, RAM addresses, program constants/immediates, and more.
![[20250218_162750.jpg]]
<div align="center" style="color:#888888"><em>Having organized bus wires helps a lot with disassembly</em></div>

Now, we are left with the individual module groups.


## The registers and ALU
In this computer, we had 2 registers and 1 ALU.

![[20250218_162524.jpg]]
The two yellow wire groups in the image above connect the outputs of the two register chips to the inputs of the ALU.
Removing the connecting wires between the two boards shows the inputs/outputs for each board more clearly.

Our register module contains 2 377 chips, and have the following i/o:
- input: clock, write register A, write register B, 8 bit data in
- output: register A, register B
![[rotated-20250218_163127.jpg]]

The ALUs we used were [2 4 bit fdsafds](TODO), and we had to add a buffer to di
![[rotated-20250218_163036.jpg]]


## The RAM
Chip Weems had some RAM lying around (link), so we just used 
![[rotated-20250218_162927.jpg]]

## The clock
![[20250218_162609.jpg]]


## ROM + PC
![[rotated-20250218_163003 1.jpg]]

## Instruction decoder
![[rotated-20250218_163005.jpg]]

## LCD display
![[rotated-20250218_163003.jpg]]


### The aftermath
Once you are done, you should have the following parts:


## Addendum: designing the computer, control signals, and debugging

Debugging/testing
![[20241117_145416.jpg]]

![[20250218_162937.jpg]]

![[20250218_163008.jpg]]