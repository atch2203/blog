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


### Separating the modules
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

Spanning between these modules are control signal wires, data wires, and power wires. (mostly) Everything else is self contained in each of the modules.

![[rotated-20250218_161732.jpg]]
<div align="center" style="color:#888888"><em>TODO label spanning connections</em></div>




## Addendum: designing the computer