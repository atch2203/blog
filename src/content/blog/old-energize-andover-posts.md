---
author: atch2203
pubDatetime: 2023-12-01 #2022-09-23T15:22:00Z
title: Old Energize Andover Posts
featured: false
draft: false
tags:
  - energize andover
description: A collection of my blog posts from Energize Andover in 2021.
---

A few years ago during the pandemic, I joined Energize Andover, and here are the blog posts I wrote while in it.

# Day 1

## 2021-01-16

This is my first post!
I just got my blog set up, and will start working on the pandas exercises soon.
One thing I want to do, though, is to make this blog without jekyll, because the format doesn't allow for any easy navigation.
That'll be done sometime in the far future; I forgot most, if not all, of my knowledge on web development.
For now, I'll just start learning pandas and other python libraries.

# Day 2

## 2021-01-17

I started doing the pandas exercises today, but pycharm for some reason won't render jupyter notebooks, so I'm doing the exercises from github.
I've looked at the exercises, but I wasn't able to do any of them, so I had to look at the solutions.
Tomorrow, I'll look over the pandas documentation while I do the exercises.

I've also started on trying to make a non-jekyll website using React, but I haven't gotten very far. I've only installed it and created a simple webpage as of now.

# Day 3

## 2021-01-19

Today I redid the pandas chipotle exercise from scratch. It was a bit hard at first, but the later exercises became easier as it was more clear on what they wanted.

# Meeting 1

## 2021-01-20

Today we went over the first pandas exercise. Fisher also shared a document detailing how connect to the server and use poetry and pandas.

I tried to get a non-cookie cutter jekyll blog running, but there were a lot of technical issues. After some debugging with Fisher, we were able to find out that the problem was in the \_config.yml file. I deleted some lines in it, and it magically worked. However, it only works with the minima theme.

# Meeting 2

## 2021-02-03

Fisher showed rss readers and how to add blogs to them. He also shared an article on different methods of looping over arrays and how vectorization is different from applying lambdas.

# Meeting 3

## 2021-02-10

Today Fisher introduced the Energize Andover shared drive. On it were some documents with weekly meetings, plans, and members. We went over the plans for a curriculum for new members.
We also discussed how the club should operate from now on, and how new members should be accepted. We discussed some challenges with being able to accomodate new members, and how the club should be organized to fit newer members.
We decided not to accept people through the club fair, as the amount of new members that we could get might be too much to handle. Instead, we will likely accept people through AP Java and AP CS classes.

Since next week is winter break, we will have a lot of time to work on projects. However, I don't have any projects I'm working on.

# Meeting 4

## 2021-02-24

Today we discussed some ideas on the club's future. Fisher told us that there are some opportunities to share stuff with the AGAB. We also discussed a possible curriculum for new members and mentor/apprentice groups, as well as a monthly mailing list to keep everybody up to date.

# Meeting 5

## 2021-03-17

Today we went over the curriculum that Fisher made and revised it to make sure that new members wouldn't miss anything. I also learned some new topics, such as EAFP vs LBYL. I was also introduced to the Building Energy API, and was given a small assignment to get used to using it.

# Meeting 6

## 2021-03-31

Today we went over the code that I made for the Buidling Energy API. Fisher also showed his own code for the same assignment, and it was a lot better than mine. I learned some new things, such as list comprehension, converting dataframes to lists, and that you can chain dataframe functions.

# Meeting 7

## 2021-04-07

Today Fisher introduced the cloud shell as an alternative to VMs and the Energize server. It has its own disadvantages, but it's a lot simpler. I've never used it before, but it seems that there is a lot of functionality to it, with all of the tabs on the side and the packed interface.

# Meeting 8

## 2021-04-29

I just cloned my blog onto google cloud shell, which we decided to do last meeting. Right now it's very laggy in the shell, but there's no lag in the editor. I think that I'll use this from now on, as it takes time to boot up a vm every time I edit my blog.
Fisher talked about how we can apply stuff from AP Statistics to things we do in Energize Andover. He also mentioned how his Amazon Alexa project has security vulnabilities and cannot be used, so he will be focusing on creating the curriculum.
Since we're going back to in-person school next month, we might be able to do in-person meetings, which I've never attended before.
My next assignment is to plot the data from the previous assignment using matplotlib. However, my solution to the previous assignment was not very good, so I will redo that first.

# Meeting 9

## 2021-05-06

Today Fisher went over the assignment from last time. We also found out some interesting things, such as what happens when a module and package have the same name on the same level.

Things I learned:

- How packages and modules work/the difference
- \_\_init\_\_ in packages
- How to use modules that are part of imported packages
- The purposes of different files in the default poetry project
- Some markdown syntax to make this list

# Meeting 10

## 2021-05-13

Today we went over assignment 3, which I had a few problems with importing on. It turns out that relative imports are very hard to use, and that the root directory cannot be a package. After debugging my code with Fisher a lot and having a lot of random errors, we got everything to work.

Things I learned today:

- The root directory cannot be a package
- Using python3 without -m doesn't work with imports while python3 -m does
- You should only be able to run python3 from the root directory
- Context managers
- Imports cannot contain multiple levels
- touch makes empty files
