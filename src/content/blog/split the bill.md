---
author: atch2203
pubDatetime: 2026-01-26
title: Split The Bill
featured: false
draft: false
tags:
  - coding
description: My experience with using AI to code a web app
---

> **tl;dr** I vibe coded a web app to split bills privately and with p2p/party functionality @ https://atch2203.github.io/split-the-bill; while claude built a functional app, the code itself is a mess and I wouldn't use rely on AI-generated code for real work

## The Problem
Last semester, I was eating dinner at a restaurant with some of my friends after a performance for KDC (shoutout to Miss Saigon!). However, as a group of 11 people ordering 22 items total, our receipt ended up totaling over \$200. Naturally, calculating the division reliably was not so easy, made even harder by the fact that some of us shared items.

Usually when I had to split bills, I would follow a simple algorithm:
1) find each person's subtotal (sum of their items before tax and tip)
2) calculate each person's "real total" = their subtotal * (the party's total+tax+tip / the party's subtotal)

> Another alternative would be to account for tax+tip individually, but that's technically more calculations.

However, having to do that for 11 people is a lot of manual work prone to errors, which is why I decided to spend a few days automating a quick task.

## "Coding" the app
Since seeing how productive claude code could be during CPTC this year made me decide to see how far it could go with this idea. I first started out with making a description of the whole app and user flow to guide the model in the right direction when starting out. To give a quick summary of my prompt:

```
I am making a web application called "split the bill" using svelte. It's main purpose is to be a client side only web app that can scan a receipt, assign people to what they bought, and then calculate what each person should pay. The user interface should be flexible, allowing users to add people, add receipt items, assign people, and more without forcing the user to follow steps.

<insert receipt scanning flow here>

<insert people assignment flow here>

<insert price calculation here>

Stretch goal: multiuser flow with trystero:
- Once the MVP is done, add the ability for peers to join a "party", and for people to automatically assign themselves items
```

I already had an idea of the libraries and frameworks I wanted to use:
- sveltekit with deno (just cause I wanted to try them out)
- tesseract.js or scribe.js for OCR on the receipt
- simple regex for parsing the scanned receipt
- trystero for P2P/multiuser functionality

> Apparently, although I didn't know it at the time, I was doing "spec-driven vibe coding," which imo is a cringe buzz word (isn't that just how normal product development and software engineering works?)

With that, I let the model go and do its thing, telling it to add the next thing or fix the current thing as it finished each part, and it was mostly smooth sailing.

### Some not so smooth sailing
Overall, I had a pretty good experience using claude. However, there are some notable issues that I came across when trying to get stuff done.

#### Running commands
I wrote almost no code, but when it came to validating the app or doing anything else from the command line, I did not trust claude at all. First off, it tried to use `npm` every time to run the app *despite it reading all the files in the project and seeing the `deno.lock` and `deno.json` files*. Also, it would try to use `curl` to see if the app worked, which is fine if my app was plain html with nothing else, but unfortunately, all it sees is the following due to the app being implemented using Svelte:
```html
<script>
{
	__sveltekit_8fw1bm = {
		base: new URL(".", location).pathname.slice(0, -1),
		assets: "/split-the-bill"
	};
	const element = document.currentScript.parentElement;
	Promise.all([
		import("./_app/immutable/entry/start.Xhew5Gn_.js"),
		import("./_app/immutable/entry/app.Cpoh_HBd.js")
	]).then(([kit, app]) => {
		kit.start(app, element);
	});
}
</script>
```
Because of that, my flow ended up mostly being "prompt claude -> wait a few minutes -> validate that the app works -> repeat", making the whole project seem more like a chore than something I actually wanted to do. 

> Another reason I didn't trust claude to run commands was due to stories I've heard of AI `rm -rf`ing people's projects. Additionally, while I'm reasonably sure I was secure, John Hammond has made [plenty](https://www.youtube.com/watch?v=_r_sLetar_o) [of](https://www.youtube.com/watch?v=Oiv3TaIR9UY) [videos](https://www.youtube.com/watch?v=r14c5jP-51A) detailing how attackers can trick models through invisible input and other tactics.

#### The unspecified logic and implementation specifics
If you look at the [receipt text parser](https://github.com/atch2203/split-the-bill/blob/main/src/lib/utils/receiptParser.ts), what you'll see is over 500 lines of typescript to apply regex to 6 different hardcoded patterns, with over 150 lines just being lists of regex patterns to catch edge case items (like tax, tip, subtotal, etc). While I did specify to use regex to identify items, I did not mean for it to make code spaghetti with constants all over the place.

This became a lot more apparent when I got to the implementation of p2p functionality. I first asked it to use Trystero, which it happily agreed to do, adding all the boilerplate to share state across peers. However, due to reliability reasons, I reverted the changes and asked it to switch to using PeerJS. When it started coding, I quickly realized that it was using a different protocol for updates:
- When I asked it to use Trystero, all the peers were equal and updates were sent as individual changes to the overall state.
- When I asked it to use PeerJS, all the guests would send their updates to a single host node that broadcast the whole app state on every change.
Both of these architectures are equally valid, but they made me realize that when you are thinking at a higher level, you are at the whim of whatever AI generates to "fill the logic gaps".

You might say that it's the programmer's fault for not reviewing all the code, but I argue that this should never be used for any real coding. Any real code an AI generates is code that somebody will have to maintain, and that means code that somebody will have to refactor when the AI decides to use a memory inefficient state sharing protocol, create unnecessary abstractions in state, or churn out 500 lines of unreadable regex.

#### Token usage
One of the main reasons this project took 3 days was that I got rate limited very often. I am on the claude pro plan using sonnet, and I found myself being limited after only 1-2 hours of coding (the session limit resets after 4 hours). This really made it hard for me to get on a roll, since I would always be monitoring my token usage and trying to plan my objectives around whether I would be in the middle of something when my limit hit.

## Conclusions
I will definitely admit: this project was very tuned to ai coding and is probably the best I'm going to get out of AI-generated code. I would think that most other projects would not be as smooth sailing, especially if you do not have at least as clear of a vision of the final product as I had for this one. I don't want to repeat myself (and others) too much, but I would never trust AI to generate large amounts of code for work or a bigger project.

One thing that I will say AI-generated code is good for is playing around and prototyping: it would have taken me a lot longer on my own to realize that scribe.js too slow for this project compared to tesseract.js or that Trystero sacrifices reliability for true decentralization when PeerJS achieves sufficient privacy with the speed I need.

Additionally, as a more security/backend developer, I will say that AI is great for pumping out generic and "modern" looking frontends when you don't want to do it yourself.

Once again, you can find the project at https://atch2203.github.io/split-the-bill and the (spaghetti) code on my [github](https://github.com/atch2203/split-the-bill/tree/main), and I hope that you find this free tool useful (I'm more proud of the idea than the actual coding of it).