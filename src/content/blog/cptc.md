---
author: atch2203
pubDatetime: 2026-02-03
title: An Uncomprehensive Guide to Doing Well in CPTC
featured: false
draft: false
tags:
  - cybersec
description: Things I learned while competing in the Collegiate Penetration Testing Competition
---

<style>
i {
  color: #888888;
}
</style>

Last ~~week~~ month, the UMass Cybersecurity club sent a team of 6 people to compete in the Collegiate Penetration Testing Global Finals. We ended up placing 3rd out of the 12 teams who made it to the finals, and our whole team definitely learned a lot about both pentesting as well as the power of claude code. This is most likely the last time I compete in CPTC, so I wanted to provide my experience and thoughts on this Finals as well as CPTC as a whole.

# What is CPTC?
CPTC stands for the Collegiate Penetration Testing Competition, and in the competition, as you may have guessed, different colleges compete to see who is "better" at penetration testing.

This competition is starkly different from CTFs, hack the box, and other online events in a few ways. While technical ability does give a team a leg up, it is not a major decider of the winning team. In fact, the technical section contributes only 30-40% of the total score. The majority of the points instead came from being professional with the client (aka role playing) and understanding how technical vulnerabilities contribute to the bigger company picture.

> For anybody who has done CCDC, this competition is a lot more chill during the engagement but you get almost no rest, since you are either pentesting or writing the report during the whole time.

Additionally, due to the more realistic setting, the vulnerabilities are not as technically advanced. While teams sometimes find some really cool or advanced vulnerabilities, for each technically advanced one, there are at least 5 other easy findings (eg plaintext creds in javascript, no authentication on admin panel, etc). Keep in mind that in the bigger picture, more technically advanced = lower chances of exploitation in the real world.

# Overview of the competition
During Globals, teams are given access to the company network for 16 hours split over 2 days (plus one night for checking in and one day for presentations/awards). In regionals we only get 8 hours on 1 day (plus one day for awards), making the event and report a lot more brief.

![altText](@assets/images/cptc/cptcglobalsschedule.png)
<div align="center" class="caption"><i>Finals schedule for CPTC 11</i></div>

![altText](@assets/images/cptc/cptcregionalsschedule.png)
<div align="center" class="caption"><i>Regionals schedule for CPTC 11</i></div>

The whole objective of the competition is "do well as if you were a pentesting consulting team hired by a company." There are multiple factors that go into this:
- Do reasonably well at finding vulnerabilities/issues in the company's services/technology
- Report said issues in a clear and coherent way to the company through a report and presentation
- Be professional at all times, and don't cause issues for the client aka DFIU

During the event, you will mostly be on-site during the day and in your hotel at night.

## When you are on-site (environment access and injects)
When you are on-site, you will either be getting information about the competition from the organizers, or you will be sitting in a room with your team and 6 laptops/university computers (regionals/finals). During this time, you will be able to rdp into attack boxes in the company network to pentest.

> In previous years, we RDPed into a windows machine, and then we could ssh into a kali machine, but 2 years ago they changed it so that we RDPed into the kali machines from the windows machines (RDPception!).

![altText](@assets/images/cptc/cptcnetworkdiagram.png)
<div align="center" class="caption"><i>All of the machines in the network this year</i></div>

While you have environment access, you are able to interact with the company's services, all of which are built by the volunteer team. Throughout the 8 hours during the day, your main goal will be to find and document as many vulnerabilities as you can.

The environment is similar to hack the box pro labs, where you have multiple machines (but sometimes on multiple subnets as well). You should go through a similar initial process to htb, where you do scans and poke around. However, there are some differences to note:
- **There is no "end goal".** You just keep looking around for as many findings as you can. Even if you already have root on a machine, that doesn't mean there aren't other vulnerabilities.
- **You really need to keep track of what you've done so far.** When there are over 20 endpoints and services on 6 or 7 machines, you need to be able to know what you've dirbusted, what you've cred fuzzed, and what you've explored sufficiently so that your team doesn't waste time doing redundant work. While real pentesters use tools like click up or jira for longer engagements, a whiteboard or a word doc work just fine.
- **Many of the findings are a lot simpler.** Some aren't even things you would consider real vulnerabilities, such as getting people's date of birth in an API response. You need to think from the company's viewpoint.
- **You need to document as you go.** At minimum, this means getting screenshots of proof of the finding, but you should also document and get screenshots of the steps it takes to replicate it.

![altText](@assets/images/cptc/cptcboard.png)
<div align="center" class="caption"><i>How we attempted to organize what we were doing this year</i></div>

### Injects
During the time you are on-site, your client will email you for advice or to request something, and they also will walk into your room for various things. I won't get too much into detail, but here are some examples of things I've seen requested in emails:
- Write us a 1 page report on the top 5 cyber threats to a social media company
- Make a deepfake of our CEO saying something that could harm our company
- Give us a 3 minute presentation on potential uses for AI in our company

There is also usually a phishing oriented inject, where they request that your team draft/send a phishing email or make a phishing call.

> For these types of requests, you usually have at least an hour to respond, so **you have time to write a response**. In fact, most of the time your team won't be an expert in the topic and will have to do plenty of research into it. One thing to note is that the amount of email injects will usually require at least one person on your team to be dedicated to them for around half of their time.

While the email communication is more business-oriented, the in-person interactions can be more funny but also more urgent, as you have to respond on the spot:
- We just got an email saying we got hacked and asking for a ransom. What should we do?
- I have a meeting with the CEO in 15 minutes and want to know the most important issue to address.
- I am an intern and want to ask if you guys could hack Rockstar Games for $2000.

> The most important thing about these types of injects is to be professional. **Have somebody (usually the captain) dedicated to being the point of contact** when they walk into the room, and for the rest of the team, **try to look like you know what you are doing while the company staff are in the room** (either listening attentively, but not in an eavesdropping sort of way, or continuing to work). For the point of contact, **don't be afraid to defer the question to a more knowledgeable team member, but also don't be afraid to say "We don't know, can we get back to you on that?"** *For the silly injects, focus on maintaining a straight face and using your common sense. The organizers have permission to laugh out of the blue and step out of character, but if you don't.* 

Finally, there are some multi-team injects that don't really fall under the above categories (usually only appearing during finals). For example, one year, one of us was paired up with people from two other teams to go on a scavenger hunt, and in another year, one of us spent half a day with people from three other teams to build something using AI. Again, just be professional and have fun!

### Tickets
Tickets are your only form of communication with the company that you initiate. **There is no penalty for sending one, so don't hesitation to use it.** If you have a question about whether a service is broken, send a ticket. If you are unsure if doing something (like stopping a tram through a web app) will have a real impact, send a ticket. If you want to clarify a something about a request they have for you, send a ticket.

> **Pro tip:** make a ticket template like "*Dear company, we are a pentest team doing pentest things. {insert ticket content here}. Best, team name*". While the CEO might have the luxury to send from all of their smart devices, you shouldn't have inconsistent ticket formats.

### Educational opportunities
If your team does something bad or think you've done something bad, like taking down one of their services, sending sensitive data to an external server (like jwt.io or webhook.site) or writing sensitive passwords in plain sight, your team will lose points as an "educational opportunity" (your team learned something you shouldn't do). 

> **You should immediately make a ticket** ***before they come to your room*** saying "*We did something bad, here are the things affected, we won't do it again we promise.*" Not only is it the right thing to do in a real world situation, but you might also get some points back for being communicative and professional.

If you ever get a surprise walk in because you were unaware of what you did wrong, be professional and try to do damage control. Ask for time to confer with your team about what could have gone wrong, or ask the staff for any pointers on what could have happened. It's better to ask for time than to be wrong.

> Educational opportunities are the easiest way to not lose points! While it might be hard to gain 1 or 2 points in the technical, injects, or report sections, it's very easy to not lose 4 to 6 points in the educational opportunities section just by being aware and careful when pentesting.

**You should never try to BS the client in any scenario. If you made a mistake (even unknowlingly), own up to it. If you don't know the answer to a technical question, say "I don't know". The volunteers also have technical knowlege (even if they pretend to not have any to be in character), and they will immediately to tell if you are lying.**

## When you are in your hotel (report writing and sleeping)
When you're not on-site, you are in the hotel. 🤯

In the hotel you will not have access to the environment to pentest, and instead will use your time to write up all of the findings you discovered in the prior 8 hours. The report will usually be over 50 pages for regionals and around 100 for finals, so your team needs a good organization plan.

> While our team used Ghostwriter this year, you don't need report writing software to do well. We've used Pwndoc and plain Microsoft Word in the past, and they all do fine. *If your team uses a templating tool, you should debug it and make sure it works fine. For both Ghostwriter and Pwndoc, we had to debug errors when we tried to export during regionals.* **However, your team should always prepare a template before the competition.** Any time you can save doing formatting or writing standard report stuff (like the intro and pentest methodology/tooling stuff) is time you have to write the actual content of the report. For finals, this also extends to the presentation slide deck.

![altText](@assets/images/cptc/cptcreportsubmit.png)
<div align="center" class="caption"><i>Submitting the report at 11:58PM (a new record in earliness!)</i></div>

There's not really much advice I can give here, except that you should **consider your audience** (the C-suite, managers, and engineers remediating the findings). **Don't use technical jargon when talking to an executive** (both irl and in the report), nor focus only on an attacker's viewpoint. Be "holistic" and try to imagine what they would think when they see your work. There are plenty of ways to go about this, which you can see in [previous reports](https://github.com/globalcptc/report_examples). What our team found was most successful for findings was the following:
- **Standard CVSS stuff**: Score, string, etc
- **General description**: Context surrounding the finding (which service? what does it do?)
- **Business impact**: for any executive or manager reading this, why should they even care about this? How could this cause the company to lose money, lose customers, etc?
- **Technical impact**: for any technical person reading this, how does this vulnerability affect their services and systems? Could an adversary pivot to other systems, take over user accounts, change other people's usernames, etc?
- **Remediation**: be as detailed as possible but be as general as possible to allow the company to fix it their own way
- **Steps to reproduce and proof**: make sure that a non-security technical person can replicate it (they don't know how to use burp suite, metasploit, etc)

**For the executive summary and non-findings sections, keep it non-technical**, like the business impact section. You want to be able to convey higher level ideas, such as how the company should improve their authentication, instead of saying that there is an SQL injection in the login form. 

### Also when you are on-site (presentation)
For finals, the awards day also includes team presentations in the morning. Each team will have 10 minutes to present, including time for questions. This means that the slides should take around 7 minutes. This presentation is to the C-suite of the company, so the same stuff as above applies even more. **Your team should never say anything even remotely technical, and most of the presentation should be trying to say "Your company is cooked, and here's why (but there is still a silver lining!)".** You can find previous presentations on the [cptc youtube channel](https://www.youtube.com/@globalcptc).

> **The presentation is also something your team should prepare beforehand!** While the content may change during the competition, by virtue of it being to company executives, you will still be conveying similar messages in business lingo.

## Before the competition
As I mentioned a few times, before the competition, there are a few things that your team should prepare beforehand to be successful: 
- Report template and/or software
- Presentation practice and slide deck template
- Pentesting practice and game plan for keeping track of what's been tested
- Game plan for walk-in injects
- A ticket template

There are still some more things teams to do to maximize success.

### OSINT
Before regionals, the CPTC team will create profiles for the fictional company online on various sites like LinkedIn, Github, and there will also be an "official site". Teams can look into these before the competition to find useful information such as company structure and emails. With enough digging, teams can also find sensitive information like passwords, old pentest reports, and more, giving them a leg up in the competition. 

When I competed we didn't find anything useful for the first 2 years, despite going so far as to order a USB stick from their Shopify and do forensics on the files that came with the flash drive. We discovered after finals that there wasn't much OSINT due to there not being enough volunteers and due to improving bot detection on social media sites.

While they did bring back OSINT for this year, unfortunately there's no way to know whether there is or isn't OSINT ahead of time, and we assumed we wouldn't find much like previous years. However, this year, the CPTC world team revealed that they did have an old pentest report accessible on scribd by going through the commit history of a github repo.

### Inject prep
Looking back on this year, there are a few things that I found we could have prepared better to deal with unexpected situations.

#### Responses to on the spot urgent questions
While you can't prepare for every question, you should know general good practices for operational scenarios that aren't always intuitive:
- What's the best way to handle a ransomware attack?
- How should a company responsibly deal the disclosure of a critical vulnerability that can heavily impact customers?
- What should a company do if passwords are leaked? If customer data is leaked?

Many of these questions can be answered by skimming through generally accepted security guides, such as the [stop ransomware guide](https://www.cisa.gov/stopransomware/ransomware-guide) or [CISA CPGs](https://www.cisa.gov/cybersecurity-performance-goals-2-0-cpg-2-0), as well as being aware of current events in security.

> Usually there will be at least one inject related to current events or industry trends.

Some of the in-person questions are not easily answerable. One time, we got asked about APK reversing, and thankfully our captain at the time had knowledge on it. However, we very well could have been clueless on the subject, and you need to be prepared to say "I don't know, can we look into it more and send in a ticket later?"

## Claude Code
This year, on the check in day at 8 pm (the day before we are given access to the environment), all the teams were notified that CPTC partnered with Anthropic to provide us $60,000 worth of claude tokens to use in the pentest. This was something new compared to previous years, and it was welcome, as I can confidently say that most of the teams learned how capable agents were for pentesting.

> After the competition, the organizers went into a bit more detail on how the partnership happened. The idea of this whole partnership only came about a week before, and it took them a few iterations of implementation before finally sorting everything out around 8 AM of the day before the competition. While the organizers didn't show it, they were as equally surprised as we about the addition of claude code.

![altText](@assets/images/cptc/cptczoom.png)
<div align="center" class="caption"><i>The surprise zoom call starring Bailey Finn</i></div>

During the first day, our team didn't really use it that much, since we were used to the "normal pentesting flow" of using tools and doing things manually. However, on the second day, one of our team members did a multi-team inject to build a tool that used AI, and they came back a changed man. After lunch, they immediately went ham, running `claude --dangerously-skip-permissions` and telling it to gain access to some machines we didn't get into. On its own, it ended up
1) Cracking a hash that we were trying to crack for the past day (guess god ig) to get into an admin portal
	1) Also using a CVE in traefik one of our team members found to get into the same admin portal
2) Looked around the admin and diagnostics portal (which we haven't even explored yet!) and found an arbitrary file upload/download endpoint
3) Discovered that the host fs was mounted on the docker container
4) Used the file upload endpoint to upload a cronjob with a reverse shell on the host
5) Opened a listener for the reverse shell, giving us root

This was not the only thing it found. It also found a mass assignment in a messaging application, some more hashes we overlooked, and more. Overall, I found it to be very good at both speeding up our workflow and combing through a large attack surface, trying a lot more attacks and possibilities than we could feasibly do in 16 hours. However, we very commonly found it would go off track, thinking that a vulnerability existed where there was nothing or generating fake credentials, requiring us to intervene regularly.

> I do not support using Claude Code the way we did for any real pentests, as it very well does have the capability to ruin your network despite being guided by a human operator. Even the organizers acknowledged that it could break services and accounts on the network, and they explicitly stated that we would not get any educational events for mishaps with claude code. 

CPTC 11 was the first time I used claude code, as previously, I only used free models (opencode, copilot, [gemini pro for students](https://gemini.google/students/)). This experience definitely enlightened me about the power and pitfalls of using claude code as an agent, and I appreciate the opportunity given by the CPTC team for us to try it out in an environment with no repercussions for breaking stuff.

## Banquet and Award Ceremony
Unlike all of the sections above, the banquet and award ceremony are not scored and allow teams to chill out. This year, the banquet had good food (as always), and the cptc team ran their hot ones Q&A again, this year starring Gideon dying. Unfortunately, the banquet always takes 3 hours, which is 3 less hours for report writing.

![altText](@assets/images/cptc/cptccake.png)
<div align="center" class="caption"><i>Fire cake as always</i></div>

![altText](@assets/images/cptc/cptcbanquet.png)
<div align="center" class="caption"><i>6 people who would rather write the report than sit at a fancy table</i></div>

After the banquet, there was also a career fair, this year only having tables for Security Risk Advisors and Crowe due to a winter storm delaying literally every other company from getting their people and tables over. Fortunately, many of the volunteers at the event were more than willing to talk about their companies, including Hurricane Labs, Black Hills Security, IZT Tech, and more (apologies to everybody I forgot). In fact, Charles from IZT Tech sat at our table during the Banquet, and he provided a lot of useful career advice and information!

### Awards Ceremony
While the awards ceremony might feel long, the volunteer team does give a lot of interesting information about how they run the event, including how they monitor every team with a 3 person SOC, more about the services from the developers, how they make the OSINT, and more.

This year featured Bob Kalka, one of the founders of CPTC, stalling for an hour with a humorous and very informative talk on tips for success in the security (but also tech) industry.

![altText](@assets/images/cptc/cptcprozes.png)
<div align="center" class="caption"><i>Our winnings this year</i></div>

After they gave out a total of 15 different prizes, we ~~went home~~ talked to the other teams and app developers to see what we missed and what we could improve. Only after that did we start the 7 hour drive back home.

# My years in CPTC
## CPTC9 - RAKMS - Airport Services
![altText](@assets/images/cptc/cptcrakms.png)

During my first year, I was an alternate that only competed in the Global Finals. Our team that year consisted of 2 seniors, 3 juniors, and me, a freshman. Being a freshman, I naturally didn't contribute much outside of injects (and writing binary search in python).

While I can't recall much from this year, I do remember the injects:
- For one of them, our teams went on a scavenger hunt with a radio to find a transmitter in the building.
- For another one, two people from our team used a laptop with a radio attachment to pentest a baggage claim device.
- For the phishing inject, we were able to send an email with a payload that would be run, and we were able to get a reverse shell. We also got the go binaries (called "phishing pole") and tried to reverse them.
- We also got a vishing inject where we called the help desk and tried to get some initial access or useful information.

In addition to there being 4 subnets with a comprehensive AD network and a handful of web apps, there was an AWS component to the competition. Thankfully, one of our team members was a UMass DevOps Club member, and they crushed the AWS pentest.

This year was the funniest in terms of our educational opportunities:
- Our first educational opportunity was for writing credentials on the whiteboard (there was a glass wall so people could see in from outside)
- We then got another educational opportunity for locking out domain user accounts that our team created
- Finally, we got another educational opportunity for writing passwords on the whiteboard again, but this time it was passwords for the said domain user accounts 

> For CPTC9 we used raw Microsoft Word, and our table of contents had `Error! Bookmark not defined` over 20 lines. We also had one of the greatest reports of all time, as you can see below.

![altText](@assets/images/cptc/cptclegofortnite.png)
![altText](@assets/images/cptc/cptccharttitle.png)
![altText](@assets/images/cptc/cptcnumber.png)


## CPTC10 - Flakebook/Y - Social Media
![altText](@assets/images/cptc/cptcflakebook.png)

After our success from the previous year, 4 out of our 6 team members graduated, leaving us with only the captain, me, and 4 new members. While we did well in regionals, we did not fare too well in finals.

It was around this year that I felt CPTC making a transition in the services we were pentesting, switching from a more traditional AD and separated web services across multiple subnets to two subnets with a big web application (the social media app) that used microservices. Additionally, continuing their cloud component from last year, this year they had some secrets/files on Azure (although the scoping was unclear, as teams had to search for a publicly accessible blob).

As the "main web person" on our team, I mostly explored the main social media web app and didn't do many injects. I will say that IMO the injects weren't as cool as my first year (I guess airport companies are cooler than social media companies).
- This year there was lots of "low hanging fruit" related to user authentication.
- There was also a vishing inject in finals where we used an audio deepfake to impersonate somebody.

In terms of educational opportunities, we got cooked this year in globals:
- We used jwt.io to analyze their JWT tokens, sending sensitive information to whoever ran jwt.io
- We also copied hashes into a word doc to share, and the staff were concerned that our team would crack the hashes secretly

> For CPTC 10 we used Pwndoc, and our table of contents spilled into the cover (How does that even happen?).

## CPTC11 - All Ports Tours - Cruise Company
![altText](@assets/images/cptc/cptcallportstours.png)

This year we had 3 returning members, and the youngest of us was a sophomore. Due to vacation conflicts, we ended up switching in both of our alternates for the final, but despite two of our members being completely new to CPTC in the finals, we did well with every member contributing.

The trend of moving toward more "modern" architectures with dockerized web apps and a single subnet continued. What made this even more clear was the lack of Active Directory vulnerabilities in the network, forcing most of our team to work on web. Unfortunately, they did not complete the cloud trifecta by including GCP this year, instead opting for no cloud component to the competition at all.

- During regionals, we only got 1 walk-in inject where executives asked for the most urgent finding to present to the CEO.
- We (almost) had no educational opportunities this year! We did have one mishap with submitting a hash to an online cracker, but, following my above advice, we notified the company and prepared a good response.

> This year we used Ghostwriter, and we finally got a perfect table of contents!

## Other reflections on CPTC
### The issue of time 
Naturally, with around 48 hours of competition, there is insufficient time to recreate a real pentest engagement, which usually happens over course of weeks. Teams are pressured to sacrifice thoroughness in favor of being able to look over everything in time, and more importantly, report writing becomes a sprint to get something down for every finding. It was only after my first time competing that I realized what types of preparation are vital to success (*especially a report template and a plan for keeping track of the pentest*), and I wish it didn't have to be that way. However, teams can still do well if they do research on what they need to prepare ahead of time, as evidenced by UCI's win this year as a first time competitor.

### The issue of grading
Additionally, with the less than 14 or so hours from the submission of reports to awards ceremony, people do have the right to question the rigidity of the scoring process (like some people in discord). Mistakes do happen, as evidenced by the single mishap this year in the Great Lakes region (though no qualifications to globals was affected).

Despite this, as with many other similar types of competitions with "vague grading" like hackathons and FRC, the grading system is as robust as it can be. I talked with some of the volunteers after the awards ceremony this year, and they spoke to how rigid the grading system is, requiring graders grade in "silos" (independently of each other) and are peer reviewed (independently as well) to prevent bias before opinions/scores are combined into the final placements. In hackathons and FRC, there is a similar system of having multiple judges deliberate independently before discussing the final winners. Because of that, just like how the scores of said competitions are respected as final, I believe the scores of CPTC and the time and effort the volunteers put into grading should also be respected.

### Direction of the competition
As I mentioned in the previous section, the environment has changed with each competition to match the tech industry's move toward microservices, vibe coded apps, and the cloud. While being able to pentest AD is a good skill to have, rewarding teams by including more AD vulnerabilities could lead to CPTC alumni becoming AD scanners, something that I think (as a web person) is a less marketable skill to have compared to general pentesting and security auditing. I will say that I was a bit surprised by the lack of cloud in this last year, as it is becoming even more ubiquitous nowadays.

# Closing thoughts
This year, the CPTC team also announced their plan to become an independent organization from RIT. They very much have the capability to stand on their own legs with their sponsors, and I am excited to see how much they grow now that they are independent.

**I cannot recommend this competition enough to anybody in cybersecurity, computer science, or any field (one of our team members was a psychology major!). This competition gives you the opportunity for plenty of educational opportunities, both good and bad, and is one of the best preparations (technical, professional, and organizational skills-wise) you can get to before going into the industry outside of an internship (which you can also get through networking at this competition!).**