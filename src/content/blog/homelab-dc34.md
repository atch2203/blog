---
author: atch2203
pubDatetime: 2026-09-05
title: Homelab Upgrades and Defcon 34
featured: false
draft: false
tags:
  - cybersec
  - other
description: The state of the homelab address and my first con ever
---
# My homelab

I don't think I've ever written about my homelab yet, but recently I made some upgrades to my homelab that I think it's finally usable now.

## What specs?
I have no idea. I have two computers: a ~$300 mini pc (16 gb ram, 1 tb nvme + 5 tb hard drive), and an old pc (idk ram, 4tb hard drive) that my family got for $50. The main reason we got the mini pc was to reduce energy costs (the previous computer I was using consumed 40W+ on idle, this one consumes ~10W). I also got an 8 port switch (idk gbps, not in frame) since we were running out of ports on the router.

![altText](@assets/images/homelab-dc34/homelab-dc34.png)

## What services?
Currently I have Proxmox on the mini pc and a Proxmox backup server on the big pc. I set it up so every day, the big pc turns on at noon, the mini pc backs everything up, and then it shuts down the big pc (to reduce power costs).

On proxmox, I am running:
- Pihole (lxc)
- Nextcloud (lxc + snap)
- Gitea (lxc + docker)
- tailscale/golink (lxc + docker)
- TrueNAS (VM)

Everything above is on the 1tb nvme. The TrueNAS VM also has passthrough to the 5tb hard drive (recently upgraded from 500 gb), which it is using as a storage pool. On TrueNAS, I have:
- immich
- qbittorrent + prowlarr + jackett + flaresolverr + jellyfin
- i2p
- an smb share and ftp server

### What else?
I currently use tailscale to access my homelab remotely (as well as drive everything through pihole).

I also just set up a cloudflare tunnel (not telling where it is though) with google auth in front of one of my services, I highly recommend it if you want to expose your services to family/friends without having to install tailscale on their devices.

# Defcon 34
This year was my first time going to Defcon (I paid out of pocket though 💸). I definitely think it was a worthwhile experience. While I didn't tryhard any CTFs or go to all the events I would have liked to have seen, I definitely think I spent all the time I had at Defcon well. 

If you ever have the chance to go to Defcon for the first time, I would recommend looking around all the villages and communities before getting deep into one. I would also recommend doing a reasonable amount of osint on unofficial events (there's a ton of parties going on, you just have to find them), getting the hacker tracker app, and planning your hotel/transportation ahead of time. Most importantly, meet up with other friends that are also going or make new friends when you get there (things are more fun in a group)!

Here are some things I did and some photos I took:
- 5n4ck3y CTF (Highly recommend, shoutout to the organizers)
- Cloud Village CTF + Labs
- HackTheFortress
- Gambling (ofc)
- Ride the Las Vegas Loop from one side of the WLVCC parking lot to the other
- Went to a Jetski hacking talk before realizing stacksmashing was the speaker

![altText](@assets/images/homelab-dc34/homelab-dc34-1.png)

![altText](@assets/images/homelab-dc34/homelab-dc34-2.png)

![altText](@assets/images/homelab-dc34/homelab-dc34-3.png)

![altText](@assets/images/homelab-dc34/homelab-dc34-4.png)

![altText](@assets/images/homelab-dc34/homelab-dc34-5.png)