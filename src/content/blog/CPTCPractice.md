---
author: atch2203
pubDatetime: 2023-10-31
title: HTB "Writeups"
featured: false
draft: false
tags:
  - HTB writeups
description: Old writeups I did for HTB machines
---

# Bashed

### nmap scan

scan with `-Pn` shows port 80  
![ALt text](@assets/images/writeups/bashed/image.png)

Looking at the webpage, it looks like they have `phpbash` running on it

in the blog post, there is an screenshot with the file `/uploads/phpbash.php`, but that doesn't lead to anything  
![Alt text](@assets/images/writeups/bashed/image-2.png)  
![Alt text](@assets/images/writeups/bashed/image-3.png)

### dirbusting

running `dirb http://10.10.10.68` shows a few directories  
![Alt text](@assets/images/writeups/bashed/image-1.png)  
`phpbash.php` can be found in the `/dev` directory  
![Alt text](@assets/images/writeups/bashed/image-4.png)

opening up `phpbash.php` gives us a shell  
![alt text](@assets/images/writeups/bashed/image-5.png)

### getting root

Attempts at simple revshells in the webshell don't work

running `sudo -l` shows that we can sudo scriptmanager with no password  
![Alt text](@assets/images/writeups/bashed/image-6.png)  
Additionally, the `/scripts` folder is only accessible as scriptmanager  
![Alt text](@assets/images/writeups/bashed/image-7.png)

looking into scripts, we see that there's a python file and text file, and that the python file makes the text file every so often.  
![Alt text](@assets/images/writeups/bashed/image-14.png)  
this probably means that a something is running `test.py` regularly as root to create the `test.txt` file.

We can abuse this by replacing `test.py` with a reverse shell. To get our file onto the server, we have to wget from the `/var/www/html/uploads` folder and then moving it to `/scripts`, as we don't have write permissions in other folders.  
![Alt text](@assets/images/writeups/bashed/image-10.png)  
![Alt text](@assets/images/writeups/bashed/image-11.png)  
![Alt text](@assets/images/writeups/bashed/image-12.png)

After that, we open a port and wait until we get a reverse shell.  
![Alt text](@assets/images/writeups/bashed/image-13.png)

## Solutions

The phpbash repository has not been updated since 2018, so it doesn't look like there's any updates that would fix privillage escalation issues.  
Limiting users from accessing anything outside of the blog pages, such as `/dev` and `/css` could resolve this issue if the phpbash functionality isn't required.

Disallowing `www-data` from sudoing with no password would prevent anyone on the webshell from modifying `/scripts`.

Another thing that could be done would be to switch from using a task scheduler that doesn't run as root, as it allows `scriptmanager` to run things as root from the scripts folder.

# Blue

### nmap scan

![Alt text](@assets/images/writeups/blue/image.png)

![Alt text](@assets/images/writeups/blue/image-1.png)

![Alt text](@assets/images/writeups/blue/image-2.png)

### eternal blue time

![Alt text](@assets/images/writeups/blue/image-3.png)

![Alt text](@assets/images/writeups/blue/image-4.png)

## Solution

- update windows to the latest version or according to [this](https://support.microsoft.com/en-us/topic/ms17-010-security-update-for-windows-smb-server-march-14-2017-435c22fb-5f9b-f0b3-3c4b-b605f4e6a655) or [this](https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-010)

# Jerry

### Nmap scans

scanning with no options is blocked
![Alt text](@assets/images/writeups/jerry/image-1.png)

scanning with `-Pn` shows tomcat is running on port 8080
![Alt text](@assets/images/writeups/jerry/image-2.png)

scanning port 8080 with `-sV -sC -Pn`
![Alt text](@assets/images/writeups/jerry/image-3.png)

### Looking at the website

Logging in with `admin: admin` works, but it has no perms  
_insert screenshot of no perms here_

### Login enumeration

Run metasploit/run common passwords

results in `tomcat: s3cret` as a username password pair  
_insert screenshot here_

### Reverse WAR shell

Use msfvenom to generate reverse jsp shell
`specific command`
![Alt text](@assets/images/writeups/jerry/image-4.png)

upload `shell.war` under war uploads  
_insert screenshot of upload page here_

listen on port \_\_\_ with `nc -nvlp 3155`

navigate to `10.10.10.95/shell`  
and then the reverse shell is connected
![Alt text](@assets/images/writeups/jerry/image-5.png)

### finding flag

navigate to `C:\Users\Administrator\Desktop\flags`
and print flag
![Alt text](@assets/images/writeups/jerry/image-6.png)

## Solution

Change the credentials to a non-default username/password

# Lame

### nmap scan

![Alt text](@assets/images/writeups/lame/image.png)  
![Alt text](@assets/images/writeups/lame/image-1.png)

searching up "Samba smbd 3.0.20-Debian exploit" results in [this](https://www.exploit-db.com/exploits/16320)

### rce

executing the exploit with metasploit gives us root access
![Alt text](@assets/images/writeups/lame/image-2.png)

## solution

Update samba to >3.0.25rc3

# Precious

### nmap scan

![Alt text](@assets/images/writeups/precious/image.png)

![Alt text](@assets/images/writeups/precious/image-3.png)

Looking at the website, it looks like the websites you can put are very limited.  
![Alt text](@assets/images/writeups/precious/image-2.png)  
I made a python http server and downloaded a pdf of that webpage  
![Alt text](@assets/images/writeups/precious/image-5.png)  
![Alt text](@assets/images/writeups/precious/image-4.png)
![Alt text](@assets/images/writeups/precious/image-6.png)

### rce

looking up "pdfkit v0.8.6" gives us [this](https://www.exploit-db.com/exploits/51293), which is v0.8.7.2

running the exploit  
![Alt text](@assets/images/writeups/precious/image-7.png)  
![Alt text](@assets/images/writeups/precious/image-8.png)

There is the ssh password for henry under `/home/ruby/.bundle/config`  
![Alt text](@assets/images/writeups/precious/image-9.png)

we can ssh to `henry@precious.htb` with the password  
![Alt text](@assets/images/writeups/precious/image-10.png)

henry can run `/usr/bin/ruby` with no sudo password
![Alt text](@assets/images/writeups/precious/image-11.png)

We can find a ruby update dependency exploit [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Ruby.md)  
Running it confirms that we are root.
![Alt text](@assets/images/writeups/precious/image-12.png)

Replacing the payload with a reverse shell gives us a root shell.
![Alt text](@assets/images/writeups/precious/image-13.png)
![Alt text](@assets/images/writeups/precious/image-14.png)

## solution

- don't leave ssh exposed
- don't put ssh credentials in .bundle/config
- don't give users the ability to modify `dependencies.yml` or run ruby as root
- update pdfkit to >=0.10.0 (not sure if this is actually true)

# Shocker

### nmap scan

![Alt text](@assets/images/writeups/shocker/image.png)
![Alt text](@assets/images/writeups/shocker/image-1.png)
![Alt text](@assets/images/writeups/shocker/image-2.png)

### dirb

Initial dirb shows `index.html`, as well as two inaccessible directories  
![Alt text](@assets/images/writeups/shocker/image-3.png)

Dirbing on `cgi-bin` with `.cgi` doesn't show anything, but we get a result for `.sh`  
![Alt text](@assets/images/writeups/shocker/image-5.png)  
![Alt text](@assets/images/writeups/shocker/image-4.png)

downloading `/cgi-bin/user.sh` gives us something that looks like something from `uptime`  
![Alt text](@assets/images/writeups/shocker/image-6.png)

looking for "apache cgi exploits" gives us [this](https://www.exploit-db.com/exploits/34900)

nmapping shows that the server is vulnerable  
![Alt text](@assets/images/writeups/shocker/image-7.png)

we can run the exploit using metasploit  
![Alt text](@assets/images/writeups/shocker/image-8.png)

it looks like we have access to `/usr/bin/perl`, so we can probably do a rev shell through that.  
![Alt text](@assets/images/writeups/shocker/image-9.png)

running the script results in a rev shell  
![Alt text](@assets/images/writeups/shocker/image-10.png)
![Alt text](@assets/images/writeups/shocker/image-11.png)

## solutions

- disallow the user from accessing perl with no password, as it's what allowed for the revshell
- patch the issue with [this](https://bugzilla.redhat.com/show_bug.cgi?id=1141597)
- upgrade past bash 4.3, as [the exploit only works from 1.14-4.3](https://nvd.nist.gov/vuln/detail/CVE-2014-6271)
