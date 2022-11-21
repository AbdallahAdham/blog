+++ 
author = ['Abdallah Adham']
title = "ElMariachi-PC PwnTillDawn Writeup"
date = 2022-11-19
description = "This is a writeup of the ElMariachi-PC machine in PwnTillDawn Online platform."
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

image = "post/El-Mariachi_PwnTillDawn/elmariachi_pwntilldawn.JPG"
+++

---

This writeup has been authorized by the **PwnTillDawn Crew**! 

Check their websites for more information!
1. [wizlynxgroup](https://www.wizlynxgroup.com/)
2. [online.pwntilldawn](https://online.pwntilldawn.com/)

## Target Information

| Name | IP | Operating System | Difficulty| 
|----------- | ----------- | ----------- |  -----------|
|**ElMariachi-PC**| **10.150.150.69** | **Windows** | **Easy** |

## Scanning

### Nmap Scanning

```bash
$ nmap 10.150.150.69 -A -p- --min-rate=5000 -n -sT -Pn --open -oG allports
Nmap scan report for 10.150.150.69
Host is up (0.094s latency).
Not shown: 54303 closed tcp ports (conn-refused), 11221 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=ElMariachi-PC
| Not valid before: 2022-11-18T13:20:31
|_Not valid after:  2023-05-20T13:20:31
|_ssl-date: 2022-11-19T16:45:57+00:00; +41m04s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: ELMARIACHI-PC
|   NetBIOS_Domain_Name: ELMARIACHI-PC
|   NetBIOS_Computer_Name: ELMARIACHI-PC
|   DNS_Domain_Name: ElMariachi-PC
|   DNS_Computer_Name: ElMariachi-PC
|   Product_Version: 10.0.17763
|_  System_Time: 2022-11-19T16:45:28+00:00
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
50417/tcp open  msrpc         Microsoft Windows RPC
60000/tcp open  unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Type: text/html
|     Content-Length: 177
|     Connection: Keep-Alive
|     <HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD><BODY><H1>404 Not Found</H1>The requested URL nice%20ports%2C/Tri%6Eity.txt%2ebak was not found on this server.<P></BODY></HTML>
|   GetRequest: 
|     HTTP/1.1 401 Access Denied
|     Content-Type: text/html
|     Content-Length: 144
|     Connection: Keep-Alive
|     WWW-Authenticate: Digest realm="ThinVNC", qop="auth", nonce="Bh5opIvq5UDI4UcCi+rlQA==", opaque="m2yqFi2usv3AY2yatYSTRmyNPAplB8C1oC"
|_    <HTML><HEAD><TITLE>401 Access Denied</TITLE></HEAD><BODY><H1>401 Access Denied</H1>The requested URL requires authorization.<P></BODY></HTML>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port60000-TCP:V=7.93%I=7%D=11/19%Time=6378FE2E%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,179,"HTTP/1\.1\x20401\x20Access\x20Denied\r\nContent-Type:\x
SF:20text/html\r\nContent-Length:\x20144\r\nConnection:\x20Keep-Alive\r\nW
SF:WW-Authenticate:\x20Digest\x20realm=\"ThinVNC\",\x20qop=\"auth\",\x20no
SF:nce=\"Bh5opIvq5UDI4UcCi\+rlQA==\",\x20opaque=\"m2yqFi2usv3AY2yatYSTRmyN
SF:PAplB8C1oC\"\r\n\r\n<HTML><HEAD><TITLE>401\x20Access\x20Denied</TITLE><
SF:/HEAD><BODY><H1>401\x20Access\x20Denied</H1>The\x20requested\x20URL\x20
SF:\x20requires\x20authorization\.<P></BODY></HTML>\r\n")%r(FourOhFourRequ
SF:est,111,"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Type:\x20text/html
SF:\r\nContent-Length:\x20177\r\nConnection:\x20Keep-Alive\r\n\r\n<HTML><H
SF:EAD><TITLE>404\x20Not\x20Found</TITLE></HEAD><BODY><H1>404\x20Not\x20Fo
SF:und</H1>The\x20requested\x20URL\x20nice%20ports%2C/Tri%6Eity\.txt%2ebak
SF:\x20was\x20not\x20found\x20on\x20this\x20server\.<P></BODY></HTML>\r\n"
SF:);
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 41m04s, deviation: 0s, median: 41m03s
| smb2-time: 
|   date: 2022-11-19T16:45:28
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
```

It looks like this machine have only ports related to **SMB and DNS** services.

## Enumeration

I am going to enumerate anything possible about **SMB** services as it is most likely to have **exploits**.

### SMB Enumeration

Now, I will use an auxiliary in **Metasploit Framework** to scan for the **SMB version** to search if it is vulnerable to any exploits or not!

#### Metasploit

```bash
msf6 > search auxiliary/scanner/smb/smb_version
Matching Modules
================

   #  Name                               Disclosure Date  Rank    Check  Description
   -  ----                               ---------------  ----    -----  -----------
   0  auxiliary/scanner/smb/smb_version                   normal  No     SMB Version Detection


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/smb/smb_version

msf6 > use auxiliary/scanner/smb/smb_version
msf6 auxiliary(scanner/smb/smb_version) > options

Module options (auxiliary/scanner/smb/smb_version):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/U
                                       sing-Metasploit
   THREADS  1                yes       The number of concurrent threads (max one per host)

msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 10.150.150.69
RHOSTS => 10.150.150.69
msf6 auxiliary(scanner/smb/smb_version) > run

[*] 10.150.150.69:445     - SMB Detected (versions:2, 3) (preferred dialect:SMB 3.1.1) (compression capabilities:) (encryption capabilities:AES-128-GCM) (signatures:optional) (guid:{12ce29e0-f300-4650-b6a7-8851bc744142}) (authentication domain:ELMARIACHI-PC)
[*] 10.150.150.69:        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

>SMB Detected (versions:2, 3)
>Authentication domain: ELMARIACHI-PC

#### SmbClient

I think i will use the **SmbClient** tool to see if there are any shared resources.

```bash
$ smbclient -L //10.150.150.69 -N
session setup failed: NT_STATUS_ACCESS_DENIED
```

Looks like it is prohibted to access those shares.

### Port 60000 Enumeration

So, I think this port is related to HTTP services as we can see from the output of **nmap scanning**.

Let's open the browser see what is up there?

![web](post/El-Mariachi_PwnTillDawn/imgs/1.JPG)

Also, From the nmap scanning i have found:
>  WWW-Authenticate: Digest realm="**ThinVNC**", qop="auth", nonce="Bh5opIvq5UDI4UcCi+rlQA==",

ThinVNC is **a web remote access client (browser-based, HTML5)**. It's an improved version of the standard VNC protocol.

Let's see if there are any exploits or default credientials for this software.

I have found this [Article](https://redteamzone.com/ThinVNC/) which explains how to bypass the authentication of **ThinVNC** software.

Let's do this step by step:

1. Open Burpsuite and intercept the signing in process.

2. Change the URL to this path `/admin/../../ThinVnc.ini` to navigate to the default credientials (authentication) page.

![directory_traversal](post/El-Mariachi_PwnTillDawn/imgs/2.JPG)

3. Sign in using the **Username** and **Password** resulted from the **directory traversal** attack.

```rext
User=desperado
Password=TooComplicatedToGuessMeAhahahahahahahh
```

![sign_in](post/El-Mariachi_PwnTillDawn/imgs/3.JPG)

4. Now, We can connect to the victim machine remotely.

![remote](post/El-Mariachi_PwnTillDawn/imgs/4.JPG)


5. We can navigate using **File Explorer** and get the _Flag_.

![get_flag](post/El-Mariachi_PwnTillDawn/imgs/5.JPG)


```txt
FLAG67 = 2971f3459fe55db1237aadXXXXXXXXXXXXXXXX
```

_Pwned_

![Pwned](post/El-Mariachi_PwnTillDawn/imgs/6.JPG)
