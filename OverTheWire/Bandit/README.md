CTF | OverTheWire | Bandit

prerequisite

- Git
- Basic networking tools (nc,nmap)
- Basic linux commands like (ls,mkdir,rm,cd,cat)
- Bash scripting

SSH protocol (also referred to as Secure Shell) is a method for secure remote login from one computer to another. It provides several alternative options for strong authentication, and it protects the communications security and integrity with strong encryption

Ssh Pass is a tiny utility, which allows you to provide the ssh password without using  
the prompt. This will very helpful for scripting. Ssh Pass is not good to use in multi user environment [sshpass docs](https://linux.die.net/man/1/sshpass)

⚠️ **Disclaimer**: This solution was generated in May 2024. If you are accessing this information at a later date, please note that circumstances may have changed. Different levels of flags, variations in levels, and even new levels altogether might have been introduced. Please verify the most current and relevant information before making any decisions based on this content.

```bash
sudo apt-get install sshpass
sshpass -p `cat filename` ssh user@bandit.labs.overthewire.org -p 2220
```

**Bandit**

The goal of this level is for you to log into the game using SSH. The host to which you need to connect is bandit.labs.overthewire.org, on port 2220. The username is bandit0 and the password is bandit0. Once logged in, go to the Level 1 page to find out how to beat Level 1.

connect to the labs

```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
password:bandit
```

or use `nano` cmd and save password as `bandit0` and file name also same,

```bash
sshpass -p `cat bandit0` ssh bandit0@bandit.labs.overthewire.org -p 2220
```

---

#### **Level 0 :**

The password for the next level is stored in a file called **readme** located in the home directory. Use this password to log into bandit1 using SSH. Whenever you find a password for a level, use SSH (on port 2220) to log into that level and continue the game.

```bash
ls
cat readme
```

---

#### **Level 1:**

The password for the next level is stored in a file called **-** located in the home directory

```bash
ls -a
cat ./-
```

---

#### **Level 2:**

The password for the next level is stored in a file called spaces in this filename located in the home directory

```bash
cat spaces\ in\ this\ filename
```

or

```
cat "spaces in this filename"
```

---

#### Level 3

The password for the next level is stored in a hidden file in the **inhere** directory.

```bash
cd inhere/ls -la
cat .hidden
```

---

#### **Level 4:**

The password for the next level is stored in the only human-readable file in the **inhere** directory. Tip: if your terminal is messed up, try the “reset” command.

```bash
file ./*
```

or

```bash
strings ./*
cat ./-file07
```

---

#### **Level 5:**

The password for the next level is stored in a file somewhere under the **inhere** directory and has all of the following properties:
• human-readable  
• 1033 bytes in size  
• not executable

`ls -lR` -> list the files recursive from pwd ,
`!` -> not , `1033c` -> c refers to bytes

```bash
ls -lR
find ! -executable -size 1033c
```

---

#### **Level 6:**

The password for the next level is stored **somewhere on the server** and has all of the following properties:
• owned by user bandit7  
• owned by group bandit6  
• 33 bytes in size
<br>

`/`- refers from the root directory, `2>/dev/null` will redirect results which doesn't permissions

```bash
find / -size 33c -user bandit7 -group bandit6 2>/dev/null
```

---

#### **Level 7:**

password for the next level is stored in the file data.txt next to the word millionth

```bash
cat data.txt | grep "millionth"
```

---

#### **Level 8:**

password for level is stored in the file and is the only line of text that occurs only once  
`grep -v` refers to invert , `uniq -c` refers to count

```bash
cat data.txt | sort | uniq -c | grep -v "10"
```

---

#### **Level 9:**

The password for the next level is stored in the file data.txt in one of the few human-readable strings, preceded by several ‘=’ characters.

```bash
cat data.txt | strings | grep "="
```

---

#### **Level10:**

The password for the next level is stored in the file data.txt, which contains base64 encoded data  
`base64 -d` -> refers to decode from base64

```bash
cat data.txt | base64 -d
```

---

#### **Level11:**

password for level is stored in the file, where all lowercase and uppercase have been rot13  
copy the data.txt in your clipboard

```bash
cat data.txt
```

`apt install bsdgames` it has `rot13` program to decode rot13 string in your local machine, after you installed using bsd games

```bash
echo "encoded_string" | rot13
```

---

#### **Level12:**

password stored in the file, which is a hexdump file that has been repeatedly compressed. For this level it may be useful to create a dir under /tmp in which you can work using mkdir. eg: mkdir /tmp/myname123. copy the datafile using cp, and rename it using mv

make tmp folder  
data.txt has hexdump using `xxd -reverse` and get string direct > to folder

```bash
mkdir /tmp/har
go to bandit12
cp ./data.txt /tmp/har
cd /tmp/har
xxd -r data > filename
```

the redirected file is a gzip archive but it doesn't have gzip extension

```bash
file filename
mv archive archive.gz
gunzip archive.gz
```

archive converted into bzip2

```bash
file archive
bzip2 -d archive or bunzip archive
```

```bash
archive.out it is a gzip file
file archive.out
mv archive.out archive.gz
gunzip archive.gz
```

archive is a tar file `tar -xvf file` 'x' (extract), 'v' (verbose), and 'f' (file).

```bash
tar -xvf archive
data5.bin is tar file
tar -xvf data5.bin
data6.bin is bzip2 file
bzip2 -d data6.bin
data6.bin.out is a tar file
tar -xvf data6.bin.out
data8.bin is a gzip
mv data8.bin data8.gz
gunzip data8.gz
ls
file data8
cat data8
```

---

#### Level13:

password is stored in /etc/bandit_pass/bandit14 and can only be read by user bandit14. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level. Note: localhost is a hostname that refers to the machine you are working on  
`ssh -i file` identity_file which RSA private key for the labs

```bash
ssh -i sshkey.private bandit14@bandit.labs.overthewire.org -p 2220
```

---

#### **Level14:**

The password for the next level can be retrieved by submitting the password of the current level to port 30000 on localhost.

save the password for bandit13 because we didn't save in our local machine , because we used to connect using sshkey

```bash
cat /etc/bandit_pass/bandit14
```

```bash
cat /etc/bandit_pass/bandit14 | nc localhost 30000
```

paste current level password.

---

#### **Level15:**

password can be retrieved by submitting the password of the current level to port 30001 on localhost using SSL encryption.  
Helpful note: Getting “HEARTBEATING” and “Read R BLOCK”? Use -ign_eof and read the “CONNECTED COMMANDS” section in the manpage. Next to ‘R’ and ‘Q’, the ‘B’ command also works in this version of that command…

copy current level password.

`s_client` -> which can establish a transparent connection to a remote server speaking SSL/TLS

```bash
cat /etc/bandit_pass/bandit15
openssl s_client -connect localhost:30001
```

paste current level password

---

#### **Level16:**

credentials for the next level can be retrieved by submitting the password of the current level to a port on localhost in the range 31000 to 32000. First find out which of these ports have a server listening on them. Then find out which of those speak SSL and which don’t. There is only 1 server that will give the next credentials, the others will simply send back to you whatever you send to it.

`nmap [target] -p` -> refers to ports

```bash
nmap localhost -p 31000-32000
```

this will return a list of scanned ports and bruteforce port with openssl

```bash
cat /etc/bandit_pass/bandit16
openssl s_client -connect localhost:31790
```

copy the rsa private key and save as `bandit17rsa` in local machine

```bash
chmod 700 bandit17rsa
ssh -i bandit17rsa bandit17@bandit.labs.overthewire.org -p 2220
cat /etc/bandit_pass/bandit17
```

---

#### **Level17:**

There are 2 files in the home-directory: passwords.old and passwords.new. The password for the next level is in passwords.new and is the only line that has been changed between passwords.old and passwords.new  
NOTE: if you have solved this level and see ‘Byebye!’ when trying to log into bandit18, this is related to the next level, bandit19

```bash
diff password.old password.new
```

---

#### **Level18:**

The password for the next level is stored in a file readme in the homedirectory. Unfortunately, someone has modified .bashrc to log you out when you log in with SSH.

we can cat readme asap before logout execution by giving as argument in your local machine

```bash
sshpass -p `cat bandit18` ssh bandit18@bandit.labs.overthewire.org -p 2220 "ls"
sshpass -p `cat bandit18` ssh bandit18@bandit.labs.overthewire.org -p 2220 "cat readme"
```

---

#### **Level19:**

To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (/etc/bandit_pass), after you have used the setuid binary.

```bash
./bandit20-do id
./bandit20-do cat /etc/bandit_pass/bandit20
```

---

#### **Level20:**

There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a command-line argument. It then reads a line of text from the connection and compares it to the password in the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).

make 2 terminal , first create sever `nc -lvp` -l (listen) -v (verbose) -p (port)

```bash
nc -lvp 8888
```

at another terminal make listener connect to created server using subconnect

```bash
./suconnect 8888
```

if we give current bandit20 password at `server shell` that means at nc -lvp 8888 we get next level password flag , give current level flag -> `GbKksEFF4yrVs6il55v6gwY5aVje5f0j`

---

#### **Level21:**

A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.  
Commands you may need to solve this level  
cron, crontab, crontab(5) (use “man 5 crontab” to access this)

```bash
cd /etc/cron.d/
ls -la
cat cronjob_bandit22
```

the cronjob file has a bash file refers bash file

```bash
cat /usr/bin/cronjob_bandit22.sh
```

the bash file makes a permission to a file in tmp directory

```bash
cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```

---

#### **Level22:**

A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.  
NOTE: Looking at shell scripts written by other people is a very useful skill. The script for this level is intentionally made easy to read. If you are having problems understanding what it does, try executing it to see the debug information it prints.  
cmds cron, crontab, crontab(5) (use “man 5 crontab” to access this)

```bash
cd /etc/cron.d/
cat cronjob_bandit23
cat /usr/bin/cronjob_bandit23.sh
```

cronjob_bandit23.sh bash file

```bash
#!/bin/bash
myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)
echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"
```

command return filename which has a password next level

```bash
echo "I am user bandit23" | md5sum | cut -d ' ' -f 1
$ 8ca319486bfbbc3663ea0fbe81326349
cat /tmp/8ca319486bfbbc3663ea0fbe81326349
```

---

#### **Level23:**

A program is running automatically at regular intervals from cron, the time-based job scheduler. Look in /etc/cron.d/ for the configuration and see what command is being executed.  
NOTE: This level requires you to create your own first shell-script. This is a very big step and you should be proud of yourself when you beat this level!  
NOTE 2: Keep in mind that your shell script is removed once executed, so you may want to keep a copy around…

```bash
cd /etc/cron.d/
cat cronjob_bandit24
cat /usr/bin/cronjob_bandit24.sh
```

it has different bash file

```bash
#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname
echo "Executing and deleting all scripts in /var/spool/$myname/foo:"
for i in * .*;
do
if [ "$i" != "." -a "$i" != ".." ];
then
echo "Handling $i"
owner="$(stat --format "%U" ./$i)"
if [ "${owner}" = "bandit23" ]; then
timeout -s 9 60 ./$i
fi
rm -f ./$i
fi
done
```

```bash
mkdir /tmp/har3
chmod 777 /tmp/har3
cd /tmp/har3
```

create a own bash file `nano get.sh` ,`ctrl+o` to save , `ctrl+x` to exit

```bash
#!/bin/bash
cat /etc/bandit_pass/bandit24 > /tmp/har3/passwd.txt
```

after creating bash ,enable execute previlege by `chmod` (change_mode) commandd

```bash
chmod 700 get.sh
cp get.sh /var/spool/bandit24/foo
ls /tmp/har3/
cat /tmp/har3/passwd.txt
```

---

#### **Level24:**

A daemon is listening on port 30002 and will give you the password for bandit25 if given the password for bandit24 and a secret numeric 4-digit pincode. There is no way to retrieve the pincode except by going through all of the 10000 combinations, called brute-forcing.

```bash
mkdir /tmp/har4
chmod 777 /tmp/har4
cd /tmp/har4
nano brute.sh
```

```bash
#!/bin/bash

for i in {9999..000};
do
echo "UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $i"
done
```

The Netcat ( nc ) command is a command-line utility for reading and writing data between two computer networks.

```bash
chmod +x brute.sh
./brute.sh > rockyou.txt
cat rockyou.txt | nc localhost 30002
```

---

#### **Level25:**

Logging in to bandit26 from bandit25 should be fairly easy… The shell for user bandit26 is not /bin/bash, but something else. Find out what it is, how it works and how to break out of it.

```bash
ls
cat /etc/passwd
# we got level 26 has /usr/bin/showtext , let's see the content
file /usr/bin/showtext
cat /usr/bin/showtext
exit
```

`showtext` content -> this show `TERM=linux`

```bash
#!/bin/sh

export TERM=linux

more ~/text.txt
exit 0
```

```bash
ssh -i bandit26.sshkey bandit26@bandit.labs.overthewire.org -p 2220
# it closed immediately , so save bandit26.sshkey as bandit26rsa , try from local machine
```

```bash
nano bandit26rsa
chmod 700 banditrsa
ssh -i bandit26.sshkey bandit26@bandit.labs.overthewire.org -p 2220
# but dont execute last command
```

zoom in the terminal as much as possible , then execute cmd and resize into small `yes` . go to `more`
if you see `more` then press `v` to enter vi's edit mode , access vi options using `:`

```
:set shell=/bin/bash
:sh
@bandit26
```

Then ,
`cat /etc/bandit_pass/bandit26 `

---

#### **Level26:**

Good job getting a shell! Now hurry and grab the password for bandit27!.

Try to Connect the labs if it is immediately closed then,
Don't use flag , use ssh_private.key got from previous level ,to connect ,but 
zoom in the terminal as much as possible and resize into small . go to `more`
if you see `more` then press `v` to enter vi's edit mode

```
:set shell=/bin/bash
:shell
```

you will login as bandit26 then `ls -la`

```bash
./bandit27-do cat /etc/bandit_pass/bandit27
```

---

#### **Level27:**

There is a git repository at `ssh://bandit27-git@localhost/home/bandit27-git/repo` via the port `2220`. The password for the user `bandit27-git` is the same as for the user `bandit27`.

Clone the repository and find the password for the next level.

Make a temp directory and setup

```bash
cd /tmp/har5
git clone "ssh://bandit27-git@localhost:2220/home/bandit27-git/repo"
yes
3ba3118a22e93127a4ed485be72ef5ea
cd repo/
cat README
```

---

#### **Level28:**

There is a git repository at `ssh://bandit28-git@localhost/home/bandit28-git/repo` via the port `2220`. The password for the user `bandit28-git` is the same as for the user `bandit28`.
Make a temp directory and setup

```bash
cat /etc/bandit_pass/bandit28
cd /tmp/har5
git clone "ssh://bandit28-git@localhost:2220/home/bandit28-git/repo"
yes
0ef186ac70e04ea33b4c1853d2526fa2
cd repo/
cat README.md
```

```md
##credentials

- username: bandit29
- password: xxxxxxxxxx
```

Because of file has password also change in upcoming modification so check out  
`git log`  
you can repo commits with hash check each hash  
`git show edd935d60906b33f0619605abd1689808ccdd5ee `

---

#### **Level29:**

There is a git repository at `ssh://bandit29-git@localhost/home/bandit29-git/repo` via the port `2220`. The password for the user `bandit29-git` is the same as for the user `bandit29`.

Clone the repository and find the password for the next level.

Make a temp directory and setup

```bash
cd /tmp/har5
git clone "ssh://bandit29-git@localhost:2220/home/bandit29-git/repo"
yes
```

paste current level password because git repo password same as current level password

```bash
cat README.md
```

Because of file has password also change in upcoming modification ,so checking
`git log` git doesn't have password commit ,
so check may be a remote branches in this repo using `git check out remotes/origin/dev`

```bash
git branch -a
git checkout remotes/origin/dev
git log
git show 1d160de5f8f647f00634bbf3d49b9244275217b6
```

---

#### **Level30:**

There is a git repository at `ssh://bandit30-git@localhost/home/bandit30-git/repo` via the port `2220`. The password for the user `bandit30-git` is the same as for the user `bandit30`.

Make a temp directory and setup

```bash
cd /tmp/har5
git clone "ssh://bandit30-git@localhost:2220/home/bandit30-git/repo"
yes
5b90576bedb2cc04c86a9e924ce42faf
cat README.md
```

just an epmty file... muahaha  
there is no hash has a password modification so check .git

```bash
ls -la
cd .git
ls
cat packed-refs
```

3aefa229469b7ba1cc08203e5d8fa299354c496b refs/remotes/origin/master  
f17132340e8ee6c159e0a4a6bc6f80e1da3b1aea refs/tags/secret

```bash
git show f17132340e8ee6c159e0a4a6bc6f80e1da3b1aea
```

---

#### **Level31:**

There is a git repository at `ssh://bandit31-git@localhost/home/bandit31-git/repo` via the port `2220`. The password for the user `bandit31-git` is the same as for the user `bandit31`.

Make a temp directory and setup

```bash
cd /tmp/har5
git clone "ssh://bandit31-git@localhost/home/bandit31-git/repo"
yes
47e603bb428404d265f59c42920d81e5
cat README.md
```

This time your task is to push a file to the remote repository.

Details:  
File name: key.txt  
Content: 'May I come in?'  
Branch: master

paste “May I come in?” into `key.txt` , `.gitignore` this file ignore all `*.txt` in this repo to add into staging area so remove `.gitignore`

```bash
nano key.txt
git add key.txt -f
rm .gitignore
git add key.txr -f
git push
```

---

#### **Level32:**

After all this git stuff its time for another escape. Good luck!

`$0` If the $0 special variable is used within a Bash script, it can be used to print its name and if it is used directly within the terminal, it can be used to display the name of the current shell. , but we will unlock the shell, u won't get response every commands in `$0` shell

```bash
$0
cat /etc/bandit_pass/bandit33
# That's all
```

---
