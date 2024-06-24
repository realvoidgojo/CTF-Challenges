### CTF | OverTheWire | Krypton

SSH protocol (also referred to as Secure Shell) is a method for secure remote login from one computer to another. It provides several alternative options for strong authentication, and it protects the communications security and integrity with strong encryption

SSH Pass is a tiny utility, which allows you to provide the SSH password without using  
the prompt. This will very helpful for scripting. SSH Pass is not good to use in multi user environment [sshpass docs](https://linux.die.net/man/1/sshpass)

⚠️ **Disclaimer**: This solution was generated in June 2024. If you are accessing this information at a later date, please note that circumstances may have changed. Different levels of flags, variations in levels, and even new levels altogether might have been introduced. Please verify the most current and relevant information before making any decisions based on this content.

Welcome to Krypton! The first level is easy. The following string encodes the password using Base64:

```
S1JZUFRPTklTR1JFQVQ=
```

Use this password to log in to krypton.labs.overthewire.org with username krypton1 using SSH on port 2231. You can find the files for other levels in /krypton/

---

### Krypton0

`S1JZUFRPTklTR1JFQVQ=` , decode from base64 using `base64 -d` cmd , then we got that
`KRYPTONISGREAT` save as krypton1

```bash
sshpass -p `cat krypton1`  ssh krypton1@krypton.labs.overthewire.org -p 2231
```

### Krpton1

The password for level 2 is in the file ‘krypton2’. It is ‘encrypted’ using a simple rotation. It is also in non-standard ciphertext format. When using alpha characters for cipher text it is normal to group the letters into 5 letter clusters, regardless of word boundaries. This helps obfuscate any patterns. This file has kept the plain text word boundaries and carried them to the cipher text. Enjoy!

```bash
cd /krypton/
ls

krypton1  krypton2  krypton3  krypton4  krypton5  krypton6

cd krypton1

ls
krypton2  README # we have 2 files

cat krypton2
YRIRY GJB CNFFJBEQ EBGGRA

cat README

The first level is easy.  The password for level 2 is in the file
'krypton2'.  It is 'encrypted' using a simple rotation called ROT13.  <<<<

```

let reverse that encryption using `tr`

```bash
echo "YRIRY GJB CNFFJBEQ EBGGRA" | tr [A-Z] [N-ZA-M]
LEVEL TWO PASSWORD ROTTEN
# password is ROTTEN
```

---

### Krpton2

```bash
cd /krypton/krypton2
ls
encrypt  keyfile.dat  krypton3  README

cat README
ROT13 is a simple substitution cipher.
.....
example
krypton2@melinda:~$ mktemp -d
/tmp/tmp.Wf2OnCpCDQ
krypton2@melinda:~$ cd /tmp/tmp.Wf2OnCpCDQ
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ ln -s /krypton/krypton2/keyfile.dat
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ ls
keyfile.dat
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ chmod 777 .
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ /krypton/krypton2/encrypt /etc/issue
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ ls
ciphertext  keyfile.dat

cat krypton3
OMQEMDUEQMEK

#Let follow the above example from README
mktemp -d
cd /tmp/tmp.9T7GwxNK5j
ln -s /krypton/krypton2/keyfile.dat
ls
keyfile.dat
chmod 777 .

cat /etc/issue
Ubuntu 22.04.3 LTS \n \l

/krypton/krypton2/encrypt /etc/issue # let give issue file to encrypt binary
ls
ciphertext  keyfile.dat

# we followed above eg , and got ciphertext
cat ciphertext
GNGZFGXFEZX

/krypton/krypton2/encrypt
usage: encrypt foo  - where foo is the file containing the plaintext

# let create plaintext
echo "ABCDEFGHIJKLMNOPQRSTVWXYZ" > plaintext
ls
ciphertext  keyfile.dat  plaintext
/krypton/krypton2/encrypt plaintext
MNOPQRSTUVWXYZABCDEFHIJKL # we got the rotation pattern, using this let solve krypton3

cat /krypton/krypton2/krypton3
/krypton/krypton2/krypton3
OMQEMDUEQMEK

echo "OMQEMDUEQMEK" | tr [MNOPQRSTUVWXYZABCDEFHIJKL] [ABCDEFGHIJKLMNOPQRSTVWXYZ]
CAESARISEASY

# Short Hand example
echo "OMQEMDUEQMEK" | tr [M-ZA-L] [A-Z]
CAESARISEASY
```

https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,false,14)&input=T01RRU1EVUVRTUVL , we used CyberChef , got
`OMQEMDUEQMEK` -> `CAESARISEASY` alt ROT14 by brute force

---

### Krypton3

```bash
cd /krypton/krypton2
ls
found1  found2  found3  HINT1  HINT2  krypton4  README

file ./*
./found1:   ASCII text, with very long lines (1542), with no line terminators
./found2:   ASCII text, with very long lines (2128), with no line terminators
./found3:   ASCII text, with very long lines (560), with no line terminators
./HINT1:    ASCII text
./HINT2:    ASCII text
./krypton4: ASCII text, with no line terminators
./README:   ASCII text

cat README
Well done You have moved past an easy substitution cipher.Hopefully you just encrypted the alphabet a plaintext to fully expose the key in one swoop.The main weakness of a simple substitution cipher is  repeated use of a simple key.In the previous exerciseyou were able to introduce arbitrary plaintext to expose the key.  In this example, the cipher mechanism is not available to you, the attacker. However, you have been lucky.  You have intercepted more than one message. The password to the next level is found in the file 'krypton4'.  You have also found 3 other files.
(found1, found2, found3)

You know the following important details:
- The message plaintexts are in English (*** very important)
- They were produced from the same key (*** even better!)

cat krypton4
KSVVW BGSJD SVSIS VXBMN YQUUK BNWCU ANMJS
```

<img src="img/Pasted image 20240609110559.png" alt="Example Image" width="1080"/>

```bash
cat HINT1 HINt2
Some letters are more prevalent in English than others.
"Frequency Analysis" is your friend.
```

```py
#!/usr/bin/python3

# Script by Mike Rosinsky

import sys

if __name__=="__main__":

	char_table = {}
	char_total = 0
	groupsize = 0
	current_list = []
	frequency_list = "ETAOINSRHDLUCMFYWGPBVKXQJZ"

	#Check Argument Counts
	if len(sys.argv) != 3:
		print("Usage: python3 freq_analysis.py filename groupsize")
		exit(0)
	else:

		try:
			groupsize = int(sys.argv[2])
		except:
			print("groupsize must be an int")
			exit(0)

		# Try to Open the specified file
		try:
			with open(sys.argv[1]) as fh:
				lines = fh.readlines()
		except:
			print("No file named '" + sys.argv[1] + "'")
			exit(0)

		for line in lines:
			line = line.replace(" ", "")
			line = line.replace("\n", "")
			for i in range(len(line) - groupsize):
				group = line[i:i+groupsize]
				if group in char_table:
					char_table[group] += 1
				else:
					char_table[group] = 1

		char_table = sorted(char_table.items(), key=lambda x: x[1], reverse=True)

		for char in char_table:
			print(char[0] + ":\t" + str(char[1]))
			current_list.append(char[0])
	print("Current Frequency :","".join(current_list))
	print("Frequency    List :",frequency_list)
```

https://www.101computing.net/frequency-analysis/

<img src="img/Pasted image 20240609144411.png" alt="Example Image" width="700"/>

Let make upload this frequency analysis script to krpton3 labs using scp

```bash
mktemp -d
tmp/tmp.X0U5Fr1q4L
cp found1 found2 found3 krytpon4 /tmp/tmp.X0U5Fr1q4L
cd /tmp/tmp.X0U5Fr1q4L
ls
found1  found2  found3  krypton4
```

from your local machine uploading above script using `scp`

```bash
scp -P 2231 freq_analysis.py krypton3@krypton.labs.overthewire.org:/tmp/tmp.X0U5Fr1q4L
```

in lab , check for the uploaded script

```bash
ls
freq_analysis.py
python3 freq_analysis.py
Usage: python3 freq_analysis.py filename groupsize
# let define size = 1 , 1 char RUN like that
python3 freq_analysis.py found1 1
# merge all data together , for accuracy
cat found1 found2 found3 > all_text
python3 freq_analysis.py all_text 1
```

```
# all_text  # Frequency Table from global stats
S:      456  E:  12.02
Q:      340  T:   9.10
J:      300  A:   8.12
U:      257  O:   7.68
B:      246  I:   7.31
N:      240  N:   6.95
C:      227  S:   6.28
G:      227  R:   6.02
D:      210  H:   5.92
Z:      132  D:   4.32
V:      130  L:   3.98
W:      129  U:   2.88
M:       86  C:   2.71
Y:       84  M:   2.61
T:       75  F:   2.30
X:       71  Y:   2.11
K:       67  W:   2.09
E:       64  G:   2.03
L:       60  P:   1.82
A:       55  B:   1.49
F:       28  V:   1.11
I:       19  K:   0.69
O:       12  X:   0.17
H:        4  Q:   0.11 # Same Freq
R:        4  J:   0.10 # Same Freq ,so change if needed
P:        2  Z:   0.07
```

Frequency analysis of letters in the English language is often used in cryptography to identify patterns and decipher encoded messages

```bash
python3 freq_analysis.py all_text 3
JDS:    61

THE is most used word across english , so J -> T , D -> H , S -> E
cat /krypton/krypton3/krypton4 | tr [JDS] [THE]
KEVVW BGETH EVEIE VXBMN YQUUK BNWCU ANMTE

cat krypton4 | tr [JDSQNVXP] [THEARLFZ]
KELLW BGETH ELEIE LFBMR YAUUK BRWCU ARMTE

- Freq list: ETAOINSRHDLUCMFYWGPBVKXQJZ
- Cipher text: SQJUBNGCDZVWMYTXKELAFIORHP

cat krypton4 | tr [SQJUBNGCDZVWMYTXKELAFIORHP] [ETAOINSRHDLUCMFYWGPBVKXQJZ]
WELLU ISEAH ELEKE LYICN MTOOW INURO BNCAE

JDS  U B G C Z W M Y T K E L A F I O R H Q N V X P
THE  S O N I C D U P Y W G M B K V X Q J A R L F Z

# after couple of changes
tr [JDSQUBNGCZVWMYTXKELAFIORHP] [THEASORNICLDUPYFWGMBKVXQJZ]
```

I made distribution map for above data analysis

<img src="img/Pasted image 20240609221503.png" alt="Example Image" width="650"/>

```
cat /krypton/krypton3/krypton4 | tr 'SQJUBNGCDZVWMYTXKELAFIORHP' 'EATSORNIHCLDUPYFWGMBKVXQJZ'
WELLD ONETH ELEVE LFOUR PASSW ORDIS BRUTE

# WELL DONE THE LEVEL FOUR PASSWORD IS BRUTE
```

> [!Alternate]
> Simple automated approach , copy the found1 , found2 , found3 , krypton4 data

```
CGZNL YJBEN QYDLQ ZQSUQ NZCYD SNQVU BFGBK GQUQZ QSUQN UZCYD SNJDS UDCXJ ZCYDS NZQSU QNUZB WSBNZ QSUQN UDCXJ CUBGS BXJDS UCTYV SUJQG WTBUJ KCWSV LFGBK GSGZN LYJCB GJSZD GCHMS UCJCU QJLYS BXUMA UJCJM JCBGZ CYDSN CGKDC ZDSQZ DVSJJ SNCGJ DSYVQ CGJSO JCUNS YVQZS WALQV SJJSN UBTSX COSWG MTASN BXYBU CJCBG UWBKG JDSQV YDQAS JXBNS OQTYV SKCJD QUDCX JBXQK BMVWA SNSYV QZSWA LWAKB MVWAS ZBTSS QGWUB BGJDS TSJDB WCUGQ TSWQX JSNRM VCMUZ QSUQN KDBMU SWCJJ BZBTT MGCZQ JSKCJ DDCUE SGSNQ VUJDS SGZNL YJCBG UJSYY SNXBN TSWAL QZQSU QNZCY DSNCU BXJSG CGZBN YBNQJ SWQUY QNJBX TBNSZ BTYVS OUZDS TSUUM ZDQUJ DSICE SGNSZ CYDSN QGWUJ CVVDQ UTBWS NGQYY VCZQJ CBGCG JDSNB JULUJ STQUK CJDQV VUCGE VSQVY DQASJ UMAUJ CJMJC BGZCY DSNUJ DSZQS UQNZC YDSNC USQUC VLANB FSGQG WCGYN QZJCZ SBXXS NUSUU SGJCQ VVLGB ZBTTM GCZQJ CBGUS ZMNCJ LUDQF SUYSQ NSYNB WMZSW TBUJB XDCUF GBKGK BNFAS JKSSG QGWDC USQNV LYVQL UKSNS TQCGV LZBTS WCSUQ GWDCU JBNCS UESGN SUDSN QCUSW JBJDS YSQFB XUBYD CUJCZ QJCBG QGWQN JCUJN LALJD SSGWB XJDSU COJSS GJDZS GJMNL GSOJD SKNBJ STQCG VLJNQ ESWCS UMGJC VQABM JCGZV MWCGE DQTVS JFCGE VSQNQ GWTQZ ASJDZ BGUCW SNSWU BTSBX JDSXC GSUJS OQTYV SUCGJ DSSGE VCUDV QGEMQ ESCGD CUVQU JYDQU SDSKN BJSJN QECZB TSWCS UQVUB FGBKG QUNBT QGZSU QGWZB VVQAB NQJSW KCJDB JDSNY VQLKN CEDJU TQGLB XDCUY VQLUK SNSYM AVCUD SWCGS WCJCB GUBXI QNLCG EHMQV CJLQG WQZZM NQZLW MNCGE DCUVC XSJCT SQGWC GJKBB XDCUX BNTSN JDSQJ NCZQV ZBVVS QEMSU YMAVC UDSWJ DSXCN UJXBV CBQZB VVSZJ SWSWC JCBGB XDCUW NQTQJ CZKBN FUJDQ JCGZV MWSWQ VVAMJ JKBBX JDSYV QLUGB KNSZB EGCUS WQUUD QFSUY SQNSU

QVJDB MEDGB QJJSG WQGZS NSZBN WUXBN JDSYS NCBWU MNICI STBUJ ACBEN QYDSN UQENS SJDQJ UDQFS UYSQN SKQUS WMZQJ SWQJJ DSFCG EUGSK UZDBB VCGUJ NQJXB NWQXN SSUZD BBVZD QNJSN SWCGQ ABMJQ HMQNJ SNBXQ TCVSX NBTDC UDBTS ENQTT QNUZD BBVUI QNCSW CGHMQ VCJLW MNCGE JDSSV CPQAS JDQGS NQAMJ JDSZM NNCZM VMTKQ UWCZJ QJSWA LVQKJ DNBME DBMJS GEVQG WQGWJ DSUZD BBVKB MVWDQ ISYNB ICWSW QGCGJ SGUCI SSWMZ QJCBG CGVQJ CGENQ TTQNQ GWJDS ZVQUU CZUQJ JDSQE SBXUD QFSUY SQNST QNNCS WJDSL SQNBV WQGGS DQJDQ KQLJD SZBGU CUJBN LZBMN JBXJD SWCBZ SUSBX KBNZS UJSNC UUMSW QTQNN CQESV CZSGZ SBGGB ISTAS NJKBB XDQJD QKQLU GSCED ABMNU YBUJS WABGW UJDSG SOJWQ LQUUM NSJLJ DQJJD SNSKS NSGBC TYSWC TSGJU JBJDS TQNNC QESJD SZBMY VSTQL DQISQ NNQGE SWJDS ZSNST BGLCG UBTSD QUJSU CGZSJ DSKBN ZSUJS NZDQG ZSVVB NQVVB KSWJD STQNN CQESA QGGUJ BASNS QWBGZ SCGUJ SQWBX JDSMU MQVJD NSSJC TSUQG GSUYN SEGQG ZLZBM VWDQI SASSG JDSNS QUBGX BNJDC UUCOT BGJDU QXJSN JDSTQ NNCQE SUDSE QISAC NJDJB QWQME DJSNU MUQGG QKDBK QUAQY JCUSW BGTQL JKCGU UBGDQ TGSJQ GWWQM EDJSN RMWCJ DXBVV BKSWQ VTBUJ JKBLS QNUVQ JSNQG WKSNS AQYJC USWBG XSANM QNLDQ TGSJW CSWBX MGFGB KGZQM USUQJ JDSQE SBXQG WKQUA MNCSW BGQME MUJQX JSNJD SACNJ DBXJD SJKCG UJDSN SQNSX SKDCU JBNCZ QVJNQ ZSUBX UDQFS UYSQN SMGJC VDSCU TSGJC BGSWQ UYQNJ BXJDS VBGWB GJDSQ JNSUZ SGSCG ASZQM USBXJ DCUEQ YUZDB VQNUN SXSNJ BJDSL SQNUA SJKSS GQGWQ UUDQF SUYSQ NSUVB UJLSQ NUACB ENQYD SNUQJ JSTYJ CGEJB QZZBM GJXBN JDCUY SNCBW DQISN SYBNJ SWTQG LQYBZ NLYDQ VUJBN CSUGC ZDBVQ UNBKS UDQFS UYSQN SUXCN UJACB ENQYD SNNSZ BMGJS WQUJN QJXBN WVSES GWJDQ JUDQF SUYSQ NSXVS WJDSJ BKGXB NVBGW BGJBS UZQYS YNBUS ZMJCB GXBNW SSNYB QZDCG EQGBJ DSNSC EDJSS GJDZS GJMNL UJBNL DQUUD QFSUY SQNSU JQNJC GEDCU JDSQJ NCZQV ZQNSS NTCGW CGEJD SDBNU SUBXJ DSQJN SYQJN BGUCG VBGWB GRBDG QMANS LNSYB NJSWJ DQJUD QFSUY SQNSD QWASS GQZBM GJNLU ZDBBV TQUJS NUBTS JKSGJ CSJDZ SGJMN LUZDB VQNUD QISUM EESUJ SWJDQ JUDQF SUYSQ NSTQL DQISA SSGST YVBLS WQUQU ZDBBV TQUJS NALQV SOQGW SNDBE DJBGB XVQGZ QUDCN SQZQJ DBVCZ VQGWB KGSNK DBGQT SWQZS NJQCG KCVVC QTUDQ FSUDQ XJSCG DCUKC VVGBS ICWSG ZSUMA UJQGJ CQJSU UMZDU JBNCS UBJDS NJDQG DSQNU QLZBV VSZJS WQXJS NDCUW SQJD

DSNSM YBGVS ENQGW QNBUS KCJDQ ENQIS QGWUJ QJSVL QCNQG WANBM EDJTS JDSAS SJVSX NBTQE VQUUZ QUSCG KDCZD CJKQU SGZVB USWCJ KQUQA SQMJC XMVUZ QNQAQ SMUQG WQJJD QJJCT SMGFG BKGJB GQJMN QVCUJ UBXZB MNUSQ ENSQJ YNCPS CGQUZ CSGJC XCZYB CGJBX ICSKJ DSNSK SNSJK BNBMG WAVQZ FUYBJ UGSQN BGSSO JNSTC JLBXJ DSAQZ FQGWQ VBGEB GSGSQ NJDSB JDSNJ DSUZQ VSUKS NSSOZ SSWCG EVLDQ NWQGW EVBUU LKCJD QVVJD SQYYS QNQGZ SBXAM NGCUD SWEBV WJDSK SCEDJ BXJDS CGUSZ JKQUI SNLNS TQNFQ AVSQG WJQFC GEQVV JDCGE UCGJB ZBGUC WSNQJ CBGCZ BMVWD QNWVL AVQTS RMYCJ SNXBN DCUBY CGCBG NSUYS ZJCGE CJ

KSVVW BGSJD SVSIS VXBMN YQUUK BNWCU ANMJS
```

paste this in https://www.quipqiup.com/ , and solve

<img src="img/Pasted image 20240609153316.png" alt="Example Image" width="1080"/>

---

### Krypton4

```bash
cd /krypton/krypton4
ls
found1  found2  HINT  krypton5  README
/tmp/tmp.85ll5KYW2v
```

we need frequency_anlayis.py , vignere_shift.py , vignere_decoder.py

vignere_shift.py

```py
#!/usr/bin/python3

# Script by Mike Rosinsky

import sys

if __name__=="__main__":

	key_length = 4
	shift = 0
	out_string = ""

	if len(sys.argv) > 4:
		print("Usage: python3 vignere_shift.py filename key_length [shift]")
		exit(0)
	else:

		try:
			key_length = int(sys.argv[2])
			if len(sys.argv) == 4:
				shift = int(sys.argv[3])
		except:
			print("key_length and [shift] must be an int")
			exit(0)

		try:
			with open(sys.argv[1]) as fh:
				lines = fh.readlines()
		except:
			print("No file named '" + sys.argv[1] + "'")
			exit(0)

		for line in lines:
			line = line.replace(" ", "")
			line = line.replace("\n", "")
			for index in range(shift, len(line)):
				if index % key_length == shift:
					out_string += line[index]

		print(out_string)
```

vignere_decoder.py

```py
#!/bin/usr/python3

# Script by Mike Rosinsky

import sys

key = ""
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

if __name__=="__main__":

	out_string = ""

	if (len(sys.argv)) != 3:
		print("Usage: python3 vignere_decoder.py filename key")
		exit(0)
	else:

		key = sys.argv[2]

		print("Decoding file '" + sys.argv[1] + "' with key '" + sys.argv[2] + "':\n")

		try:
			with open(sys.argv[1]) as fh:
				lines = fh.readlines()
		except:
			print("No file named '" + sys.argv[1] + "'")
			exit(0)

		for line in lines:
			line = line.replace(" ", "")
			line = line.replace("\n", "")
			for index in range(len(line)):
				c = alphabet[(alphabet.index(line[index]) - alphabet.index(key[index % len(key)])) % 26]
				out_string += c

	print(out_string)

```

```
cat README
Good job!

You more than likely used frequency analysis and some common sense
to solve that one.

So far we have worked with simple substitution ciphers.  They have
also been 'monoalphabetic', meaning using a fixed key, and
giving a one to one mapping of plaintext (P) to ciphertext (C).
Another type of substitution cipher is referred to as 'polyalphabetic',
where one character of P may map to many, or all, possible ciphertext
characters.

An example of a polyalphabetic cipher is called a Vigen�re Cipher.  It works
like this:

If we use the key(K)  'GOLD', and P = PROCEED MEETING AS AGREED, then "add"
P to K, we get C.  When adding, if we exceed 25, then we roll to 0 (modulo 26).


P     P R O C E   E D M E E   T I N G A   S A G R E   E D
K     G O L D G   O L D G O   L D G O L   D G O L D   G O

becomes:

P     15 17 14 2  4  4  3 12  4 4  19  8 13 6  0  18 0  6 17 4 4   3
K     6  14 11 3  6 14 11  3  6 14 11  3  6 14 11  3 6 14 11 3 6  14
# P + K = C
C     21 5  25 5 10 18 14 15 10 18  4 11 19 20 11 21 6 20  2 8 10 17

So, we get a ciphertext of:

VFZFK SOPKS ELTUL VGUCH KR

This level is a Vigen�re Cipher.  You have intercepted two longer, english
language messages.  You also have a key piece of information.  You know the
key length!

> [!NOTE]
> For this exercise, the key length is 6.  The password to level five is in the usual

place, encrypted with the 6 letter key.

Have fun!

```

Let convert polyalphabetic into polyalphabetic m key = 6 ,

```bash
python3 vignere_shift.py /krypton/krypton4/found1 6 0 > shift0
cat shift0

YIYWNQRLYTRHYDJTWZSLNNHTMJJYFNYIJJSLWNMFXBBKXIMJTBMIYJJNTYBWKWWLFGWISJSZYSYPJNFJQFWTYWKJJMMNSYWKYSAYMTSQZJRFDMKXFJJPKFSTTTJMBMJDSQIJPFJTSJWJPJIKXISJFFYXMQMYIMZYFSJWJNTWGJYGZTMTYSFFJTWJQBSFSJSJIJJNKWSXZYZKXMSSIFTXSSKTJTYWMYKLTISNJFITWIXNBSJHJF

# Let Frequency analyis
J:      37
S:      24
Y:      22
T:      20
W:      17
F:      17
M:      16
I:      14
N:      12
K:      11
X:      9
Z:      7
B:      7
Q:      6
L:      5
P:      4
R:      3
H:      3
D:      3
G:      3
A:      1
Current Frequency : J SYTWFMINKXZBQLPRHDGA
Frequency    List : E TAOINSRHDLUCMFYWGPBVKXQJZ

A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z
0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25

# P + K = C
we know ,
K = C - P
K = 9 - 4 = 5 (F)

python3 vignere_shift.py /krypton/krypton4/found1 6 1 > shift1
cat shift1
V:      35
K:      31
Y:      19
F:      19
Z:      18
U:      16
R:      16
J:      14
I:      12
E:      12
N:      8
W:      7
C:      7
P:      7
T:      6
X:      4
M:      3
S:      2
G:      2
L:      2
B:      1
Current Frequency : VKYFZURJIENWCPTXMSGLB
Frequency    List : ETAOINSRHDLUCMFYWGPBVKXQJZ

# P + K = C
we know ,
K = C - P
K = 21 - 4 = 17 (R)

# Repeat this process till 0 to 5 , Key Length = 6
FREKE

# For shift5 C - E
K = C - P
K = 2 - 4 = -2 refers to index , which is Y

KEY = FREKEY

```

```bash
python3 vignere_decoder.py /krypton/krypton4/krypton5 FREKEY
Decoding file '/krypton/krypton4/krypton5' with key 'FREKEY':

# The password is
CLEARTEXT
```

> [!Alternate]
> Simple automated approach , copy the found1 , found2 data and paste , then click automatic decryption

https://www.dcode.fr/vigenere-cipher?__r=1.bfe6582fb9b4a64b88c14daa919fc7c2

<img src="img/Pasted image 20240610190212.png" alt="Example Image" width="1080"/>

Paster Key and cipher , click decrypt

<img src="img/Pasted image 20240610190439.png" alt="Example Image" width="1080"/>

---

### Krypton5

```bash
cd /krypton/krypton5
ls
found1  found2  found3  krypton6  README
cat README
Frequency analysis can break a known key length as well.  Lets try one
last polyalphabetic cipher, but this time the key length is unknown.
Enjoy.

# Same Problem but Unknow Key Length
mktemp -d
/tmp/tmp.GB1KGksMl3
cd /tmp/tmp.GB1KGksMl3

```

I Search to find key length for Vigenère ciphertext , and found kasiski test

> [!NOTE]
> The Kasiski test analyzes repeated sequences of characters in a Vigenère cipher's ciphertext to find distances between them. These distances are used to determine the greatest common divisors, helping to estimate the key length

Kasiski Test Program

```py
from collections import defaultdict
import re
import sys
from math import gcd
from collections import Counter

def kasiski_test(ciphertext):
    # Remove non-alphabet characters and convert to uppercase
    ciphertext = re.sub(r'[^A-Z]', '', ciphertext.upper())

    # Dictionary to store sequences and their positions
    sequences = defaultdict(list)

    # Look for sequences of 3 characters (can be adjusted if needed)
    for i in range(len(ciphertext) - 2):
        seq = ciphertext[i:i+3]
        sequences[seq].append(i)

    # Find distances between repeated sequences
    distances = []
    for seq, positions in sequences.items():
        if len(positions) > 1:
            for i in range(1, len(positions)):
                distances.append(positions[i] - positions[i-1])

    # Calculate GCD of each pair of distances and count frequencies
    gcd_counts = Counter()
    for i in range(len(distances)):
        for j in range(i + 1, len(distances)):
            g = gcd(distances[i], distances[j])
            if g > 1:  # We are interested in GCDs greater than 1
                gcd_counts[g] += 1

    return gcd_counts

def main():
    # Check if the file path argument is provided
    if len(sys.argv) != 2:
        print("Usage: python kasiski.py <ciphertext_file>")
        return

    # Read ciphertext from file
    file_path = sys.argv[1]
    try:
        with open(file_path, 'r') as file:
            ciphertext = file.read()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return

    # Perform Kasiski test to find the key length frequencies
    gcd_counts = kasiski_test(ciphertext)

    if gcd_counts:
        # Calculate total counts
        total_counts = sum(gcd_counts.values())

        # Print frequencies as percentages
        print("Possible key lengths with likelihood percentages:")
        for key_length, count in gcd_counts.most_common():
            percentage = (count / total_counts) * 100
            if percentage < 1:
                break
            print(f"{key_length} -> {percentage:.2f}%")
    else:
        print("No repeated sequences found. Unable to estimate key length.")

if __name__ == "__main__":
    main()

```

Let Test the possible key length

```
python3 kasiski_test.py found1
9 -> 40.07

python3 kasiski_test.py found2
9 -> 44.52%

python3 kasiski_test.py found3
9 -> 39.00%

KEY LENGHT = 9
```

```
python3 vignere_shift.py found1 9 0 > shift0
python3 vignere_shift.py found1 9 1 > shift1
python3 vignere_shift.py found1 9 2 > shift2
python3 vignere_shift.py found1 9 3 > shift3
python3 vignere_shift.py found1 9 4 > shift4
python3 vignere_shift.py found1 9 5 > shift5
python3 vignere_shift.py found1 9 6 > shift6
python3 vignere_shift.py found1 9 7 > shift7
python3 vignere_shift.py found1 9 8 > shift8
```

```bash

A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z
0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25

B,E -> 1-4  = -3 (X)
I,E -> 8-4  = 4  (E)
C,E -> 2-4  = -2 (Y)
P,E -> 15-4  = 11 (L)
I,E -> 8-4   = 4  (E)
R,E -> 17-4  = 13 (N)
G,E -> 6 - 4 = 2  (C)
X,E -> 23 - 4 = 29 (T)
L,E -> 11 - 4 =  7 (H)

# "XEYLENCTH" This has to be "KEYLENGTH" , u can do this for found2 ,found3

python3 vignere_decoder.py krypton6 KEYLENGTH
Decoding file 'krypton6' with key 'KEYLENGTH':

RANDOM
```

> [!Alternate]
> Simple automated approach , copy the found1 , found2 data and paste , then click automatic decryption

https://www.dcode.fr/vigenere-cipher?__r=1.bfe6582fb9b4a64b88c14daa919fc7c2

---

### Krypton6

```bash
cd /krypton/krypton6
ls
encrypt6  HINT1  HINT2  keyfile.dat  krypton7  onetime  README

mktemp -d
cd /tmp/tmp.uyGTFzTRM1
ln -s /krypton/krypton6/keyfile.dat

touch tales_line
ITWASTHEBESTOFTIMES
xxd -b tales_line
00000000: 01001001 01010100 01010111 01000001 01010011 01010100  ITWAST
00000006: 01001000 01000101 01000010 01000101 01010011 01010100  HEBEST
0000000c: 01001111 01000110 01010100 01001001 01001101 01000101  OFTIME
00000012: 01010011 00001010                                      S.

/krypton/krypton6/encrypted6 tales_line ctext

cat ctext
MBYTVZFMZDCMVSLQDJP
xxd -b ctext
00000000: 01001101 01000010 01011001 01010100 01010110 01011010  MBYTVZ
00000006: 01000110 01001101 01011010 01000100 01000011 01001101  FMZDCM
0000000c: 01010110 01010011 01001100 01010001 01000100 01001010  VSLQDJ
00000012: 01010000                                               P

ITWASTHEBESTOFTIMES
MBYTVZFMZDCMVSLQDJP

^ : XOR
01001001 ^ 01001101 = 00000100 (4) -> (E)
A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z
0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25

# Instead we use A becaues its 0 m A ^ 0 -> A , 'A' is a Key
rm ctext

python3 -c "print('A'*69)" > a.text
ls
a.text  keyfile.dat  tales_line
/krypton/krypton6/encrypt6 a.text cipher_text
cat cipher_text
EICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIY

EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
EICTDGYIY

# Its is a Symmetric Block Cipher , but due to AAA.. , its is Key
python3 vignere_decoder.py /krypton/krypton6/krypton7 EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
Decoding file '/krypton/krypton6/krypton7' with key 'EICTDGYIYZKTHNSIRFXYCPFUEOCKRN':

LFSRISNOTRANDOM

```

---

### Krypton7

```bash

krypton7@bandit:~$ cd /krypton/krypton7
krypton7@bandit:/krypton/krypton7$ ls
README
krypton7@bandit:/krypton/krypton7$ cat README
Congratulations on beating Krypton!

```
