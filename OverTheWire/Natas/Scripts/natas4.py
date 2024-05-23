import requests
import re

username = 'natas4'
password = 'tKOcJIbzM4lTs8hbCmzn5Zr4434fGZQm'

url = 'http://%s.natas.labs.overthewire.org'%username

# response = requests.get(url,auth=(username,password))
# content = response.text

print(requests.get(url, headers={'natas5': password}))
# hashvalue = re.findall("natas4:(.*)",content)[0]
# print(hashvalue)