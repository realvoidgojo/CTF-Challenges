import requests
import re

username = 'natas8'
password = 'a6bZCNYwdKqN5cGP11ZdtPg0iImQQhAB'

url = 'http://%s.natas.labs.overthewire.org/'%username
url1 = 'http://%s.natas.labs.overthewire.org/index-source.html'%username

sessions = requests.Session()
response = requests.post(url, data={'secret' : 'oubWYf2kBq' , 'submit':'submit'} ,
auth = (username,password))

# response = requests.get(url,auth=(username,password) )

content = response.text

# print(content)
hashvalue = re.findall("The password for natas9 is (.*)",content)[0]
print(hashvalue)