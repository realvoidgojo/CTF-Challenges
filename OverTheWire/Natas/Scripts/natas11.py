import requests
import re
import urllib.parse as urllib

username = 'natas11'
password = '1KFqoJXi6hRaPluAmk8ESDW4fSysRoIg'

url = 'http://%s.natas.labs.overthewire.org/'%username
url1 = 'http://%s.natas.labs.overthewire.org/index-source.html'%username

session = requests.Session()

cookies = {"data" : "MGw7JCQ5OC04PT8jOSpqdmk3LT9pYmouLC0nICQ8anZpbS4qLSguKmkz"}

response = session.get(url,auth=(username,password) ,cookies=cookies)

content = response.text
flag = re.findall("The password for natas12 is (.*)<br>",content)[0]
print(flag)