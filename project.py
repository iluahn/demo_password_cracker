import hashlib
import os

def bruteforce(usr_hash):
	symbols = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
	flag = 0
	for current in range(4):
		a = [i for i in symbols]
		for y in range(current):
			a = [x+i for i in symbols for x in a]
		#searching
		for pswd in a:
			#using sha-256 algorithm
			hash_func = hashlib.sha256()
			#object must be encoded before hashing 
			pswd = pswd.encode('utf-8')
			hash_func.update(pswd)
			#return result in hex
			hash_value = hash_func.hexdigest()
			if(usr_hash == hash_value):
				print("\nPASSWORD:", pswd.decode())
				flag = 1
				break
		if(flag == 1):
			break
	if(flag == 0):
		print("\nPassword is too long or contains special symbols")

def dict_search(usr_hash):
	dict = open("dict.txt", "r")
	flag = 0
	for password in dict:
		password = password.replace('\n', '')
		#object must be encoded before hashing 
		password = password.encode('utf-8')
		#using sha-256 algorithm
		hash_func = hashlib.sha256()
		hash_func.update(password)
		#return result in hex
		hash_value = hash_func.hexdigest()
		if(usr_hash == hash_value):
			print("\nYour password was found in dictionary!")
			print("Password:", password.decode())
			flag = 1
			break
	if(flag == 0):
		print("\nYour password was NOT found in dictionary!")



option = -1
while(option != '4'):
	print("1)Search password's hash value in dictionary")
	print("2)Bruteforce password (for short passwords)")
	print("3)Calculate password's hash value")
	print("4)Exit")
	option = input()
	if(option == '1'):
		print("Print password's hash:")
		usr_hash = input()
		dict_search(usr_hash)
	if(option == '2'):
		print("Print password's hash:")
		usr_hash = input()
		bruteforce(usr_hash)
	if(option == '3'):
		print("Print your password to calculate sha256:")
		pswd = input()
		#object must be encoded before hashing 
		pswd = pswd.encode('utf-8')
		#using sha-256 algorithm
		hash_func = hashlib.sha256()
		hash_func.update(pswd)
		#return result in hex
		user_hash_value = hash_func.hexdigest()
		print("Password's hash:",user_hash_value)
	print("\n")










