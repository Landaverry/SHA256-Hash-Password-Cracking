#Python - SHA256 Password Cracking
#Takes the SHA256 hash of a password and runs it against the SHA256 hash of each password found in the rockyou.txt file
from pwn import * 
import sys

#This project allows crednetials to be passed rather than being hard coded like the SSH brute froce project
#Check to see if the right number of arguments are passed in during .py call
if len(sys.argv) != 2:
	print("Inavlid Arguments!")
	print(">> {} <SHA256sum>".format(sys.argv[0]))
	exit()
#Pass first parameter into variable
wanted_hash=sys.argv[1]
#Assign a password file
password_file="rockyou.txt"
#Keep track of number of attempts made
attempts=0
#
with log.progress("Attempting to Crack: {}!\n".format(wanted_hash)) as p:
	#Open password file
	with open(password_file, "r", encoding='latin-1') as password_list:
		for password in password_list:
			#iterate through each password in the password file and cleanup
			#removes the trailing new line
			password = password.strip("\n").encode('latin-1')
			#Use sha256sum from the pwntools library to create password hash
			password_hash = sha256sumhex(password)
			#update the status of the cracking job
			p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'),password_hash))
			#Checking the hashes of the two passwords
			if password_hash == wanted_hash:
				p.success("Password Has found after {} attempts! {} hashes to {}!".format(attempts, password.decode('latin-1'),password_hash))
				exit()
			attempts+=1
		p.failure("Password hash not found!")