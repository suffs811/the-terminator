#!/usr/bin/env Python3

import hashlib
print("******************** Password Cracker ********************")

pass_found = 0

input_hash = input("Enter the hashed password: ")

pass_doc = input("\nEnter path to passwords file: ")

try:
	pass_file = open(pass_doc, "r")
except:
	print("Error:")
	print(pass_doc, " is not found. \nPlease give correct path.")
	quit()

for word in pass_file:
	enc_word = word.encode('utf-8')

	hash_word = hashlib.md5(enc_word.strip())

	digest = hash_word.hexdigest()

	if digest == input_hash:
		print("Password found.\nThe password is: ", word)
		pass_found = 1
		break

if not pass_found:
	print("Password not found in ", pass_doc)
	print("\n")

print("******************** Thank you ********************")