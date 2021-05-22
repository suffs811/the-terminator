#!/usr/bin/env python3

# spaces are always ! points
coder = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1 234567890!"
a = int(input("Gimme a num from 1 to 10: "))
count = 0

while count < a:
	print("Hello, there")
	count += 1

i = input("\nHow are you today? ")
print(f"\nI'm glad to hear you are {i} today.")

# function to start if statement to run secret functions
def begin_secret():

	if i == "secret":

		print("\nWhat would you like to do? ")
		print("censor, encode, decode")
		to_do = input(": ")

		if to_do == "censor":
			para = input("paragraph: ")
			word = input("word: ")


		# function to censor a given word in a sentence/paragraph
			def censor(para, word):
				para_list = para.split()
				new_list = []
				for w in para_list:
					if w == word:
						new_w = ""
						for i in range(0, len(w)):
							new_w += "-"
						new_list.append(new_w)
					else:
						new_list.append(w)
				output = " ".join(new_list)
				return output

			print(censor(para, word))


		# function to encode a phrase
		elif to_do == "encode":
			para = input("paragraph: ")
			def encode(para):
				new_list = []
				for w in para:
					for l in w:
						if l != "":
							ll = coder.find(l) #int
							lll = coder[(ll+10)%64] #str
							new_list.append(lll)
						else:
							continue
				output = "".join(new_list)
				return output

			print(encode(para))


		# function to decode the encoded phrase
		elif to_do == "decode":
			para = input("paragraph: ")
			def decode(para):
				new_list = []
				for i in para:
					ii = coder.find(i)
					iii = coder[(ii-10)%64]
					new_list.append(iii)
				output = "".join(new_list)
				output.replace("!", " ")
				return output

			print(decode(para))

		else:
			raise SyntaxError("Unknown input. System will now self destruct")

	else:
		quit()

begin_secret()

print("Anything else? (y/n)")
again = input(": ")
if again == "y":
	begin_secret()
else:
	quit()
