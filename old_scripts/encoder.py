#!/usr/bin/env Python3
# author: cysec11
# license: MIT license

# take an ascii word and hash it using md5


import hashlib


password = input("Password\n:")


enc_word = password.encode('utf-8')

hash_word = hashlib.md5(enc_word.strip())

digest = hash_word.hexdigest()

print(digest)
