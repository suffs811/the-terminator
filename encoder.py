#!/usr/bin/env Python3

import hashlib


password = input("Password\n:")


enc_word = password.encode('utf-8')

hash_word = hashlib.md5(enc_word.strip())

digest = hash_word.hexdigest()

print(digest)