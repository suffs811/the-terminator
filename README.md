# scripts
various scripts. Use at your own risk. I am not responsible for any damage or harm done to anything or anyone at all ever for anything ever.

The encoder.py and decoder.py are to be used together as they hash a word into standard md5 hash format and decode an md5 hash, respectly. 
The remaining files are not connected to one another and are used for various, simply tasks described below:

- decoder.py - md5 hash to word via rockyou.txt (provide path to wordlist).
- encoder.py - word to md5 hash.
- encourage.py - asks for an emotion and gives a Bible verse for encouragement.
- link-redirect-www-data - to be used in a compromised web server. Replaces all paragraphs <p> in the index.html file to a link you provide.
- secret.py - disguised as a normal program. When asked how you are feeling today, reply 'secret' to encode/decode a message, or censor a word from a sentence/paragraph.
- system(notes).py - various notes I took on finding system information using python.
- exfil.py - script that write system data and /etc files to file, scp the file to local machine, and covers tracks by clearing logs.
- pers.py - script for establishing persistence on compromised target machine with root permissions

TO DO:
- add else: and f.close() to add_user function in pers.py