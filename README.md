# scripts
various scripts.

Linux pentesting scripts:
- enum.py - script for automating common enumeration techniques (nmap,web,ftp,smb,nfs)
- exfil.py - script that write system data and /etc files to file, scp the file to local machine, and covers tracks by clearing logs.
- priv.py - script to automate common privelege escalation techniques
- pers.py - script for establishing persistence on compromised target machine with root permissions.

Older scripts:
The encoder.py and decoder.py are to be used together as they hash a word into standard md5 hash format and decode an md5 hash, respectly. 
The remaining files are not connected to one another and are used for various tasks described below:

- encoder.py - word to md5 hash.
- decoder.py - md5 hash to word via rockyou.txt (provide path to wordlist).
- encourage.py - asks for an emotion and gives a bible verse for encouragement.
- link-redirect-www-data - to be used in a compromised web server. Replaces all paragraphs <p> in the index.html file to a link you provide.
- secret.py - disguised as a normal program. When asked how you are feeling today, reply 'secret' to encode/decode a message, or 'censor' a word from a sentence/paragraph.
- system(notes).py - various notes I took on finding system information using python.
