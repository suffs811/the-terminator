# hello! welcome to the terminator's individual scripts!
- you can use these to isolate an individual stage of the penetration test, instead of using terminator.py.

<> note: terminator.py contains all the indiv scripts and is the primary method for using the terminator tool; therefore, the individual scripts might not be as up to date or production ready! 
- feel free to leave a comment or suggestion for making the tool better

- enum.py - script for automating common enumeration techniques (nmap,web,ftp,smb,nfs)
- priv.py - script to automate common privelege escalation techniques
- pers.py - script for establishing persistence on compromised target machine with root permissions.
- exfil.py - script for writing system data and /etc files to file, scp the file to local machine, and covers tracks by clearing logs.
- report.py - script to compile pentest data from the above scripts and create a report with it

*report.py will likely not function properly if the individual scripts are used; so, to ensure proper report.py functionality, please use terminator.py*
