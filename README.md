# The Terminator
+++ A tool for automating the enumeration, privilege escalation, persistence, exfiltration, and reporting stages of a pentest +++

# how to use
terminator.py is used by itself and is comprised of enum.py, exfil.py, priv.py, and pers.py. for this reason, you can either use terminator.py by itself, or use each of the other scripts individually.

/ for help with usage, use the -h flag or grep for 'usage' in the script (grep "usage" enum.py)

- terminator.py - tool for automating enumeration, privilege escalation, persistence, and exfiltration
- enum.py - script for automating common enumeration techniques (nmap,web,ftp,smb,nfs)
- priv.py - script to automate common privelege escalation techniques
- pers.py - script for establishing persistence on compromised target machine with root permissions.
- exfil.py - script for writing system data and /etc files to file, scp the file to local machine, and covers tracks by clearing logs.
- report.py - script to compile pentest data from the above scripts and create a report with it

Leave a comment if you have any questions!

 _______ _    _ ______ 
|__   __| |  | |  ____|  
   | |  | |__| | |__                                            |
   | |  |  __  |  __|  > - - - - - - - - - - - - - - - - - - +++ +++
   | |  | |  | | |____                                          | 
   |_|  |_|  |_|______|
 _______ ______ _____  __  __ _____ _   _       _______ ____  _____  
|__   __|  ____|  __ \|  \/  |_   _| \ | |   /\|__   __/ __ \|  __ \ 
   | |  | |__  | |__) | \  / | | | |  \| |  /  \  | | | |  | | |__) |
   | |  |  __| |  _  /| |\/| | | | | . ` | / /\ \ | | | |  | |  _  / 
   | |  | |____| | \ \| |  | |_| |_| |\  |/ ____ \| | | |__| | | \ \ 
   |_|  |______|_|  \_\_|  |_|_____|_| \_/_/    \_\_|  \____/|_|  \_\
\n
\\ created by: suffs811
\\ https://github.com/suffs811/Terminator.git
