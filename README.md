# the terminator
+++ a tool for automating common techniques for the enumeration, privilege escalation, persistence, exfiltration, and reporting stages of a pentest +++

- *feel free to use and test the terminator and share your suggestions in the Discussions*
# contents
the terminator automates every stage of a penetration test *except* gaining the initial shell (there are too many possible ways to get an initial shell for it to be reliably automated, and it can depend on a multitude of nuanced vulnerabilities, so that stage is up to you, good luck!)
- terminator.py - tool for automating common techniques for enumeration, privilege escalation, persistence, exfiltration, and reporting
- directory-list.txt - default wordlist of common directory names for web enumeration (use -w in 'enum' module to specify a different wordlist)

# how to use
terminator.py has four modules (enum, priv, root, and report):
- enum - enumerate the target ip
- priv - attempt privilege escalation on target machine
- root - with root privileges, establish persistence and exfiltrate system data to local machine
- report - create .txt and .docx report files on local machine from data gathered using the previous modules

because terminator only automates the most common penetration testing procedures, you will still need to put in some manual work if terminator is not successful. this tool is simply to speed up and automate the simple tasks.

- clone the repository to your computer with "git clone https://github.com/suffs811/the-terminator.git"
- if you choose to only download terminator.py and not the entire repo, you will need to specify a directory wordlist for webpage enumeration ("-w" with the "enum" module of terminator.py)

<> note: for full terminator productivity, you will need to run the script *four* separate times:
first on your own machine, second time on the target machine after gaining initial shell, third time on target machine after gaining root privileges, and fourth time on your local machine to compile the report.

terminator.py will create a .txt file and a Word (.docx) file from terminator's findings as the report

*for help with usage, use the -h flag or grep for 'usage' in the script (grep "usage" terminator.py)*

*hint: local machine = your own machine*

# syntax
(stage 1-enumerating target from local machine):
- python3 terminator.py enum -t <target_ip_to_enumerate>
(optional: -w <path_to_directory_wordlist> (otherwise, terminator will use default list))

(stage 2-privilege escalation after gaining shell on target machine):
- python3 terminator.py priv -u <new_root_username> -p <new_root_passwd> 

(stage 3-persistence/data exfiltration after gaining root privileges on target machine):
- python3 terminator.py root -u <new_user_name> -p <new_user_passwd> -l <local_ip> -x <local_listening_port>
(optional: -f (bypass root permissions check))

(stage 4-create report on local machine):
- python3 terminator.py report -o <output_file_name>

# details
stage 1 - enumeration
- initial nmap scan to find open ports on host
- secondary nmap scan to identify services running on open ports
- if http in use, run nikto, gobuster, curl robots.txt, and searchsploit for service version exploits
- if smb in use, run enum4linux and nmap scripts to scan smb shares and users
- if ftp in use, run nmap scripts to determine if ftp allows 'anonymous' logon
- if nfs in use, run nmap scripts to identify service status and mounted shares

stage 2 - privilege escalation
- attempt to disable history logging of current session and create current backups of log files
- attempt running sudo-l to find commands user can run as sudo, then run the command if it does not require user interaction; if it does, then print to screen
- find files with suid bitset and if the binary exists in terminator's dictionary, execute the code; if it needs user interaction, print to screen
- run strings on suid files to find commands that do not specify command's full path, then create binary file in /tmp, echo '/bin/bash -p' to file, add /tmp to $PATH, execute binary
- check if /etc/passwd or /etc/shadow are world-writable; if either one is, create password from user input and append new root user to the file; su user for root

stage 3 - persistence and data exfiltration (ensure ssh is active on local machine)
- check for root permissions and suggest -f to bypass root check
- if root permissions is true, create password from user input, add new root user to /etc/passwd, /etc/shadow files and add to root group
- create shell script at /dev/shm/.data/data_log containing netcat reverse shell at ip:port from user input
- create cronjob in /etc/crontab to execute the shell script every 5 minutes

- write id,whoami,netstat and /etc/passwd,/etc/shadow,/etc/hosts,/etc/crontab,/etc/exports, and suid files to single file and scp the file to local machine using ip from user input to local 'root' user; *scp will prompt for local user's root password on local machine*
- cover tracks by clearing log files and history, restoring log files to the copies made during stage 2, deleting all files created by terminator, and deleting terminator.py itself

stage 4 - report writing
- add contents from enum.txt (enumeration data), priv.txt (privilege escalation vector used to gain root privileges), and data_exfil.txt (peristence and target machine data) to .txt and .docx files with headings; use -o to specify desired file name

# TO DO
- create vm to help people learn how to use the terminator
- add web enumeration function that scans web page images for hidden stego files & searches for usernames/passwords in source code

# credit and license
Copyright (c) 2023 suffs811

https://github.com/suffs811

This project is licensed under the MIT License - see the LICENSE file for details.

directory-list.txt comes from SecLists' common.txt list of directory names. it can be found here: https://github.com/suffs811/SecLists/blob/master/Discovery/Web-Content/common.txt

*terminator has been tested on kali linux 2022.4 (local machine) and ubuntu unity 22.10 / Ubuntu 20.04.6 / Ubuntu 18.04.6 (target machine)*

-+- Leave a comment if you have any questions! -+-
