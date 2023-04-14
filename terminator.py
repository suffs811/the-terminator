#!/usr/bin/python3
# author: suffs811
# https://github.com/suffs811/the-terminator.git
# purpose: automate enumeration, privilege escalation, persistence, exfiltration, and reporting stages of a pentest
#
# usage: python3 terminator.py enum -t <target_ip_to_enumerate> (optional: -w <path_to_directory_wordlist> (otherwise, terminator will use default list))
# usage: python3 terminator.py exploit -u <user's_username> -p <user's_passwd> -l <local_ip> -x <local_listening_port> (optional: -f (avoid root permissions check))
# usage: python3 terminator.py report -o <output_file_name>

'''
TO DO:
add local directory list file to github
add scripts to terminator
test
'''

import os
import argparse
import time
import re


parser = argparse.ArgumentParser(description="script for automating common enumeration techniques\nusage: python3 enum.py 10.0.0.1")
parser.add_argument("level", help="use terminator to enumerate target machine from local machine", required="True")
parser.add_argument("-t", "--targetip", help="specify target ip to enumerate")
parser.add_argument("-w", "--wordlist", help="specify wordlist for directory walking (gobuster)")
parser.add_argument("-u", "--username", help="specify targeted user's username")
parser.add_argument("-p", "--password", help="specify targeted user's password if known")
parser.add_argument("-l", "--localip", help="specify your (local) ip for data exfiltration and backdoor callback")
parser.add_argument("-x", "--localport", help="specify your (local) port for backdoor callback")
parser.add_argument("-f", "--force", help="force bypass of root permissions check (optional)", required=False, action="store_true")
parser.add_argument("-o", "--output", help="specify name for report")
args = parser.parse_args()
level = args.level
ip = args.targetip
wordlist = args.wordlist
username = args.username
password = args.password
local_ip = args.localip
local_port = args.localport
output = args.output


print('''
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
''')


# enumeration ###############################

# get pwd and make enum directory
pwd = os.getcwd()
os.system("mkdir enum/")

# run initial nmap scan
def init_scan(ip,pwd):
   
   ports = []
   services = {}
   # run initial port scan
   print("\n### finding open ports... ###")
   os.system("nmap -vv -sS -n -Pn -T5 -p- {} -oN enum/scan_1".format(ip))

   # get ports for next scan
   with open("{}/enum/scan_1".format(pwd)) as scan_1:
      lines_1 = scan_1.readlines()
      for line in lines_1:
         number = re.search("\A[1-9][0-9]",line)
         if number:
            line_split = line.split(" ")
            first_word = line_split[0]
            ports.append(first_word[:-4].strip())
            continue
         else:
            continue


   print("\n### open ports: {}".format(ports))
   time.sleep(3)
   print("\n### finding services for ports... ###")
   port_scan = ",".join(ports)
   os.system("nmap -vv -A -p {} {} -oN enum/scan_2".format(port_scan,ip))

   # get services for open ports
   with open("{}/enum/scan_2".format(pwd)) as scan_2:
      lines_2 = scan_2.readlines()
      for line in lines_2:
         number = re.search("\A[1-9][0-9]",line)
         if number:
            line_split = line.split(" ")
            third_word = line_split[2]
            fifth_word = line_split[4]
            services.update({"third_word":"fifth_word"})
            continue
         else:
            continue

   tot = []
   for port in ports:
      tot.append(port)
   for service in services:
      tot.append(service)

   print("\n### services found: {}".format(services.strip()))

   return ports,services,tot


# enumerate web service with nikto, gobuster, curl, and searchsploit
def web(ip,wordlist,services):
   print("\n### initiating web enumeration... ###")
   web_port = []
   for value in services:
      if "http" in value or "web" in value:
         web_port.append(services[value.key()])
      else:
         continue

   print("\n### running nikto... ###")
   os.system("nikto -h {} -o enum/nikto.txt".format(ip))
   print("\n### running gobuster... ###")
   if wordlist:
      os.system("gobuster dir -u {} -w {} | tee enum/dir_walk.txt".format(ip,wordlist))
   else:
      os.system("gobuster dir -u {} -w directory-list.txt | tee enum/dir_walk.txt".format(ip))
   for port in web_port:
      print("\n### curling robots.txt for {}:{}... ###".format(ip,port))
      os.system("curl http://{}:{}/robots.txt | tee enum/robots.txt".format(ip,port.strip()))
   print("\n### looking for webserver vulnerabilities in searchsploit... ###")
   os.system("searchsploit {} | tee enum/searchsploit.txt".format(services["http"]))

   print("\n### web enum output saved to nikto.txt, dir_walk.txt, robots.txt, and searchsploit.txt in enum/ ###")


# use enum4linux and nmap to enumerate smb shares/users
def smb(ip):
   print("\n### initiating smb enumeration... ###")
   os.system("enum4linux -A {} | tee enum/smb_enum.txt".format(ip))
   os.system("nmap -vv -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse {} -oN enum/smb_nmap.txt".format(ip))
   print("\n### smb enum output saved to enum/smb_nmap.txt ###")


# use nmap to try ftp anonymous login
def ftp(ip):
   print("\n### initiating ftp enumeration... ###")
   os.system("nmap -vv -p 21 --script=ftp-anon {} -oN enum/ftp_nmap.txt".format(ip))
   print("\n### ftp enum output saved to enum/ftp_nmap.txt ###")


# use nmap to show NFS mounts
def nfs(ip):
   print("\n### initiating nfs enumeration... ###")
   os.system("nmap -vv -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount {} -oN enum/nfs_nmap.txt".format(ip))
   print("\n### nfs enum output saved to enum/nfs_nmap.txt ###")

# privilege escalation ###############################

# persistence ###############################

# data exfiltration ###############################

# report ###############################



# call functions
if level == "enum":
   # call enumeration functions
   init_scan(ip)
   for item in tot:
      if item == "80" or item == "8080" or item == "http":
         web(ip,wordlist)
         continue
      elif item == "139" or item == "445" or item == "smb" or item == "samba":
         smb(ip)
         continue
      elif item == "21" or item == "ftp":
         ftp(ip)
         continue
      elif item == "111" or item == "nfs":
         nfs(ip)
      else:
         print("\n### scan complete... view enum/ and continue with manual enumeration ###")
elif level == "exploit":
   # call exploit functions
   pass
elif level == "report":
   # call report functions
   pass
else:
   print("\n*** specify either 'enum', 'exploit', or 'report' ***")

