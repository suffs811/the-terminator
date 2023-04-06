#!/usr/bin/python3
# author: suffs811
# https://github.com/cysec11/scripts.git
# purpose: automate common enumeration techniques 
# using nmap, nikto, dirbuster, and enum4linux.
#
# usage: python3 enum.py -w <path_to_directory_list> <target_ip>


import os
import argparse
import time
import re


parser = argparse.ArgumentParser(description="script for automating common enumeration techniques\nusage: python3 enum.py 10.0.0.1")
parser.add_argument("ip", help="ip or domain to enumerate")
parser.add_argument("-w", "--wordlist", help="specify wordlist for directory walking (gobuster)", required="True")
args = parser.parse_args()
ip = args.ip
wordlist = args.wordlist


# get pwd and make enum directory
pwd = os.getcwd()
os.system("mkdir enum")

# run initial nmap scan
def init_scan(ip,pwd):
	
	print("\n### finding open ports... ###")
	os.system("nmap -vv -sS -n -Pn -T5 -p- {} -oN scan_1".format(ip))
	ports = []
	services = {}

	# get ports for next scan
	with open("{}/scan_1".format(pwd)) as scan_1:
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
	port_scan = ",".join()
	os.system("nmap -vv -A -p {} {} -oN scan_2".format(port_scan,ip))

	# get services for open ports
	with open("{}/scan_2".format(pwd)) as scan_2:
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

	tot = ports+services

	print("\n### services found: {}".format(services.strip()))

	return ports,services,tot


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
	os.system("gobuster dir -u {} -w {} | tee enum/dir_walk.txt".format(ip,wordlist))
	for port in web_port:
		print("\n### curling robots.txt for {}:{}... ###".format(ip,port))
		os.system("curl http://{}:{}/robots.txt | tee enum/robots.txt".format(ip,port.strip()))
	print("\n### looking for webserver version in searchsploit... ###")
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


# call functions
init_scan(ip)

for item in tot:
	if item == "80" or item == "8080" or item == "http":
		web(ip,wordlist)
		continue
	elif item == "139" or item == "445" or item == "smb" or item == "samba":
		smb(ip)
		continue
	elif or item == "21" or item == "ftp":
		ftp(ip)
		continue
	elif or item == "111" or item == "nfs":
		nfs(ip)
	else:
		print("\n### scan complete... continue with manual enumeration ###")

