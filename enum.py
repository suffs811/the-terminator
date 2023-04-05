#!/usr/bin/python3
# author: suffs811
# github: https://github.com/cysec11/scripts.git
# purpose: automate enumeration using nmap, nikto, dirbuster, enum4linux, and others.
#
# usage: python3 enum.py -w /home/kali/directory.txt 10.0.0.1

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


# get pwd
pwd = os.getcwd()


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

	print("\n### services found: {}".format(services.strip()))

	return ports,services


def web(ip,wordlist,services):
	print("\n### initiating web enumeration... ###")
	web_port = []
	for value in services:
		if "http" in value or "web" in value:
			web_port.append(services[value.key()])
		else:
			continue

	print("\n### running nikto... ###")
	os.system("nikto -h {} -o nikto.txt nmap".format(ip))
	print("\n### running gobuster... ###")
	os.system("gobuster dir -u {} -w {} | tee dir_walk.txt".format(ip,wordlist))
	for port in web_port:
		print("\n### curling robots.txt for {}:{}... ###".format(ip,port))
		os.system("curl http://{}:{}/robots.txt | tee robots.txt".format(ip,port.strip()))

	print("\n### web enum output saved to nikto.txt, dir_walk.txt, and robots.txt ###")


def smb(ip):
	print("\n### initiating smb enumeration... ###")
	os.system("enum4linux -A {} | tee smb_enum.txt".format(ip))
	os.system("nmap -vv -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse {} -oN smb_nmap.txt".format(ip))
	print("\n### smb enum output saved to smb_nmap.txt ###")


def ftp(ip):
	print("\n### initiating ftp enumeration... ###")
	os.system("nmap -vv -p 21 --script=ftp-anon {} -oN ftp_nmap.txt".format(ip))
	print("\n### ftp enum output saved to ftp_nmap.txt ###")


def nfs(ip):
	print("\n### initiating nfs enumeration... ###")
	os.system("nmap -vv -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount {} -oN nfs_nmap.txt".format(ip))
	print("\n### nfs enum output saved to nfs_nmap.txt ###")


# call functions
init_scan(ip)

if "80" in ports or "8080" in ports or "http" in services.values():
	web(ip,wordlist)
	continue
elif "139" in ports or "445" in ports or "smb" in services.values() or "samba" in services.values():
	smb(ip)
	continue
elif "21" in ports or "ftp" in services.values():
	ftp(ip)
	continue
elif "111" in ports or "nfs" in services.values():
	nfs(ip)
else:
	print("\n### scan complete... continue with manual enumeration ###")

