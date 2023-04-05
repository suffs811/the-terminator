#!/usr/bin/python3
# author: suffs811
# github: https://github.com/cysec11/scripts.git
# purpose: automate enumeration using nmap, nikto, dirbuster, enum4linux, and others.
#
# usage: python3 enum.py 10.0.0.1

import os
import argparse
import time


parser = argparse.ArgumentParser(description="script for automating common enumeration techniques\nusage: python3 enum.py 10.0.0.1")
parser.add_argument("ip", help="ip or domain to enumerate")
args = parser.parse_args()
ip = args.ip


# get pwd
pwd = os.getcwd()


# run initial nmap scan
def init_scan(ip,pwd):
	serv_dic = {
	"ftp"ftp()
	"ssh":ssh()
	"smtp":smtp()
	"http":web()
	"smb":smb()
	}
	
	print("\n### finding open ports... ###")
	os.system("nmap -vv -sS -n -Pn -T5 -p- {} -oN scan_1".format(ip))
	ports = []
	services = []

	# get ports for next scan
	with open("{}/scan_1".format(pwd)) as scan_1:
		lines_1 = scan_1.readlines()
		for line in lines_1:
			line_split = line.split(" ")
			first_word = line_split[0]
			ports.append(first_word[:-4].strip())
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




def web():
	pass



def smb():
	pass



def ftp():
	pass


# call functions
init_scan(ip)

