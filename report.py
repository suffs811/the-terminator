#!/usr/bin/python3
# author: suffs811
# https://github.com/cysec11/scripts.git
# purpose: automate common enumeration techniques 
# using nmap, nikto, dirbuster, and enum4linux.
#
# usage: python3 report.py -w <path_to_directory_list> <target_ip>


import os
import argparse
import time
import re


parser = argparse.ArgumentParser(description="script for making a report from pentest scripts\nusage: python3 report.py 10.0.0.1")
parser.add_argument("ip", help="ip or domain to enumerate")
parser.add_argument("-w", "--wordlist", help="specify wordlist for directory walking (gobuster)", required="True")
args = parser.parse_args()
ip = args.ip
wordlist = args.wordlist

scans = input("\n### Have you run enum/data_exfil/priv/pers.py scripts? (y/n): ")

'''
-enum

-data_exfil

-priv

-pers

'''



if scans:
	# call functions
	pass
else:
	print("\n*** run enum/data_exfil/priv/pers.py scripts before running this report script... ***")
