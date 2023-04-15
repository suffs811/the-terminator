#!/usr/bin/python3
# author: suffs811
# https://github.com/suffs811/the-terminator.git
# purpose: script for creating report from terminator findings
#
# usage: python3 report.py -o <output_file_name>


import os
import argparse


parser = argparse.ArgumentParser(description="script for making a report from pentest scripts\npython3 report.py -o <output_file_name>")
parser.add_argument("-o", "--output", help="specify name for report")
args = parser.parse_args()
output = args.output


# create file and write contents to it
def create(ip,output):
   os.system("touch /terminator/report.txt")
   os.system("echo '-+- Penetration Testing Report for {} -+-' >> /terminator/report.txt".format(ip))
   os.system("echo '' >> /terminator/report.txt")
   os.system("echo '+ + + Stage 1 - Enumeration + + +' >> /terminator/report.txt")
   os.system("echo '' >> /terminator/report.txt")
   os.system("cat /terminator/enum.txt >> /terminator/report.txt")
   os.system("echo '' >> /terminator/report.txt")
   os.system("echo '+ + + Stage 2 - Exploitation / Initial Shell + + +' >> /terminator/report.txt")
   os.system("echo '' >> /terminator/report.txt")
   os.system(" echo ' *** ADD YOUR EXPLOITION METHOD FOR THE INITAL SHELL HERE ***' >> /terminator/report.txt")
   os.system("echo '' >> /terminator/report.txt")
   os.system("echo '+ + + Stage 3 - Privilege Escalation + + +' >> /terminator/report.txt")
   os.system("echo '' >> /terminator/report.txt")
   os.system("cat /terminator/priv.txt >> /terminator/report.txt")
   os.system("echo '' >> /terminator/report.txt")
   os.system("echo '+ + + Stage 4 - Persistence and Data Exfiltration + + +' >> /terminator/report.txt")
   os.system("cat /terminator/data_exfil.txt >> /terminator/report.txt")
   os.system("echo '' >> /terminator/report.txt")
   os.system("echo '' >> /terminator/report.txt")
   os.system("echo '--- END OF REPORT ---' >> /terminator/report.txt")
   os.system("mv /terminator/report.txt /terminator/{}".format(output))
   print("### penetration test report for {} is ready at /terminator/{} ###\nplease add your method for gaining the initial shell in the '+ + + Stage 2 - Exploitation / Initial Shell + + +' section.\nall reference data for enumeration, privilege escalation, and persistence/data exfiltration are located in /terminator/ as enum.txt, priv.txt, and data_exfil.txt, respectively.".format(ip,output))
   print("\n\n-+- {} has been terminated -+-".format(ip))

create(ip,output)
