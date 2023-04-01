#!/usr/bin/env python3
# author: cysec11
# license: MIT license

# notes on using python libraries to find system info

import os
import subprocess
import platform
import socket
#import wmi #windows only

# ------- os - used for single commands, more simple, no control of stdout 
os.system("ls -la")
os.system("pwd")
print(os.uname())

# ------- subprocess - more control of stdin/stdout 
list_files = subprocess.run(["ls", "-l"], stdout=subprocess.DEVNULL)
subprocess.run(["ls", "-a", "-l", "-h"])
subprocess.run(["echo", "hello world"])
print("The exit code was: %d" % list_files.returncode)
cat_cmd = subprocess.run(["cat"], stdout=subprocess.PIPE, text=True, input="Hello world")
print(cat_cmd.stdout)

# ------- subprocess.Popen - run a command and contnue to do other work while its being executed
list_dir = subprocess.Popen(["ls", "-l"])
list_dir.wait()
list_dir.poll()

cat_again = subprocess.Popen(["cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
output, errors = cat_again.communicate(input="Hello world") #.communicate to manage input/output
cat_again.wait()
print(output)
print(errors)

# ------- platform - for both unix/windows . use wmi module only for windows
my_system = platform.uname()

print(f"system: {my_system.system}")
print(f"node name: {my_system.node}")
print(f"release: {my_system.release}")
print(f"version: {my_system.version}")
print(f"machine: {my_system.machine}")
print(f"processor: {my_system.processor}")

'''
# ------- wmi - for windows only
c = wmi.WMI()   
my_system = c.Win32_ComputerSystem()[0]
 
print(f"Manufacturer: {my_system.Manufacturer}")
print(f"Model: {my_system. Model}")
print(f"Name: {my_system.Name}")
print(f"NumberOfProcessors: {my_system.NumberOfProcessors}")
print(f"SystemType: {my_system.SystemType}")
print(f"SystemFamily: {my_system.SystemFamily}")
'''

# ------- socket >> for python reverse shell
