# Checking Hosts on my network to see if they are unknown. Useful when need to know when something came online and easy to identify things
# 04/18/2023

import nmap  # Host scanning
import dns.resolver  # Resolving the IPs on the network to dns name
import getmac  # Get mac of these hosts so I can whitelist known no dns hosts
from discord import Webhook, RequestsWebhookAdapter # Discord webhook

# Rotate File
import os
import shutil
import datetime


subnets = ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"]  # The subnets you want the automation for
lastList = []  # Clear this file each night. Can store them in there when found. 
ignoreList = []  # List of macs to not care about not having a DNS record.
unfoundList = []  # Holds all non found IPs
lastListFile = "lastList.txt"

webhook = Webhook.from_url("https://discord.com/api/webhooks/channel_here/webhook_here", adapter=RequestsWebhookAdapter())  # I like discord for my notifications

# Read in the ignoreMacs whitelist file
with open("ignoreMacs.txt","r") as file1:
    for line in file1:
        line = line.split("#")  # Formatted ignore list to have a comment so you can note why.
        ignoreList.append(line[0].strip()) # Split comment then strip the \n

# Read in the last log of this so we don't spam discord with new hosts
with open(lastListFile,"r") as file2:
    for line in file2:
        lastList.append(line.strip())

resolver = dns.resolver.Resolver(configure=False)  # New Python3.9 way to make DNS requests
resolver.nameservers = ['Your Local DNS Server']  # Local DNS Server Here

nm = nmap.PortScanner()  # Object of the port scanner

for subnet in subnets:  # Loop through all my subnets/vlans
    nm.scan(subnet, arguments='-sn')  # run a basic Nmap scan
    for host in nm.all_hosts():  # Loop through scan results
        try:
            response = resolver.resolve(dns.reversename.from_address(host), 'PTR')  # Does the reverse dns lookup on its own without having to give the octets backwards
            dnsName = str(response[0])[:-1]  # These are good in my book nothing to do about them
            #print(dnsName)  # Can print for debuging
        except: 
            macOfHost = getmac.get_mac_address(ip=host)  # Get the mac
            if macOfHost is not None and macOfHost not in ignoreList and macOfHost not in lastList:  # make sure the mac is not in the list of known hosts on the network.
                unfoundList.append(host) # Add host to list
                #print(f"Not found: {host}")  # Debug
                #print(f"Mac of it {getmac.get_mac_address(ip=host)}")  # Debug
                

if unfoundList != lastList and unfoundList != []:  # If there is something in the unfound DNS, and we have not already sent this(checking lastList)
    webhook.send(f"New Hosts on the network with no DNS Record: {unfoundList}")  # Send to discord
    unfoundList_with_newlines = [host + '\n' for host in unfoundList]  # Parsing unfoundList to write toa file

    with open(lastListFile, 'w') as file:
        file.writelines(unfoundList_with_newlines)  # Writes multiple lines

now = datetime.datetime.now()  # Get date time to rotate file

# check if it's midnight since I am running it every minute, not the best file rotation but cron will save me
if now.hour == 0 and now.minute == 0:
    # Create a new filename with a timestamp
    new_filename = lastListFile + '.' + now.strftime('%Y-%m-%d_%H-%M-%S')

    # Rename the file
    shutil.move(lastListFile, new_filename)

    # Create a new empty file with the original name
    open(lastListFile, "a").close()
