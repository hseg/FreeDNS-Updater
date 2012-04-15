"""
 Redistributed with minor modifications by Menachem D. Mostowicz
 Source URL: http://www.dangibbs.co.uk/journal/freedns-python-ip-updater-for-linux

 Instructions: Set update_key to the sha1 hash at the end of the direct update
               url given by freedns. The script will update the freedns entry
               with the current external IP of the computer.
 Quick Linux DNS IP Updater Python script for FreeDNS (freedns.afraid.org)

 Author: Daniel Gibbs
 Version: 0.2
 URL: http://www.danielgibbs.net/

 ** Must set update_key and make sure that ip_file is read and writable

 This program is free software; you can redistribute it and/or modify it under
 the terms of the GNU General Public License as published by the Free Software
 Foundation; either version 2 of the License, or (at your option) any later
 version.

 This program is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 """
import sys
import os
import time
import stat
from urllib import urlopen

# FreeDNS Update Key
update_key = "UPDATE_KEY_HASH"

# FreeDNS Update URL
update_url = "http://freedns.afraid.org/dynamic/update.php?" + update_key

# External IP URL (must return an IP in plain text)
ip_url = "http://www.danielgibbs.net/ip.php"

# Open URL to return the external IP
external_ip = urlopen(ip_url).read()

# The file where the last known external IP is written
ip_file = ".freedns_ip"

# Create the file if it doesnt exist otherwise update old IP
if not os.path.exists(ip_file):
	fh = open(ip_file, "w")
	fh.write(external_ip)
	fh.close()
	last_external_ip = "Unknown"
	print("Created FreeDNS IP log file: " + ip_file)
else:
	fh = open(ip_file, "r")
	last_external_ip = fh.read()
	last_external_ip = last_external_ip.rstrip('\n')

# Check old IP against current IP and update if necessary
if last_external_ip != external_ip:
	urlopen(update_url)
	print("External IP updated FROM (" + last_external_ip + ") TO (" + external_ip + ")")
	fh = open(ip_file, "w")
	fh.write(external_ip)
	fh.close()
else:
	last_ip_update = time.ctime(os.stat(ip_file).st_mtime)
	print("External IP (" + external_ip + ") has not changed. Last update was " + last_ip_update)

