#!/usr/bin/python
from urllib.request import urlopen
import argparse, configparser, socket, sys # For configurations
import os, pwd                             # For checking file ownership
import urllib.error                        # For getting the IP from html

# Set defaults
args = {"ip_file":"/var/cache/freedns-updater-git/last_ip",
        "debug":False,
        "update_urls":{},
        "check_urls":
            ["http://icanhazip.com",
             "http://ifconfig.me/ip"],
        "fail_rate":0.5}

def update_new(orig, new):
    orig.update({key:val for key,val in new.items() if val is not None})

def get_ip(ip_list):
    ret = []
    fail = 0
    for ip_url in ip_list:
        try:
            ret.append(urlopen(ip_url).read().decode('utf-8').strip())
        except urllib.error.URLError as e:
            if isinstance(e.reason, socket.timeout):
                fail += 1
            else:
                raise
    return ret, fail

def add_head(file, head):
    # configparser.ConfigParser expects a header in the configuration file,
    # but we want shell-like configuration files.
    # So, to keep ConfigParser happy, we add a header to our configs on the fly
    yield '[{}]\n'.format(head)
    for line in file:
        yield line

def list_union(first, second):
    return list(set(first) | set(second))

# Overwrite defaults with configuration file
parser = configparser.ConfigParser()
parser.read_file(add_head(open('/etc/freedns.conf'),'DEFAULT'),
                '/etc/freedns.conf')
values = dict(parser['DEFAULT'])
values['fail_rate'] = float(parser['DEFAULT']['fail_rate'])
values['check_urls'] = list_union(parser['DEFAULT']['check_urls'].split(),
                                  args['check_urls'])
update_new(args, values)

# Overwrite defaults with command line arguments
parser = argparse.ArgumentParser(
         description = "Updates the IP of a freedns domain")
parser.add_argument('--update_urls', help='The direct update url of the domain')
parser.add_argument('--ip_file',
         help='The file where the last known IP address is stored')
parser.add_argument('--fail_rate', help='The maximal acceptable failure rate',
         type=float)
parser.add_argument('-d', '--debug', action='store_true',
         help='Print debugging information')
update_new(args, vars(parser.parse_args()))

external_ip, fail = get_ip(args['check_urls'])
if args['debug']:
    print("Got IP addresses:")
    for url,ip in zip(args['check_urls'], external_ip):
        print("{} -> {}".format(url,ip))

if fail > len(args['check_urls'])*args['fail_rate']:
    print("Error: The fail rate is above the acceptable rate")
    exit(1)

if len(set(external_ip)) != 1:
    print("Error: There is no consensus as to the public IP")
    print("Answers are: {}".format(external_ip))
    exit(2)

external_ip = external_ip[0]

if args['debug']:
    print("Arguments used:")
    print("  Failure rate: {}".format(args['fail_rate']))
    print("  IP file: {}".format(args['ip_file']))
    print("  Update url: {}".format(args['update_urls']))
    print("  IP checking urls")
    for url in args['check_urls']:
        print("    -> {}".format(url))
    print("")
    print("External IP: {}".format(external_ip))

# Create the ip file if it doesn't exist otherwise update old IP
if not os.path.exists(args['ip_file']):
    fh = open(args['ip_file'], "w")
    fh.write(external_ip)
    fh.close()
    last_external_ip = None
    if args['debug']:
        print("Created FreeDNS IP log file: {}".format(args['ip_file']))
        print("External IP updated to ({})".format(str(external_ip)))
else:
    fh = open(args['ip_file'], "r")
    last_external_ip = fh.readline()

# Check that the ip file is owned by nobody:nobody
stat = os.stat(args['ip_file'])
ids = pwd.getpwnam('nobody')
if (stat.st_uid, stat.st_gid) != (ids.pw_uid, ids.pw_gid):
    print("Error: IP file {} owned by {}"
          "It must be owned by nobody"
          .format(args['ip_file'], pwd.getpwuid(stat.st_uid).pw_name))
    exit(3)

# Check old IP against current IP and update if necessary
if last_external_ip != external_ip and last_external_ip is not None:
    urlopen(args['update_urls'])
    fh = open(args['ip_file'], "w")
    fh.write(external_ip)
    fh.close()
    if args['debug']:
        print("External IP updated FROM ({}) TO ({})".format(
            str(last_external_ip), str(external_ip)))
elif last_external_ip is not None:
    if args['debug']:
        print("External IP ({}) has not changed.".format(
            str(last_external_ip)))
