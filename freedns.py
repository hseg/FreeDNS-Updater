#!/usr/bin/python
from urllib.request import urlopen
import argparse, configparser, socket, sys # For configurations
import errno                               # For errors
import os, pwd                             # For checking file ownership
import re, urllib.error                    # For getting the IP from html
import syslog                              # For logging

def log_info(msg):
    syslog.syslog(syslog.LOG_INFO, msg)

def log_error(msg):
    syslog.syslog(syslog.LOG_ERR, msg)

def get_ip(ip_list, fail_rate):
    ret = {}
    begin_regex = r'(?:^|(?<=\s))' # Matches all strings at the beginning of the
                                   # string or preceded by whitespace
    end_regex = r'(?:$|(?=\s))' # Matches all strings at the end of the string
                                # or succeded by whitespace
    octet_regex = r'25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9]' # Matches all octets
                                                          # (Strings whose int
                                                          # conversion is in the
                                                          # range 0x00-0xFF)
    ip_regex = re.compile(r'{beg}(?:(?:{oct})\.){{3}}(?:{oct}){end}'
                    .format(oct = octet_regex, beg=begin_regex, end=end_regex))
    for ip_url in ip_list:
        try:
            ips = ip_regex.findall((urlopen(ip_url).read().decode('utf-8')))
            if len(ips) != 1:
                log_error("The result from the IP URL {} is ambiguous."
                    .format(ip_url))
                raise ValueError("The result from the IP URL {} is ambiguous."
                    .format(ip_url))
            ret[ips[0]] = ret.get(ips[0], []) + [ip_url]
        except urllib.error.URLError as e:
            if isinstance(e.reason, socket.timeout):
                ret['fail'] += ret.get('fail', []) + [ip_url]
            else:
                raise

    if 'fail' in ret:
        if len(ret['fail']) > len(ip_list)*fail_rate:
            log_error("Error: The fail rate is above the acceptable rate")
            raise RuntimeError(
                "Error: The fail rate is above the acceptable rate")
        del ret['fail']
    if len(ret.keys()) != 1:
        log_error("Error: There is no consensus as to the public IP\n\
        Possible public IP addresses are: {}"
        .format('\n'.join(external_ip.keys())))
        raise RuntimeError("Error: There is no consensus as to the public IP\n\
        Possible public IP addresses are: {}"
        .format('\n'.join(external_ip.keys())))
    return set(ret.keys()).pop()

def write_ip(ip, ip_file, update_urls):
    with open(ip_file, "a+") as fh:
        fh.seek(0)
        last_ip = fh.readline()

# If we just created the IP log file, say so
    if last_ip == "":
        log_info("Created FreeDNS IP log file: {}".format(ip_file))

# Check that the ip file is owned by nobody:nobody
    stat, ids = (os.stat(ip_file), pwd.getpwnam('nobody'))
    if (stat.st_uid, stat.st_gid) != (ids.pw_uid, ids.pw_gid):
        log_error("Error: IP file {} owned by {}\nIt must be owned by nobody"
            .format(ip_file, pwd.getpwuid(stat.st_uid).pw_name))
        raise OSError(errno.EACCES,
            "Error: IP file {} owned by {}\nIt must be owned by nobody"
            .format(ip_file, pwd.getpwuid(stat.st_uid).pw_name))

    if ip != last_ip:
        for url in update_urls:
            urlopen(url)

    with open(ip_file, "w") as fh:
        fh.write(ip)

    log_info("External IP updated {} to ({})".format(
        (last_ip!="") and "from ({})".format(str(last_ip)) or "", str(ip)))

def get_config(conf_path):
# Overwrite defaults with configuration file
    def add_head(file, head):
    # configparser.ConfigParser expects a header in the configuration file,
    # but we want shell-like configuration files.
    # So, to keep ConfigParser happy, we add a header to our configs on the fly
        yield '[{}]\n'.format(head)
        for line in file:
            yield line

    parser = configparser.ConfigParser()
    parser.read_file(add_head(open(conf_path),'DEFAULT'), conf_path)
    ret = {}
    ret['fail_rate'] = proper_fraction(parser.get('DEFAULT', 'fail_rate',
                                        fallback="0.5"))
    ret['check_urls'] = set(parser.get('DEFAULT', 'check_urls',
                            fallback="").split()) | {"http://icanhazip.com",
                                                    "http://ifconfig.me/ip"}
    ret['update_urls'] = set(parser.get('DEFAULT', 'update_urls',
                            fallback="").split())
    ret['ip_file'] = parser.get('DEFAULT', 'ip_file',
                            fallback="/var/cache/freedns-updater-git/last_ip")
    return ret

def proper_fraction(string):
    # Checks if the string represents a proper fraction, throwing
    # ArgumentTypeError otherwise
    value = float(string)
    if 0 <= value < 1:
        return value
    raise argparse.ArgumentTypeError(string + " is not in the range [0,1)")

if __name__ == "__main__":
# Overwrite defaults with command line arguments
    parser = argparse.ArgumentParser(
            description = "Updates the IP of freedns domains")
    parser.add_argument('--update_urls', nargs='+',
            help='The direct update urls of the domains')
    parser.add_argument('--check_urls', nargs='+',
            help="The URLs of sites that return the requester's IP address")
    parser.add_argument('--ip_file',
            help='The file where the last known IP address is stored')
    parser.add_argument('--fail_rate',
            help='The maximal acceptable failure rate (Must be in range [0,1))',
            type=proper_fraction)
    parser.add_argument('--config', help='Alternative configuration path')
    parser.set_defaults(update_urls = None, check_urls = None, ip_file = None,
                        fail_rate = None, config = "/etc/freedns.conf")
    cmdline = vars(parser.parse_args())

    if not os.path.exists(cmdline['config']):
        raise EnvironmentError(cmdline['config'] + " does not exist")

    args = get_config(cmdline['config'])
    args.update({key:val for key,val in cmdline.items() if val is not None})
    write_ip(get_ip(args['check_urls'], args['fail_rate']),
            args['ip_file'], args['update_urls'])
