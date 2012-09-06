#!/usr/bin/python
from urllib.request import urlopen
import argparse, configparser # For configurations
import os                     # For checking file existence
import re, urllib.error       # For getting the IP from html
import syslog                 # For logging

def log_info(msg):
"Log an informative message to syslog"
    syslog.syslog(syslog.LOG_INFO, msg)

def config_error(msg):
"Log an error to syslog and raise a ConfigError"
    class ConfigError(EnvironmentError):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

    syslog.syslog(syslog.LOG_ERR, msg)
    raise ConfigError(msg)

def runtime_error(msg):
"Log an error to syslog and raise a RuntimeError"
    syslog.syslog(syslog.LOG_ERR, msg)
    raise RuntimeError(msg)

def get_ip(check_urls, fail_rate):
""" Get the IP address of this machine from the URLs listed in check_urls
    Raises an error if more than fail_rate of the URLs caused trouble
"""
    if len(check_urls) == 0:
        config_error(
        "Error: At least one IP checking URL must be passed to get_ip - \
        none found")

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
    for ip_url in check_urls:
        try:
            ips = ip_regex.findall((urlopen(ip_url).read().decode('utf-8')))
            if len(ips) != 1:
                runtime_error(
                "The result from the IP URL {} is ambiguous - {} IPs\
                returned"
                    .format(ip_url, len(ips)))
            ret[ips[0]] = ret.get(ips[0], {}) | {ip_url}
        except urllib.error.URLError as e:
            if isinstance(e.reason, socket.timeout):
                ret['fail'] = ret.get('fail', {}) | {ip_url}
            else:
                raise

    if 'fail' in ret:
        if len(ret['fail']) > len(check_urls)*fail_rate:
            runtime_error("Error: The fail rate is above the acceptable rate")
        del ret['fail']
    if len(ret.keys()) != 1:
        runtime_error("Error: There is no consensus as to the public IP\n\
        Possible public IP addresses are: {}"
        .format('\n'.join(external_ip.keys())))
    return set(ret.keys()).pop()

def update_ip(ip, ip_file, update_urls):
""" Update the IP address the URLs in update_urls point to to this machine's IP
    address if the IP address passed differs from the one in ip_file - relies on
    the DDNS hosting site to find the IP address for itself
"""
    if len(update_urls) == 0:
        config_error("Error: At least one DDNS update URL must be passed to\
        update_ip - none found")

    with open(ip_file, "a+") as fh:
        fh.seek(0)
        last_ip = fh.readline()

# If we just created the IP log file, say so
    if last_ip == "":
        log_info("Created FreeDNS IP log file: {}".format(ip_file))

    if ip != last_ip:
        for url in update_urls:
            urlopen(url)

    with open(ip_file, "w") as fh:
        fh.write(ip)

    log_info("External IP updated {} to ({})".format(
        (last_ip!="") and "from ({})".format(str(last_ip)) or "", str(ip)))

def get_config(conf_path):
"Gets the configuration options from the config file at conf_path"
    def make_ini(path):
    """ configparser.ConfigParser expects a header in the configuration file,
        so in order to be able to do away with it, we supply it ourselves
    """
        yield '[DEFAULT]\n'
        with open(path) as conf:
            for line in conf:
                yield line

    parser = configparser.ConfigParser()
    parser.read_file(make_ini(conf_path), conf_path)
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
    """ Checks if the string represents a proper fraction, throwing
        an argparse.ArgumentTypeError otherwise - to satisfy the requirements
        for the type parameter of argparse.ArgumentParser.add_argument
    """
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
    parser.add_argument('--noconfig', action='store_true',
            help='Disable loading configuration from config file')
    parser.set_defaults(update_urls = None, check_urls = None, ip_file = None,
                        fail_rate = None, config = "/etc/freedns.conf")
    cmdline = vars(parser.parse_args())

    if cmdline['noconfig']:
        args = get_config('/dev/null')
    else:
        if not os.path.exists(cmdline['config']):
            config_error(cmdline['config'] + " does not exist")
        args = get_config(cmdline['config'])

    for opt in ['update_urls', 'check_urls']:
        args[opt] = args[opt] | set(cmdline[opt])
        cmdline[opt] = None
        if len(args[opt]) == 0:
            config_error("Error: There must be at least one {}\nbetween the\
            config file and the command line arguments - none found"
            .format(' '.join(opt[:-1].split('_'))))

    args.update({key:val for key,val in cmdline.items() if val is not None})
    update_ip(get_ip(args['check_urls'], args['fail_rate']),
            args['ip_file'], args['update_urls'])
