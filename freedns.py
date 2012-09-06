#!/usr/bin/python
from urllib.request import urlopen
import argparse, configparser # For configurations
import os                     # For checking file existence
import re, urllib.error       # For getting the IP from html
import syslog                 # For logging

def log_info(msg):
    syslog.syslog(syslog.LOG_INFO, msg)

def log_error(msg):
    syslog.syslog(syslog.LOG_ERR, msg)

def get_ip(check_urls, fail_rate):
    if len(check_urls) == 0:
        msg = "Error: There must be at least one IP checking URL\n between the\
        config file and the command line arguments - none found"
        log_error(msg)
        raise EnvironmentError(msg)

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
                msg = "The result from the IP URL {} is ambiguous."
                    .format(ip_url)
                log_error(msg)
                raise ValueError(msg)
            ret[ips[0]] = ret.get(ips[0], {}) | {ip_url}
        except urllib.error.URLError as e:
            if isinstance(e.reason, socket.timeout):
                ret['fail'] = ret.get('fail', {}) | {ip_url}
            else:
                raise

    if 'fail' in ret:
        if len(ret['fail']) > len(check_urls)*fail_rate:
            msg = "Error: The fail rate is above the acceptable rate"
            log_error(msg)
            raise RuntimeError(msg)
        del ret['fail']
    if len(ret.keys()) != 1:
        msg = "Error: There is no consensus as to the public IP\n\
        Possible public IP addresses are: {}"
        .format('\n'.join(external_ip.keys()))
        log_error(msg)
        raise RuntimeError(msg)
    return set(ret.keys()).pop()

def update_ip(ip, ip_file, update_urls):
    if len(update_urls) == 0:
        msg = "Error: There must be at least one dynamic DNS update URL\n\
        between the config file and the command line arguments - none found"
        log_error(msg)
        raise EnvironmentError(msg)

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
# Overwrite defaults with configuration file
    def make_ini(path):
    # configparser.ConfigParser expects a header in the configuration file,
    # but we want shell-like configuration files.
    # So, to keep ConfigParser happy, we add a header to our configs on the fly
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
    parser.add_argument('--noconfig', action='store_true',
            help='Disable loading configuration from config file')
    parser.set_defaults(update_urls = None, check_urls = None, ip_file = None,
                        fail_rate = None, config = "/etc/freedns.conf")
    cmdline = vars(parser.parse_args())

    if cmdline['noconfig']:
        args = get_config('/dev/null')
    else:
        if not os.path.exists(cmdline['config']):
            raise EnvironmentError(cmdline['config'] + " does not exist")
        args = get_config(cmdline['config'])

    for opt in ['update_urls', 'check_urls']:
        args[opt] = args[opt] | set(cmdline[opt])
        cmdline[opt] = None
        if len(args[opt]) == 0:
            msg = "Error: There must be at least one {}\n between the\
            config file and the command line arguments - none found"
            .format(' '.join(opt[:-1].split('_')))
            log_error(msg)
            raise EnvironmentError(msg)

    args.update({key:val for key,val in cmdline.items() if val is not None})
    update_ip(get_ip(args['check_urls'], args['fail_rate']),
            args['ip_file'], args['update_urls'])
