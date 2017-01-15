#!/usr/bin/env python3
import datetime
import time
import re
import sys
from scapy.all import srp
from scapy.all import Ether, ARP, conf
# import io
# import subprocess

active_violators = {}
active_strangers = {}
blacklist_dict = {}
whitelist_dict = {}
log_file = 'nemeses.log'
ip_range = '192.168.1.0/24'
scan_retries = 5
scan_timeout = 6
wait_loop = 90


def update_configs():
    """Initiates functions which gather host details from configuration files."""
    global blacklist_dict
    global whitelist_dict
    blacklist_dict = update_config_dict('blacklist.conf', blacklist_dict)
    whitelist_dict = update_config_dict('whitelist.conf', whitelist_dict)


def update_config_dict(conf_file, global_list):
    """Opens specified host file and returns values found."""
    with open(conf_file, 'r') as file:
        latest_dict = {}
        for line in file:
            # Skip lines with comment hash
            if line[:1] == '#':
                continue
            # Regex to collapse tabs, strip newline, and then split by tabs.
            line_values = re.sub('\t\t+', '\t', line).rstrip('\n').split('\t')
            latest_dict[line_values[0]] = line_values[1]

        # Update the actively used black/whitelist if file shows new values.
        if latest_dict != global_list:
            send_to_log('{} updated to: {}'.format(conf_file.split('.')[0].capitalize(), latest_dict))

        return latest_dict


def find_blacklisters():
    """Initiates and determines if blacklisted hosts are active."""
    violators_found = blacklist_scanner()
    scan_time = time.time()

    # Add any new online host to dictionary.
    for host in violators_found:
        if host not in active_violators.keys():
            h_name = violators_found[host]['name']
            h_ip = str(violators_found[host]['ip'])
            active_violators[host] = {'name': h_name, 'ip': h_ip, 'start_time': scan_time}

            send_to_log('{} ({}) is now online'.format(h_name, h_ip))

    # Now verify what hosts have gone offline.
    hosts_to_remove = []
    for host in active_violators.keys():
        if host not in violators_found:
            diff_in_seconds = scan_time - active_violators[host]['start_time']
            active_time_calc = str(datetime.timedelta(seconds=int(diff_in_seconds)))
            h_name = active_violators[host]['name']
            h_ip = str(active_violators[host]['ip'])

            msg = '{} ({}) is offline or removed from blacklist. Active for {}'.format(h_name, h_ip, active_time_calc)
            send_to_log(msg)
            hosts_to_remove.append(host)

    for host in hosts_to_remove:
        del active_violators[host]

# Replaced with scapy version of function
# def blacklist_scanner_arpscan():
#     """Scans network for blacklisted MACs and returns those active hosts."""
#     violators = {}
#     system_command = 'sudo arp-scan --retry=10 --localnet'
#     p = subprocess.Popen(system_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
#
#     for line in io.TextIOWrapper(p.stdout, encoding="utf-8"):
#         for mac, name in blacklist_dict.items():
#             # If arp-scan finds a blacklisted MAC and it's not a duplicate entry.
#             if line.find(mac) != -1 and line.find("DUP") == -1:
#                 ip = str(line.split()[0])
#                 violators[mac] = {'name': name, 'ip': ip}
#     return violators


def blacklist_scanner():
    """With scapy, scans and returns blacklisted hosts active on network."""
    violators = {}
    collection = []
    try:
        ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip_range), retry=scan_retries, timeout=scan_timeout)
    except PermissionError:
        print('Please run with elevated permissions.')
        sys.exit(1)

    for snd, rcv in ans:
        result = rcv.sprintf(r'%ARP.psrc% %Ether.src%').split()
        collection.append(result)

    for mac, name in blacklist_dict.items():
        for host in collection:
            if host[1] == mac:
                ip = host[0]
                violators[mac] = {'name': name, 'ip': ip}
    return violators


def find_strangers():
    """Initiates and determines if unknown hosts are active on network."""
    strangers_found = host_scanner()
    scan_time = time.time()

    # Add any new strangers to dictionary.
    for host in strangers_found:
        if host not in active_strangers.keys():
            host_name = strangers_found[host]['name']
            host_ip = str(strangers_found[host]['ip'])
            active_strangers[host] = {'name': host_name, 'ip': host_ip, 'start_time': scan_time}

            send_to_log('STRANGER ONLINE!!! {} {} {}'.format(host_ip, host, host_name))

    # Log and remove strangers if now offline.
    hosts_to_remove = []
    for host in active_strangers.keys():
        if host not in strangers_found:
            diff_in_seconds = scan_time - active_strangers[host]['start_time']
            active_time_calc = str(datetime.timedelta(seconds=int(diff_in_seconds)))
            h_name = active_strangers[host]['name']
            h_ip = str(active_strangers[host]['ip'])

            msg = 'STRANGER OFFLINE!!! {} {} {}. Active for {}'.format(h_ip, host, h_name, active_time_calc)
            send_to_log(msg)
            hosts_to_remove.append(host)

    for host in hosts_to_remove:
        del active_strangers[host]


# Replaced with scapy version of function
# def host_scanner_arpscan():
#     """Collect information for all online hosts."""
#     online_hosts = {}
#     system_command = 'sudo arp-scan --verbose --retry=10 --localnet'
#     p = subprocess.Popen(system_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
#
#     for line in io.TextIOWrapper(p.stdout, encoding="utf-8"):
#
#         if len(line) > 1 and line.split()[0].count('.') == 3 and line.find("DUP") == -1:
#             ip, mac, name, *_ = tuple(line.split())
#
#             if mac not in whitelist_dict.keys():
#                 online_hosts[mac] = {'name': name, 'ip': ip}
#
#     return online_hosts


def host_scanner():
    """With scapy, return all online hosts."""
    online_strangers = {}
    collection = []
    try:
        ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip_range), retry=scan_retries, timeout=scan_timeout)
    except PermissionError:
        print('Please run with elevated permissions.')
        sys.exit(1)

    for snd, rcv in ans:
        result = rcv.sprintf(r'%ARP.psrc% %Ether.src%').split()
        collection.append(result)

    for host in collection:
        ip, mac = tuple(host)
        if mac not in whitelist_dict.keys():
            # UNKNOWN is a remnant of returned arp-scan values, left in for future enhancements
            online_strangers[mac] = {'name': 'UNKNOWN', 'ip': ip}

    return online_strangers


def send_to_log(msg):
    """Writes message to log file."""
    timestamp = time.strftime('%a %x %I:%M %p - ')
    with open(log_file, 'a') as f:
        f.write('{}{}\n'.format(timestamp, msg))


# TODO: Generate daily summary in log, showing each device's total time online.
def daily_totals():
    pass


# Future functionality
# Do a nmap scan on the unknown device to gather intel when you're away
# def nmap_scan_host(ip):
#     system_command = 'sudo nmap -A {}'.format(ip)
#     p = subprocess.Popen(system_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


# Future functionality
# Perform a DoS on the intruding device
# def attack_device(ip):
#     system_command = 'sudo hping3 -S --flood --rand-source {}'.format(ip)
#     p = subprocess.Popen(system_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def main():
    send_to_log('--------------------- nemeses start ---------------------')
    try:
        while True:
            update_configs()
            find_blacklisters()
            find_strangers()
            daily_totals()
            time.sleep(wait_loop)
    except KeyboardInterrupt:
        print('\nUser aborted.')
    finally:
        daily_totals()
        send_to_log('--------------------- nemeses ended ---------------------')


if __name__ == '__main__':
    main()
