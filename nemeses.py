import datetime
import time
import io
import subprocess
import re
active_violators = {}
active_strangers = {}
blacklist_dict = {}
whitelist_dict = {}
network_prefix = '192'


def update_configs():
    global blacklist_dict
    global whitelist_dict
    blacklist_dict = update_config_dict('blacklist.conf', blacklist_dict)
    whitelist_dict = update_config_dict('whitelist.conf', whitelist_dict)


def update_config_dict(conf_file, global_list):
    with open(conf_file, 'r') as file:
        latest_dict = {}
        for line in file:
            # Skip comments
            if line[:1] == "#":
                continue
            # Regex to collapse tabs, strip newline, and then split by tabs
            line_values = re.sub('\t\t+', '\t', line).rstrip('\n').split('\t')
            latest_dict[line_values[0]] = line_values[1]

        # Update the actively used black/whitelist if file shows new values
        if latest_dict != global_list:
            send_to_log('{} updated to: {}'.format(conf_file.split('.')[0].capitalize(), latest_dict))

        return latest_dict


def find_violators():
    violators_found = blacklist_scanner()
    scan_time = time.time()

    # Add any new online host to dictionary.
    for host in violators_found:
        if host not in active_violators.keys():
            h_name = violators_found[host]['name']
            h_ip = str(violators_found[host]['ip'])
            active_violators[host] = {'name': h_name, 'ip': h_ip, 'start_time': scan_time}

            # print('Found {} with an IP of {}.'.format(h_name, h_ip))
            send_to_log('{} ({}) is now online'.format(h_name, h_ip))

    # Now verify what hosts have gone offline.
    hosts_to_remove = []
    for host in active_violators.keys():
        if host not in violators_found:
            diff_in_seconds = scan_time - active_violators[host]['start_time']
            active_time_calc = str(datetime.timedelta(seconds=int(diff_in_seconds)))
            h_name = active_violators[host]['name']
            h_ip = str(active_violators[host]['ip'])

            send_to_log('{} ({}) went offline or removed from blacklist. Active for {}'.format(h_name, h_ip, active_time_calc))
            hosts_to_remove.append(host)

    for host in hosts_to_remove:
        # print("Removing all offline hosts.")
        del active_violators[host]


def blacklist_scanner():
    # Check blacklisted MACs against all online hosts
    violators = {}
    system_command = 'sudo arp-scan --retry=10 --localnet'
    p = subprocess.Popen(system_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    for line in io.TextIOWrapper(p.stdout, encoding="utf-8"):

        for mac, name in blacklist_dict.items():
            # If arp-scan finds a blacklisted MAC and it's not a duplicate entry
            if line.find(mac) != -1 and line.find("DUP") == -1:
                ip = str(line.split()[0])
                violators[mac] = {'name': name, 'ip': ip}
    return violators


def find_strangers():
    hosts_found = host_scanner()
    scan_time = time.time()

    # Add any new strangers to dictionary.
    for host in hosts_found:
        if host not in active_strangers.keys():
            host_name = hosts_found[host]['name']
            host_ip = str(hosts_found[host]['ip'])
            active_strangers[host] = {'name': host_name, 'ip': host_ip, 'start_time': scan_time}

            send_to_log('!!! STRANGER ONLINE !!! {} {} {}'.format(host_ip, host, host_name))

    # Now verify what strangers have gone offline.
    hosts_to_remove = []
    for host in active_strangers.keys():
        if host not in hosts_found:
            diff_in_seconds = scan_time - active_strangers[host]['start_time']
            active_time_calc = str(datetime.timedelta(seconds=int(diff_in_seconds)))
            h_name = active_strangers[host]['name']
            h_ip = str(active_strangers[host]['ip'])

            send_to_log('!!! STRANGER OFFLINE !!! {} {} {}. Active for {}'.format(h_ip, host, h_name, active_time_calc))
            hosts_to_remove.append(host)

    for host in hosts_to_remove:
        del active_strangers[host]


def host_scanner():
    # Collect information for all online hosts
    online_hosts = {}
    system_command = 'sudo arp-scan --verbose --retry=10 --localnet'
    p = subprocess.Popen(system_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    for line in io.TextIOWrapper(p.stdout, encoding="utf-8"):

        if len(line) > 1 and line[:3] == network_prefix and line.find("DUP") == -1:
                ip = str(line.split()[0])
                mac = str(line.split()[1])
                name = str(line.split()[2])
                if mac not in whitelist_dict.keys():
                    online_hosts[mac] = {'name': name, 'ip': ip}

    return online_hosts


def send_to_log(entry):
    # TODO: Implement python.logging?
    timestamp = time.strftime("%a %x %I:%M %p - ")
    log_file = "nemeses.log"
    with open(log_file, "a") as f:
        f.write('{}{}\n'.format(timestamp, entry))
        # f.close()  # with-blocks are context managed, and close files automatically


# Future functionality
# Do a nmap scan on the unknown device to gather intel when you're away
# def scan_device(ip):
#     os.system("sudo nmap -A " + ip)


# Future functionality
# Perform a DOS on the intruding device
# def attack_device(ip):
#     os.system("sudo hping3 -S --flood --rand-source " + ip)


# Generate a summary for log file, showing each device active for the day and the total time online.
def daily_totals():
    pass


def main():
    send_to_log("--------------------- nemeses start ---------------------")
    try:
        while True:
            update_configs()
            find_violators()
            find_strangers()
            time.sleep(30)  # Wait for 1 minute
    except KeyboardInterrupt:
        print("\nUser aborted.")
    finally:
        send_to_log("--------------------- nemeses ended ---------------------")


if __name__ == '__main__':
    main()
