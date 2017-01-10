# nemeses
## What is nemeses?
A Python script to detect/log blacklisted hosts on a network, as well as unknown devices.
Designed to work on Linux.

This package includes two configuration files:
* blacklist.conf
* whitelist.conf
  
The blacklist should include the paired values of specific MAC addresses, along with your preferred name for the devices. For example, a child's device which you want to log activity for.
 
The whitelist will include all network devices you know of. With this populated, nemeses will then write log entries for all devices that are unknown to you.

Output of running script will be found locally in nemeses.log.

## Requirements:
[scapy] (http://www.secdev.org/projects/scapy/)

[arp-scan](http://www.nta-monitor.com/wiki/index.php/Arp-scan_User_Guide)
