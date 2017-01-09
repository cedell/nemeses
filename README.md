# nemeses
Python script to detect/log blacklisted hosts on a network, as well as unknown devices.

This package includes two configuration files.
  blacklist.conf
  whitelist.conf
  
The blacklist should include the paired values of specific MAC addresses, along with your preferred name for the devices. For example, a child's device which you want to log activity for.
 
The whitelist will include all network devices you know of. With this populated, nemeses will then write log entries for all devices that are unknown to you.
