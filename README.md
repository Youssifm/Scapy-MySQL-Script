# Scapy-MySQL-Script

This script uses the Scapy Python API to sniff probe requests, then uploads parts of the probe request data to a SQL server. Specifically, this script parses the MAC Address, Signal dB of the probe request, a DATETIME timestamp, and the Host ID of the device the script runs on. The script is split into four threads. The main thread the three "worker" threads that do the	heavy lifting. The Scapy worker thread sniffs for probe request and passes the parsed probe request data to the data handler. The data handler	puts the data into a dictionary (aka hash table) to hold the data for	the specified WINDOW_TIME. This decreases the amount of traffic to the SQL server. Holding the data also enables us to account for duplicates within the specified WINDOW_TIME. After the specified WINDOW_TIME the	data is passed to the SQL thread to be uploaded to the SQL database.

This script must be ran as root due to the script enabling/disabling the specified interface, and more importantly, due to Scapy requiring root access to run.

The Scapy portion of this script has been modified from http://nikharris.com/tracking-people/
