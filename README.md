# Scapy-MySQL-Script

This script uses the Scapy python API to sniff probe requests then uploads the probe request to a SQL server. The script is split into four threads. The main thread the three "worker" threads that do the	heavy lifting. The Scapy worker thread sniffs for probe request and passes the probe requests to the data handler. The data handler	puts the data into a dictionary (aka hash table) to hold the data for	the specified WINDOW_TIME. This decreases the amount of traffic to the SQL server. Holding the data also enables us to account for duplicates within the specified WINDOW_TIME. After the specified WINDOW_TIME the	is passes to the SQL thread to be uploaded to the SQL database.

This script must be ran as root due to the script enabling/disabling the specified interface, and more importantly, due to Scapy requiring root access to run.

The Scapy portion of this script has been modified from http://nikharris.com/tracking-people/
