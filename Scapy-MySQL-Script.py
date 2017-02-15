# --------------------------------------------------------------------------------------------- #
#                                                                                               #
#   University of North Texas                                                                   #
#   Department of Electrical Engineering                                                        #
#                                                                                               #
#   Professor:  Dr. Xinrong Li                                                                  #
#   Name:       Youssif Mahjoub                                                                 #
#                                                                                               #
#   Date:       02/06/2017                                                                      #
#                                                                                               #
#   Title:      Probe request counter using scapy with SQL integration                          #
#   Version:    1.0                                                                             #
#                                                                                               #
#   Description:                                                                                #
#												#														#
#       This script uses the Scapy python API to sniff probe requests then			#
#	uploads the probe request to a SQL server. The script is split into			#
#	four threads. The main thread the three "worker" threads that do the			#
#	heavy lifting. The Scapy worker thread sniffs for probe request and			#
#	passes the probe requests to the data handler. The data handler				#
#	puts the data into a dictionary (aka hash table) to hold the data for			#
#	the specified WINDOW_TIME. This decreases the amount of traffic to the			#
#	SQL server. Holding the data also enables us to account for duplicates			#
#	within the specified WINDOW_TIME. After the specified WINDOW_TIME the			#
#	is passes to the SQL thread to be uploaded to the SQL database.				#
#                                                                                               #
#   Notes:                                                                                      #
#                                                                                               #
#   Issues:                                                                                     #
#                                                                                               #
#   Change Log:  										#
#		                                                                                #
#       v1.0 (02/06/2017)                                                                       #
#			1. First iteration		                                        #
#												#												#
# --------------------------------------------------------------------------------------------- #

import datetime
import MySQLdb
import netaddr
import os
import Queue
import socket
import sys
import threading
import time

from scapy.all import *

WINDOW_TIME 	= 60*5
INTERFACE   	= 'wlan1'

class ScapyScan:

    s_close = False
    hostname = ''

    # Initialization function
    def __init__(self):
	self.hostname = socket.gethostname()
        return

    def build_packet_callback(self, data_queue):
        def packet_callback(packet):
	    if not packet.haslayer(Dot11):
		return

	    # we are looking for management frames with a probe subtype
	    # if neither match we are done here
	    if packet.type != 0 or packet.subtype != 0x04:
		return

	    # list of output fields
	    fields = []

	    # append the mac address itself
	    fields.append(packet.addr2)

	    rssi_val = -(256-ord(packet.notdecoded[-4:-3]))
	    fields.append(str(rssi_val))

	    fields.append(time.strftime('%Y-%m-%d %H:%M:%S'))
	    fields.append(self.hostname)

            data_queue.put(fields)
    	return packet_callback


    def run(self, data_queue):

	os.system('ifconfig {} down'.format(INTERFACE))
    	os.system('iwconfig {} mode monitor'.format(INTERFACE))
    	os.system('ifconfig {} up'.format(INTERFACE))

	sniff(iface=INTERFACE, prn=self.build_packet_callback(data_queue), store=0)

        return

class Data_Handler():

    dh_quit = False

    # Initialization function
    def __init__(self):
        return

    def run(self, kismet_queue, sql_queue):

        d = dict()                                                      # Create dictionary (a.k.a Open hash-table (separate chaining))

        while not self.dh_quit:                                         # Loop while we want to process data

            time_window = time.time() + WINDOW_TIME                     # 60*x min timeout
            d.clear()                                                   # Clear the dictionary for the next sql_queue put
            mac_array = []                                              # Clear the mac_array for the next sql_queue put

            while True:                                                 # nested while loop that runs for the timeout mins specified above.

                q_data = kismet_queue.get()                             # Get data from the queue. The data is 1 client. (mac, signal_dbm, conn_type, date, time, host_name)
                mac_key = q_data[0]                          		# Split the mac address so we can use the mac address as a index address for the dictionary

                d[mac_key] = q_data                                 	# Set the mac index address value equal to the queue data which contains the rest of the information on that client

                if(time.time() >= time_window):                         # if it has been X mins put the the mac_array on the SQL queue

                    for item in d:                                      # Lopp through each item in the dictionary. each item is 1 clients data.
                        split = d[item]                      		# Split the data for each client so we can append the data to the mac_array as a tuple.
                        mac_array.append((split[0], split[1], split[2], split[3]))      # append it.
			 
                    break                                               # Break out of the nested while loop. This will allow the main while loop to put the data to the sql_queue
            sql_queue.put(mac_array)                                    # Add the mac_array to the sql_queue

        return

class SQL_Database():

    db = MySQLdb
    cursor = MySQLdb
    db_close = False

    # Initialization function
    def __init__(self, db_host, db_port, db_user, db_passwd, db_database, db_table):
        self.db_host = db_host
        self.db_port = db_port
        self.db_user = db_user
        self.db_passwd = db_passwd
        self.db_database = db_database
	self.db_table = db_table
        return

    # Connects to the SQL DB specified in the initialization.
    # if the connection fails print out the error message.
    def db_connect(self):
        try:
            # Open database connection
            self.db = MySQLdb.connect(host = self.db_host, port = self.db_port, user = self.db_user, passwd = self.db_passwd, db = self.db_database)

            self.cursor = self.db.cursor()                       # Prepare a cursor object using cursor() method
            self.cursor.execute("SELECT VERSION()")              # Execute SQL query using execute() method.
            db_version = self.cursor.fetchone()[0]               # Fetch a single row using fetchone() method as a tuple.


            status = '---- Connected to SQL DB ----\n\tHost: {}\n\tPort: {}\n\tDatabase: {}\n\tDatabase version : {}\n\t'.format(self.db_host, self.db_port, self.db_database, db_version)
        except:
            status = "ERROR - SQL DB: connection to SQLDB failed.\n\t"
            for index, msg in enumerate(sys.exc_info()):
                status += "SYS ERROR {}: {}\n\t".format(index, msg)

        print status

    # Insert a new entry into the SQL DB
    # If the insert fails and exception is thrown
    def db_insert(self, data_array):
        try:
            status = ''
            stmt = """INSERT INTO {} (mac, signal_dbm, date_time, node_id) VALUES (%s, %s, %s, %s)""".format(self.db_table)
            self.cursor.executemany(stmt, data_array)
            self.db.commit()                    # Commit your changes in the database

            status += "MAC Count: {} - Date: {} - Time {}".format(str(len(data_array)).zfill(5), time.strftime("%Y-%m-%d"), time.strftime("%H:%M"))
        except:
            # Rollback in case there is any error
            status = "ERROR - SQL DB: insert failed.\n\t"
            for index, msg in enumerate(sys.exc_info()):
                status += "SYS ERROR {}: {}\n\t".format(index, msg)
            self.db.rollback()

        print status

    def db_clear(self):
        try:
            stmt = """TRUNCATE TABLE {}""".format(self.db_table)
            self.cursor.execute(stmt)
            status = "SQL DB: {} table cleared.".format(self.db_table)
        except:
            # Rollback in case there is any error
            status = "ERROR - SQL DB: table clear failed.\n\t"
            for index, msg in enumerate(sys.exc_info()):
                status += "SYS ERROR {}: {}\n\t".format(index, msg)
            self.db.rollback()
        print status

    # This function returns the entire database as an array.
    # Each array element contains 1 entry from the database.
    # Currently this function is only being used for debugging purposes (3-5-16)
    def db_read(self):
        try:
            # Execute the SQL command
            self.cursor.execute("""SELECT * FROM {}""".format(self.db_table))
            db_data = self.cursor.fetchall()
        except:
            db_data = "Something went wrong"

        return db_data

    def run(self, data_queue):

        self.db_connect()
        threading._sleep(1)

        while not self.db_close:
            if not data_queue.empty():
                mac_data = data_queue.get()
                self.db_insert(mac_data)

        self.db.close()
        print 'SQL DB: CLOSED'

if __name__ == '__main__':

	scapy_queue     = Queue.Queue()
	sql_queue       = Queue.Queue()

	workerThreads   = []

	db_host         = 'SQL-Server'
	db_port         = 3306
	db_user         = 'user'
	db_passwd       = 'passwd'
	db_database     = 'SQL-db'
	db_table	= 'SQL-db-table'

	scapy_scanner   = ScapyScan()
	data_handler    = Data_Handler()
	sql             = SQL_Database(db_host, db_port, db_user, db_passwd, db_database, db_table)

	t_scapy_scanner = threading.Thread(name="Sacpy_Scanner", target=scapy_scanner.run, args=(scapy_queue,))
	t_data_handler  = threading.Thread(name="Data_Handler", target=data_handler.run, args=(scapy_queue, sql_queue,))
	t_sql           = threading.Thread(name="SQL_DB", target=sql.run, args=(sql_queue,))

	workerThreads.append(t_scapy_scanner)
	workerThreads.append(t_data_handler)
	workerThreads.append(t_sql)

	for t in workerThreads:
	    t.start()
	    print "THREAD: {} thread started.".format(t.name)
