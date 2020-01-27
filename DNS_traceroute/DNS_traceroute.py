from scapy.all import *
import sys
import socket
import csv
import os
import errno
import re

with open('ru.csv', mode='r') as csv_file:
    csv_reader = csv.DictReader(csv_file)
    line_count = 0
    for row in csv_reader:
        print row["URL"]
        print "line_count:", line_count
        line_count += 1
        my_list = []
        ans, unans = traceroute("4.2.2.1", l4=UDP(sport=RandShort()) / DNS(qd=DNSQR(qname=row["URL"]))) \

        print "<======================>"
        print  ans.summary()
        print  "<======================>"
        print unans.summary()
        print "<======================>"
        ans.summary()
        print "<======================>"
        unans.summary()



