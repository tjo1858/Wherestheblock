import sys
import socket
import csv
import urllib
import time
import datetime, threading
from bs4 import BeautifulSoup
import subprocess

with open('BlockUrls.csv', mode='r') as csv_file:
    csv_reader = csv.DictReader(csv_file)
    line_count = 0
    for row in csv_reader:
        print row["URL"]
        print "line_count:", line_count
        line_count += 1
        traceroute = subprocess.Popen(["traceroute", '-U', '-m', sys.argv[1],row["URL"]], stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT)

	    myCmd = os.popen("curl -s https://ipvigilante.com/$(curl -s https://ipinfo.io/ip) | jq ' .data.country_name'").read()
	    myCmd=myCmd.replace('"', '')
	    myCmd=myCmd.replace('\n', '')
	    print(myCmd)
        filename = "output/"+myCmd+'/'+row["URL"] + ".csv"
	    print(filename)
	    if not os.path.exists(os.path.dirname(filename)):
	        try:
	            os.makedirs(os.path.dirname(filename),0777)
	        except OSError as exc: # Guard against race condition
	            if exc.errno != errno.EEXIST:
	                raise
	    os.system("sudo chmod -R 777 output/*")        
        with open(filename, mode='w') as results:
            results_writer = csv.writer(results, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            results_writer.writerow(['URL','TTL','Response_Message'])
            TTL = 0
            for line in iter(traceroute.stdout.readline, ""):
                results_writer.writerow([row["URL"],TTL,line])
                TTL += 1
