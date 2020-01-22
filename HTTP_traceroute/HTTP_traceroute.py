import sys
import socket
import csv
import os
import errno
import re

# HTTP header
req = "GET / HTTP/1.1\r\nHost: ojaloberoi.in\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/58.0.3029.110 Chrome/58.0.3029.110 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\n\r\n"

with open('ru.csv', mode='r') as csv_file:
    csv_reader = csv.DictReader(csv_file)
    line_count = 0
    for row in csv_reader:
        print row["URL"]
        print "line_count:", line_count
        line_count += 1
        url = (row["URL"], 80)
        my_list = []
        for x in range(1, int(sys.argv[1])):
            print "TTL:" ,x
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
            c.settimeout(10)
	    try: 
    		host_ip = socket.gethostbyname(row["URL"]) 
	    except socket.gaierror:
	        print "url is not correct"
		break
            try:
                c.connect(url)
            except socket.error, msg:
                print "Couldnt connect with the socket-server: %s\n moving on" % msg
                break

            c.setsockopt(socket.SOL_IP, socket.IP_TTL, x)
            try:
                c.send(req)
                my_list.append([row["URL"],x,str(c.recv(4096))])
                c.close()
            except socket.timeout as e:
                my_list.append([row["URL"],x,e])
                c.close()

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
            results_writer.writerow(['URL', 'TTL', 'Message'])
            for item in my_list:
                results_writer.writerow(item)


