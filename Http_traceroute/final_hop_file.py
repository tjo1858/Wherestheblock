import sys
import socket
import csv

# HTTP header
req = "GET / HTTP/1.1\r\nHost: ojaloberoi.in\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/58.0.3029.110 Chrome/58.0.3029.110 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\n\r\n"
with open('BlockUrls.csv', mode='r') as csv_file:
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
            c.settimeout(5)
            c.connect(url)
            c.setsockopt(socket.SOL_IP, socket.IP_TTL, x)
            try:
                c.send(req)
                my_list.append([row["URL"],x,str(c.recv(4096))])
                c.close()
            except socket.timeout as e:
                my_list.append([row["URL"],x,e])
                c.close()
        filename = row["URL"] + ".csv"
        with open(filename, mode='w') as results:
            results_writer = csv.writer(results, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            results_writer.writerow(['URL', 'TTL', 'Message'])
            for item in my_list:
                results_writer.writerow(item)


