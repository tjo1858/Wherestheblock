import sys
import socket
import time
from random import *
from scapy.all import *
from scapy.layers import http
import subprocess

def sniff_urls(packet):
    print "here"
    if packet.haslayer(http.HTTPRequest):
        http_layer = packet.getlayer(http.HTTPRequest)
        ip_layer = packet.getlayer(IP)
        print '\n{0[src]} - {1[Method]} - http://{1[Host]}{1[Path]}'.format(ip_layer.fields,http_layer.fields)



if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ipadd = s.getsockname()[0]
    p = subprocess.Popen(["iptables","-A","OUTPUT","-p","tcp","--tcp-flags","RST","RST","-s",ipadd,"-j","DROP"], stdout=subprocess.PIPE)
    output , err = p.communicate()
    print output

    port = randint(49152,65535)
    seq = randint(1000000000,1080000000)
    for i in range(1,30):
        ip=IP(dst="ostomaan.org", ttl = i)
        SYN=TCP(sport=port , flags="S", seq=seq, dport=80)
        SYNACK=sr1(ip/SYN, verbose = 20, retry = -1, timeout = 10)
        ip.show()
        try:
            SYNACK.show()


            try:
                if SYNACK[ICMP].type == 11:
                    print "hop %d, ip %s", i, SYNACK.src
                    continue
            except:
                if SYNACK[TCP].flags == "RA" or SYNACK[TCP].flags == "R":
                    print "IPBLOCKING"
                    p = subprocess.Popen(["iptables","-D","OUTPUT","-p","tcp","--tcp-flags","RST","RST","-s",ipadd,"-j","DROP"], stdout=subprocess.PIPE)
                    output , err = p.communicate()
                    print output
                    break

                my_ack = SYNACK.seq + 1
                ACK=TCP(sport=SYNACK.dport, flags="A", seq=SYNACK.ack, ack=my_ack, dport=80)
                send(ip/ACK)

                PUSH = TCP(sport=port, dport=80, flags="PA", seq=SYNACK.ack, ack=my_ack)
                payload = "GET / HTTP/1.1\r\nHost: www.ostomaan.org\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language:en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"
                res = sr1(ip/PUSH/payload)

                res.show()
                if res[TCP].flags == "RA" or res[TCP].flags == "R":
                    print "URL BLOCKING"
                    p = subprocess.Popen(["iptables","-D","OUTPUT","-p","tcp","--tcp-flags","RST","RST","-s",ipadd,"-j","DROP"], stdout=subprocess.PIPE)
                    output , err = p.communicate()
                    print output
                    break
                else:
                    print "Successful Connection"
                    p = subprocess.Popen(["iptables","-D","OUTPUT","-p","tcp","--tcp-flags","RST","RST","-s",ipadd,"-j","DROP"], stdout=subprocess.PIPE)
                    output , err = p.communicate()
                    print output
                    break

                my_ack = res.seq + 1
                ACK=TCP(sport=50138, flags="A", seq=res.ack, ack=56565, dport=80)
                send(ip/ACK)
                if i == 30:
                    p = subprocess.Popen(["iptables","-D","OUTPUT","-p","tcp","--tcp-flags","RST","RST","-s",ipadd,"-j","DROP"], stdout=subprocess.PIPE)
                    output , err = p.communicate()
                    print output
        except:
            print "IP Blocking"
            break

