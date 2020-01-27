# Ashwin instructions

2 scripts 1 results
censor-dev is a detailed script with developer comments
censor-client is the same script a little smaller for client end executions
Blocking Method is a csv doc of my findings after running the script on a afganistan local host for 100 blocked urls

# System tools required to install:
Install apt install traceroute, pip install BeautifulSoup4, pip install scapy-ssl_tls, sudo apt-get install python-scapy, apt install jq, pip install scapy-ssl_tls.

# HTTP traceroute instructions

1. Blockurl file contains the URL to be tested CSV list
2. Enter the HTTP_traceroute directory
3. Run command:
	sudo python HTTP_traceroute.py TTL

	Ex: sudo python HTTP_traceroute.py 30

4. Results of the HTTP response is stored in Block URL names CSV files.

# TCP traceroute instructions
1. Blockurl file contains the URL to be tested CSV list
2. Enter the TCP_traceroute directory
3. Run command:
	sudo python TCP_traceroute.py 30

4. Results of the TCP response is stored in Block URL names CSV files.


# ICMP traceroute instructions

1. Blockurl file contains the URL to be tested CSV list
2. Enter the ICMP_traceroute directory
3. Run command:
	sudo python ICMP_traceroute.py 30

4. Results of the ICMP response is stored in Block URL names CSV files.

# UDP traceroute instructions

1. Blockurl file contains the URL to be tested CSV list
2. Enter the UDP_traceroute directory
3. Run command:
	sudo python UDP_traceroute.py 30

4. Results of the UDP response is stored in Block URL names CSV files.

# lft traceroute instructions

1. Blockurl file contains the URL to be tested CSV list
2. Enter the lft_traceroute directory
3. Run command:
	sudo python lft_traceroute.py 10

4. Results of the lft response is stored in Block URL names CSV files.



# TLS traceroute instructions
1. Blockurl file contains the URL to be tested CSV list
2. Enter the TLS_traceroute directory
3. Run command:
	sudo python TLS_traceroute.py TTL
Like:   sudo python TLS_traceroute.py 30

4. Results of the TLS response is stored in Block URL names CSV files.

# DNS traceroute instructions
1. Blockurl file contains the URL to be tested CSV list
2. Enter the DNS_traceroute directory
3. Run command:
	sudo python DNS_traceroute.py 


# How to enter into VPS
1. Install expect linux package (sudo apt-get install expect)
2. cd VPS
3. ./countryname.sh 

 Like ./Ukraine.sh to enter Ukraine VPS


# ToDo
SSL_TLS sample packets to be craft:
https://github.com/tintinweb/scapy-ssl_tls

Examples are present in TLS traceroute folder as well.

 
