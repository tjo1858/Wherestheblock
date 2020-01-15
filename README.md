# Ashwin instructions

2 scripts 1 results
censor-dev is a detailed script with developer comments
censor-client is the same script a little smaller for client end executions
Blocking Method is a csv doc of my findings after running the script on a afganistan local host for 100 blocked urls


# HTTP traceroute instructions

0. Blockurl file contains the URL to be tested CSV list
1. Enter the HTTP_traceroute directory
2. Run command:
	sudo python HTTP_traceroute.py TTL
        Ex: sudo python HTTP_traceroute.py 20

3. Results of the http response is stored in Block URL names CSV files.

# TCP traceroute instructions

0. Blockurl file contains the URL to be tested CSV list
1. Enter the TCP_traceroute directory
2. Run command:
	sudo python TCP_traceroute.py

3. Results of the http response is stored in Block URL names CSV files.


# ICMP traceroute instructions

0. Blockurl file contains the URL to be tested CSV list
1. Enter the ICMP_traceroute directory
2. Run command:
	sudo python ICMP_traceroute.py

3. Results of the http response is stored in Block URL names CSV files.

# UDP traceroute instructions

0. Blockurl file contains the URL to be tested CSV list
1. Enter the UDP_traceroute directory
2. Run command:
	sudo python UDP_traceroute.py

3. Results of the http response is stored in Block URL names CSV files.

# lft traceroute instructions

0. Blockurl file contains the URL to be tested CSV list
1. Enter the lft_traceroute directory
2. Run command:
	sudo python lft_traceroute.py

3. Results of the http response is stored in Block URL names CSV files.



# TLS traceroute instructions
1. Install "pip install scapy-ssl_tls" if not installed.
2. Blockurl file contains the URL to be tested CSV list
3. Enter the TLS_traceroute directory
2. Run command:
	sudo python TLS_traceroute.py TTL
Like:   sudo python TLS_traceroute.py 30

5. Results of the http response is stored in Block URL names CSV files.

# ToDo
SSL_TLS sample packets to be craft:
https://github.com/tintinweb/scapy-ssl_tls

Repository installed in TLS traceroute folder as well.
