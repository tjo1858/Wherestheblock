#!/usr/bin/env python3

import argparse
import csv
import json
import logging
import os
import pathlib
import socket
import ssl
import subprocess
import sys

import coloredlogs
import geoip2.database
import geoip2.errors
from datetime import datetime
from fake_useragent import UserAgent
from scapy.all import DNS, DNSQR, DNSRR, ICMP, IP, UDP, RandShort, sr1, traceroute

log = logging.getLogger(__name__)
coloredlogs.install(level="INFO", fmt="%(message)s")

asn_reader = geoip2.database.Reader(
    os.path.join("geolite_databases", "GeoLite2-ASN.mmdb")
)

city_reader = geoip2.database.Reader(
    os.path.join("geolite_databases", "GeoLite2-City.mmdb")
)


def dns_lookup(ip_address: str) -> str:
    """
    Perform a reverse DNS lookup on a host IP address.
    :param ip_Address: target IP address
    :return: DNS address of provided IP address
    """

    addr = ".".join(ip_address.split(".")[::-1])
    answer = sr1(
        IP(dst="8.8.8.8")
        / UDP(dport=53)
        / DNS(rd=1, qd=DNSQR(qname=f"{addr}.in-addr.arpa", qtype="PTR")),
        verbose=0,
    )
    if answer[DNS].ancount > 0:
        return answer[DNSRR][0].rdata.decode()


def ip_lookup(hostname: str) -> str:
    """
    Lookup an IP address for a given hostname.
    :param hostname: host to look up
    :return: IP address string
    """

    try:
        host_ip = socket.gethostbyname(hostname)
    except socket.error:
        log.error(f"Unable to obtain IP address for {hostname}.")
        return
    return host_ip


def geolocate(target: str) -> str:
    """
    Get the geolocation of a target IP address, using the Maxmind database.
    https://www.maxmind.com/en/home
    :param target: target IP address
    :return: string containing the {city}, {country}, if found
    """

    location = ""
    try:
        geolookup = city_reader.city(target)
    except geoip2.errors.AddressNotFoundError:
        log.debug(f"Unable to get geolocation data for {target}.")
        return location

    if geolookup.country.name:
        location += f"{geolookup.country.name}"

    if geolookup.city.name:
        location += f", {geolookup.city.name}"

    return location


def asn_lookup(target: str):
    """
    Lookup an IP addresses ASN organization and system number.
    :param target: input IP address
    :return: string containing {system number}:{organization}
    """
    try:
        geolookup = asn_reader.asn(target)
    except geoip2.errors.AddressNotFoundError:
        log.debug(f"Unable to get ASN data for {target}.")
        return ""

    return (
        str(geolookup.autonomous_system_number)
        + ":"
        + geolookup.autonomous_system_organization
    )


def get_rtt(sent_time: str, received_time: str) -> str:
    """
    Compute the total RTT for a packet.
    :param sent_time: timestamp of packet that was sent
    :param received_time: timestamp of packet that was received
    :return: total RTT in milliseconds
    """

    return round((received_time - sent_time) * 1000, 3)


def dns_traceroute(url: str, hops: int, timeout: int) -> None:
    """
    Perform a DNS traceroute (needs work)
    :param url: target url
    :param hops: max number of hops to travel
    :return: None
    """
    ans, unans = traceroute(
        "4.2.2.1", l4=UDP(sport=RandShort()) / DNS(qd=DNSQR(qname=url))
    )
    print(ans.summary())
    print(unans.summary())


def http_traceroute(url: str, hops: int, timeout: int) -> None:
    """
    Perform an HTTP get request traceroute.
    :param url: target url
    :param hops: max number of hops to travel
    :return: None
    """

    # HTTP header
    user_agent = UserAgent().random
    req = b"GET / HTTP/1.1\r\n"
    req += b"Host: ojaloberoi.in\r\n"
    req += b"Connection: keep-alive\r\n"
    req += b"Cache-Control: max-age=0\r\n"
    req += b"Upgrade-Insecure-Requests: 1\r\n"
    req += user_agent.encode() + b"\r\n"
    req += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
    req += b"Accept-Language: en-US,en;q=0.8\r\n"
    req += b"\r\n"

    results = []
    for ttl in range(1, hops + 1):
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        c.settimeout(10)
        host_ip = ip_lookup(url)
        if not host_ip:
            return

        try:
            c.connect((url, 80))
        except socket.error as e:
            log.error(f"Couldnt connect with the socket-server: {e}")
            return

        c.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        try:
            c.send(req)
            results.append([url, ttl, str(c.recv(4096))])

        except socket.error as e:
            results.append([url, ttl, e])

        finally:
            c.close()

    country = geolocate(host_ip)["country"]

    filename = os.path.join(
        pathlib.Path().absolute(), "output", "http", country, f"{url}.json"
    )
    write_results(filename, results)


def tls_traceroute(url: str, hops: int, timeout: int) -> None:
    """
    Perform a TLS handshake traceroute.
    :param url: target url
    :param hops: max number of hops to travel
    :return: None
    """

    results = []
    for ttl in range(1, hops + 1):
        host_ip = ip_lookup(url)
        if not host_ip:
            return

        sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
        sock.settimeout(5)
        # create tls context and wrap the socket
        context = ssl.create_default_context()
        ssock = context.wrap_socket(
            sock, server_hostname=url, do_handshake_on_connect=True
        )
        ssock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        try:
            ssock.connect((host_ip, 443))
            # if we can connect, write the cert (?)
            cert = ssock.getpeercert()
            results.append([url, ttl, cert])

        except socket.error as e:
            log.error(f"Couldnt connect with the socket-server: {e}")
            ssock.close()

        finally:
            ssock.close()

    country = geolocate(host_ip)["country"]

    filename = os.path.join(
        pathlib.Path().absolute(), "output", "tls", country, f"{url}.json"
    )
    write_results(filename, results)


def icmp_traceroute(url: str, hops: int, timeout: int, output: dict) -> None:
    """
    :param url: target url
    :param hops: max number of hops to travel
    :param timeout: packet timeout in seconds
    :return: None
    """
    # tcp: TCP(dport=53,flags="S"))
    # udp: UDP() / DNS(qd=DNSQR(qname="test.com"))

    print(
        f"\033[1m{'TTL': <5} {'IP' : <25} {'DNS' :<40} {'GEOLOCATION' : <40} {'ASN': <20} RTT\033[0m"
    )

    traceroute_dict = dict()
    traceroute_dict["hops"] = []
    traceroute_dict["max_ttl"] = timeout
    traceroute_dict["time"] = str(datetime.now())

    for hop in range(1, hops):

        pkt = IP(dst=url, ttl=hop) / ICMP()
        reply = sr1(pkt, verbose=0, timeout=timeout)

        if reply is None:
            log.info(f"{hop:<5} *")

        else:
            traceroute_dict["hops"].append(format_hop(reply, hop, pkt))

            if reply.type == 3:
                break

    log.info("Traceroute complete.")

    output["protocol"]["icmp"].append(traceroute_dict)

    filename = os.path.join(
        pathlib.Path().absolute(), "new_output", f"{url}.json"
    )
    write_results(filename, output)

def format_hop(reply, hop, pkt) -> dict:
    """
    Format traceroute reply results into json
    :param reply: scapy reply packet
    :param hop: hop number
    :param pkt: original packet sent out
    :return: hop results dictionary
    """
    hop_dict = dict()
    hop_dict["ttl"] = hop
    dns = dns_lookup(reply.src) or ""
    hop_dict["dns"] = dns
    location = geolocate(reply.src)
    hop_dict["location"] = location
    asn = asn_lookup(reply.src)
    hop_dict["asn"] = asn
    rtt = get_rtt(pkt.sent_time, reply.time)
    hop_dict["rtt"] = rtt

    if reply.type == 3:
        log.info(
            f"{hop:<5} {reply.src} {dns:<40} {location:<40} {asn:<20} {rtt}ms ✓"
        )
    else:
        log.info(
            f"{hop:<5} {reply.src:<25} {dns:<40} {location:<40} {asn:<20} {rtt}ms"
        )

    return hop_dict

def udp_traceroute(url: str, hops: int, timeout: int, output: dict) -> None:
    """
    Call the native traceroute for UDP
    :param url: target url
    :param hops: max number of hops to travel
    :return: None
    """
    print(
        f"\033[1m{'TTL': <5} {'IP' : <25} {'DNS' :<40} {'GEOLOCATION' : <40} {'ASN': <20} RTT\033[0m"
    )

    traceroute_dict = dict()
    traceroute_dict["hops"] = []
    traceroute_dict["max_ttl"] = timeout
    traceroute_dict["time"] = str(datetime.now())

    for hop in range(1, hops):

        pkt = IP(dst=target, ttl=hop) / UDP()
        reply = sr1(pkt, verbose=0, timeout=timeout)

        if reply is None:
            log.info(f"{hop:<5} *")

        else:
            traceroute_dict["hops"].append(format_hop(reply, hop, pkt))

            if reply.type == 3:
                break


    output["protocol"]["udp"].append(traceroute_dict)
    #host_ip = ip_lookup(url)
    #country = geolocate(host_ip)["country"]

    filename = os.path.join(
        pathlib.Path().absolute(), "new_output", f"{url}.json"
    )
    write_results(filename, output)
    log.info("Traceroute complete.")


def tcp_traceroute(url: str, hops: int, timeout: int) -> None:
    """
    Call the native traceroute for TCP
    :param url: target url
    :param hops: max number of hops to travel
    :return: None
    """
    call_native_traceroute("TCP", url, hops)


def call_native_traceroute(protocol: str, url: str, hops: int) -> None:
    """
    Wrapper to call the native traceroute utility.
    :param protocol: desired protocol choice (udp, http, etc.)
    :param url: target url
    :param hops: max number of hops to travel
    :return: None
    """
    traceroute = subprocess.run(
        ["traceroute", "-P", protocol, "-m", str(hops), url], capture_output=True,
    )
    results = []
    for hop, line in enumerate(traceroute.stdout.decode().split("\n")):
        results.append([url, hop, line])

    ip = ip_lookup(url)
    country = geolocate(ip)["country"]
    filename = os.path.join(
        pathlib.Path().absolute(), "output", protocol, country, f"{url}.json"
    )
    write_results(filename, results)


def lft_traceroute(url: str, hops: int, timeout: int) -> None:
    """
    Perform an lft traceroute.
    :param url: target URL
    :param hops: max number of hops to travel
    :return: None
    """
    traceroute = subprocess.Popen(
        ["lft", "-m", hops, url], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    results = []
    for hop, line in enumerate(traceroute.stdout.decode().split("\n")):
        results.append([url, hop, line])

    ip = ip_lookup(url)
    country = geolocate(ip)["country"]
    filename = os.path.join(
        pathlib.Path().absolute(), "output", "lft", country, f"{url}.json"
    )
    write_results(filename, results)


def write_results(filename: str, results: dict) -> None:
    """
    Write results out to a JSON file.
    :param filename: full filepath to write results to
    :param results: list of results, each entry being a list consisting of
        [ url, hop, data received]
    :return: None
    """

    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w") as outfile:
        log.info(f"Writing results to {filename}...")
        log.debug(f"\n{json.dumps(results, indent=4)}")
        json.dump(results, outfile)


def read_csv_input_file(filepath: str) -> list:
    """
    Read a CSV input file of targets.
    :param filepath: input filepath
    :return: list of targets
    """

    log.debug(f"Attempting to read input file '{filepath}'...")

    if not os.path.exists(filepath):
        log.error(f"Input file '{filepath}' does not exist.")
        return

    with open(filepath, "r") as csv_file:
        try:
            csv_reader = csv.DictReader(csv_file)
        except OSError:
            log.error(f"'{filepath}' is not a valid CSV file.")
            return

        targets = []
        for row in csv_reader:
            try:
                targets.append(row["URL"])
            except KeyError as e:
                log.error(f"Invalid CSV format: unable to grab key: {e}.")
                return

    log.debug(f"'{filepath}' contained the following targets: {targets}")
    return targets


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Perform a traceroute against a given target(s).")

    # either allow an input file, or a target address. not both
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("-c", "--csv", type=str, help="Input CSV file.")
    target_group.add_argument("-t", "--target", type=str, help="Target destination.")

    parser.add_argument(
        "-P",
        "--protocol",
        default="udp",
        type=str,
        choices=["udp", "tcp", "icmp", "lft", "http", "dns", "tls"],
        help="protocol choice (default: %(default)s)",
    )
    parser.add_argument(
        "-m",
        "--max_ttl",
        default=64,
        type=int,
        help="Set the max time-to-live (max number of hops) used in outgoing probe packets.",
    )
    parser.add_argument(
        "-T",
        "--timeout",
        default=5,
        type=int,
        help="Set the time (in seconds) to wait for a response to a probe (default 5 sec.).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose logging.",
    )
    args = parser.parse_args()

    # set log level to debug if verbose flag is passed
    if args.verbose:
        coloredlogs.install(
            level="DEBUG", fmt="%(asctime)s - %(levelname)s - %(message)s"
        )

    # requires either a CSV input file or a target address
    if not args.csv and not args.target:
        log.error("You must provide either a target or an input file. Exiting...")
        parser.print_help()
        sys.exit(1)

    targets = []

    if args.csv:
        targets = read_csv_input_file(args.csv)
        if not targets:
            sys.exit(1)

    elif args.target:
        targets.append(args.target)

    # context switcher to choose function based on provided protocol
    switcher = {
        "icmp": icmp_traceroute,
        "udp": udp_traceroute,
        "tcp": tcp_traceroute,
        "http": http_traceroute,
        "dns": dns_traceroute,
        "lft": lft_traceroute,
        "tls": tls_traceroute,
    }
    traceroute_func = switcher.get(args.protocol, lambda: "Invalid protocol.")

    for target in targets:
        filename = os.path.join(
            pathlib.Path().absolute(), "new_output", f"{target}.json"
        )

        if not os.path.exists(filename):
            output = dict()
            output["url"] = target
            output["protocol"] = dict()
            output["protocol"][args.protocol] = []
        else:
            with open(filename, 'r') as f:
                output = json.load(f)
            if args.protocol not in output["protocol"]:
                output["protocol"][args.protocol] = []

        traceroute_func(target, args.max_ttl, args.timeout, output)
