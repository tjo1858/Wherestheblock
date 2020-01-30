#!/usr/bin/env python3

import argparse
import csv
import logging
import multiprocessing
import os
import pathlib
import socket
import subprocess
import sys
from itertools import repeat

import coloredlogs
import geoip2.database
from scapy.all import *

log = logging.getLogger(__name__)
coloredlogs.install(level="INFO", fmt="%(message)s")


def dns_lookup(target: str, truncate_length: int = None) -> str:
    """
    Perform a reverse DNS lookup on a host IP address.
    :param target: target IP address
    :param truncate_length: truncate the address to this many characters
    :return: DNS address of provided IP address
    """

    try:
        dns_host = socket.gethostbyaddr(target)[0]
    except:
        log.debug(f"Unable to perform reverse DNS lookup for {target}.")
        return ""

    if truncate_length:
        dns_host = (
            (dns_host[:truncate_length] + "...")
            if len(dns_host) > truncate_length
            else dns_host
        )

    return dns_host


def ip_lookup(hostname):
    return socket.gethostbyname(hostname)


def geolocate(target: str) -> str:
    """
    Get the geolocation of a target IP address, using the Maxmind database.
    https://www.maxmind.com/en/home
    :param target: target IP address
    :return: string containing the {city}, {country}, if found
    """

    reader = geoip2.database.Reader("geolite_databases/GeoLite2-City.mmdb")
    location = {}
    try:
        geolookup = reader.city(target)
    except:
        log.debug(f"Unable to get geolocation data for {target}.")
        return

    if geolookup.city.name:
        location["city"] = geolookup.city.name

    if geolookup.country.name:
        location["country"] = geolookup.country.name

    return location


def dns_traceroute(url):
    ans, unans = traceroute(
        "4.2.2.1", l4=UDP(sport=RandShort()) / DNS(qd=DNSQR(qname=row["URL"]))
    )
    print(ans.summary())
    print(unans.summary())


def http_traceroute(url):
    # HTTP header
    req = "GET / HTTP/1.1\r\nHost: ojaloberoi.in\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/58.0.3029.110 Chrome/58.0.3029.110 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\n\r\n"
    my_list = []
    for x in range(1, int(sys.argv[1])):
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        c.settimeout(10)
        try:
            host_ip = socket.gethostbyname(url)
        except socket.gaierror:
            print("url is not correct")
            break

        try:
            c.connect(url)
        except socket.error as msg:
            print(f"Couldnt connect with the socket-server: {msg}")
            break

        c.setsockopt(socket.SOL_IP, socket.IP_TTL, x)
        try:
            c.send(req)
            my_list.append([url, x, str(c.recv(4096))])

        except socket.error as e:
            my_list.append([url, x, e])

        finally:
            c.close()

        country = geolocate(host_ip)["country"]

        filename = "output/" + country + "/russia/" + url + ".csv"
        write_results(filename, my_list)


def icmp_traceroute(url, hops):
    call_native_traceroute("ICMP", url, hops)


def tcp_traceroute(url, hops):
    call_native_traceroute("TCP", url, hops)


def udp_traceroute(url, hops):
    call_native_traceroute("UDP", url, hops)


def call_native_traceroute(protocol, url, hops):
    traceroute = subprocess.run(
        ["traceroute", f"-{protocol[0].upper()}", "-m", str(hops), url],
        capture_output=True,
    )
    results = []
    for hop, line in enumerate(traceroute.stdout.decode().split("\n")):
        results.append([url, hop, line])

    ip = ip_lookup(url)
    country = geolocate(ip)["country"]
    filename = os.path.join(pathlib.Path().absolute(), "output", country, f"{url}.csv")
    write_results(filename, results)


def lft_traceroute(url, hops):
    traceroute = subprocess.Popen(
        ["lft", "-m", hops, url], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    results = iter(traceroute.stdout.readline, "")


def write_results(filename, results):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w") as outfile:
        results_writer = csv.writer(
            outfile, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL
        )
        results_writer.writerow(["URL", "TTL", "Message"])
        for result in results:
            results_writer.writerow(result)


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
        except:
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
        choices=["udp", "tcp", "icmp"],
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

    switcher = {
        "icmp": icmp_traceroute,
        "udp": udp_traceroute,
        "tcp": tcp_traceroute,
        "http": http_traceroute,
    }
    traceroute_func = switcher.get(args.protocol, lambda: "Invalid protocol.")

    for target in targets:
        traceroute_func(target, args.max_ttl)
