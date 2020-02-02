#!/usr/bin/env python3

import argparse
import csv
import logging
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import json

import coloredlogs
import geoip2.database
import geoip2.errors
from fake_useragent import UserAgent
from scapy.all import DNS, DNSQR, UDP, RandShort, traceroute

log = logging.getLogger(__name__)
coloredlogs.install(level="INFO", fmt="%(message)s")


def dns_lookup(target: str, truncate_length: int = None) -> str:
    """
    Perform a reverse DNS lookup on a host IP address.
    :param target: target IP address
    :param truncate_length: truncate the address to this many characters,
        if desired (for output purposes)
    :return: DNS address of provided IP address
    """

    try:
        dns_host = socket.gethostbyaddr(target)[0]
    except socket.error as e:
        log.debug(f"Unable to perform reverse DNS lookup for {target}: {e}")
        return ""

    if truncate_length:
        dns_host = (
            (dns_host[:truncate_length] + "...")
            if len(dns_host) > truncate_length
            else dns_host
        )

    return dns_host


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

    reader = geoip2.database.Reader("geolite_databases/GeoLite2-City.mmdb")
    location = {}
    try:
        geolookup = reader.city(target)
    except geoip2.errors.AddressNotFoundError:
        log.debug(f"Unable to get geolocation data for {target}.")
        return

    if geolookup.city.name:
        location["city"] = geolookup.city.name

    if geolookup.country.name:
        location["country"] = geolookup.country.name

    return location


def dns_traceroute(url: str, hops: int) -> None:
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


def http_traceroute(url: str, hops: int) -> None:
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


def tls_traceroute(url: str, hops: int) -> None:
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


def icmp_traceroute(url: str, hops: int) -> None:
    """
    Call the native traceroute for ICMP
    :param url: target url
    :param hops: max number of hops to travel
    :return: None
    """

    call_native_traceroute("ICMP", url, hops)


def tcp_traceroute(url: str, hops: int) -> None:
    """
    Call the native traceroute for TCP
    :param url: target url
    :param hops: max number of hops to travel
    :return: None
    """
    call_native_traceroute("TCP", url, hops)


def udp_traceroute(url: str, hops: int) -> None:
    """
    Call the native traceroute for UDP
    :param url: target url
    :param hops: max number of hops to travel
    :return: None
    """
    call_native_traceroute("UDP", url, hops)


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


def lft_traceroute(url: str, hops: int) -> None:
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


def write_results(filename: str, results: list) -> None:
    """
    Write results out to a CSV file.
    :param filename: full filepath to write results to
    :param results: list of results, each entry being a list consisting of 
        [ url, hop, data received]
    :return: None
    """

    os.makedirs(os.path.dirname(filename), exist_ok=True)
    formatted_results = []
    with open(filename, "w") as outfile:
        for result in results:
            formatted_results.append(
                {"url": result[0], "ttl": result[1], "message": result[2]}
            )
        log.info(f"Writing results to {filename}...")
        log.debug(f"\n{json.dumps(formatted_results, indent=4)}")
        json.dump(formatted_results, outfile)


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
        traceroute_func(target, args.max_ttl)
