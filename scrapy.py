#!/usr/bin/env python3

import argparse
import csv
import logging
import os
import socket
import sys

import coloredlogs
import geoip2.database
from scapy.all import ICMP, IP, TCP, UDP, sr

log = logging.getLogger(__name__)
coloredlogs.install(level="INFO")


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


def get_rtt(sent_time: str, received_time: str) -> str:
    """
    Compute the total RTT for a packet.
    :param sent_time: timestamp of packet that was sent
    :param received_time: timestamp of packet that was received
    :return: total RTT in milliseconds
    """

    return round((received_time - sent_time) * 1000, 3)


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


def get_location(target: str) -> str:
    """
    Get the geolocation of a target IP address, using the Maxmind database.
    https://www.maxmind.com/en/home
    :param target: target IP address
    :return: string containing the {city}, {country}, if found
    """

    reader = geoip2.database.Reader("geolite_databases/GeoLite2-City.mmdb")
    try:
        geolookup = reader.city(target)
    except:
        log.debug(f"Unable to get geolocation data for {target}.")
        return

    if geolookup.city.name:
        return f"{geolookup.city.name}, {geolookup.country.name}"

    return geolookup.country.name


def traceroute(target: str, packet_type, max_ttl: int = 30, timeout: int = 5) -> list:
    """
    Perform a traceroute against a given target.
    :param target: target hostname
    :param packet_type: type (TCP, UDP, ICMP, etc.)
    :param max_ttl: maximum desired TTL
    :param timeout: timeout for each packet sent
    :return: list containing a tuple for every packet sent and its response
    """

    results = []
    log.info(f"Performing traceroute against {target}")
    log.debug(f"Max TTL is {max_ttl}, timeout is {timeout}.")

    ans, unans = sr(
        IP(dst=target, ttl=(1, max_ttl)) / packet_type, timeout=timeout, verbose=0
    )
    for packet in ans:
        packet_sent = packet[0]
        packet_received = packet[1]

        dns_host = dns_lookup(packet_received.src, truncate_length=37) or ""
        geolocation = get_location(packet_received.src) or ""
        rtt = get_rtt(packet_sent.sent_time, packet_received.time)

        print(
            f"{packet_sent.ttl:<5} {dns_host:<40} {packet_received.src:<20} {geolocation:<30} {rtt}ms"
        )

    return results


if __name__ == "__main__":

    # parse all program arguments
    parser = argparse.ArgumentParser("Perform a traceroute against a given target(s).")

    # either allow an input file, or a target address. not both
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("-c", "--csv", type=str, help="Input CSV file.")
    target_group.add_argument("-t", "--target", type=str, help="Target destination.")

    scan_type_group = parser.add_mutually_exclusive_group()
    scan_type_group.add_argument(
        "--udp", action="store_true", default=False, help="Perform a UDP traceroute."
    )
    scan_type_group.add_argument(
        "--tcp", action="store_true", default=False, help="Perform a TCP traceroute."
    )
    scan_type_group.add_argument(
        "--http", action="store_true", default=False, help="Perform an HTTP traceroute."
    )
    scan_type_group.add_argument(
        "--icmp", action="store_true", default=False, help="Perform an ICMP traceroute."
    )

    parser.add_argument("--ttl", type=int, default=30, help="Max TTL.")
    parser.add_argument(
        "--timeout", type=int, default=5, help="Default timeout per packet."
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
        coloredlogs.install(level="DEBUG")

    # require a scan type
    if not (args.tcp or args.udp or args.http or args.icmp):
        scan_type = "UDP"

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

    # dont know what to do with this for now
    packet_type = UDP(dport=33434)

    if args.tcp:
        packet_type = TCP(dport=53, flags="S")

    for target in targets:
        traceroute(target, packet_type, args.ttl, args.timeout)
    # filter = "(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12)) or (tcp and (tcp[13] & 0x16 > 0x10))"
