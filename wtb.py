#!/usr/bin/env python3

import argparse
import json
import logging
import os
import socket
import sys
from datetime import datetime

import coloredlogs
from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, sr1

from utils.asn_lookup import asn_lookup
from utils.csv_utils import read_csv_input_file
from utils.dns_lookup import dns_lookup
from utils.geolocate import geolocate
from utils.rtt import get_rtt

log = logging.getLogger(__name__)
coloredlogs.install(level="INFO", fmt="%(message)s")


class Traceroute(dict):
    def __init__(self, target, protocol="icmp", max_ttl=30, timeout=5):
        self.target = target
        self.max_ttl = max_ttl
        self.timeout = timeout
        self.protocol = protocol
        self.hops = []
        self.time = datetime.now()

        if self.protocol == "icmp":
            self.payload = ICMP()

        elif self.protocol == "tcp":
            self.payload = TCP(dport=53, flags="S")

        elif self.protocol == "udp":
            self.payload = UDP() / DNS(qd=DNSQR(qname="test.com"))

        elif self.protocol == "http":
            self.payload = TCP(dport=80, flags="S")

    def run(self):
        log.info(
            f"\033[1m{'TTL':<5} {'IP':<20} {'DNS':40} {'GEOLOCATION':40} {'ASN':20} RTT\033[0m"
        )

        for ttl in range(1, self.max_ttl + 1):
            try:
                pkt = IP(dst=self.target, ttl=ttl) / self.payload
                reply = sr1(pkt, verbose=0, timeout=self.timeout)

            except socket.gaierror as e:
                log.error(f"Unable to resolve IP for {self.target}. Error output: {e}")
                return

            except Exception as e:
                log.exception(
                    "Non-socket exception occured:  %s", getattr(e, "__dict__", {})
                )
                return

            else:
                if reply is None:
                    log.info(f"{ttl:5} *")

                else:
                    hop = Hop(
                        source=reply.src,
                        ttl=ttl,
                        sent_time=pkt.sent_time,
                        reply_time=reply.time,
                    )
                    log.info(hop)
                    self.hops.append(vars(hop))

                    if reply.haslayer(ICMP):
                        if reply.type == 3:
                            break

                    else:
                        if self.protocol == "http":
                            getStr = "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"
                            request = (
                                IP(dst="www.google.com")
                                / TCP(
                                    dport=80,
                                    sport=reply[TCP].dport,
                                    seq=reply[TCP].ack,
                                    ack=reply[TCP].seq + 1,
                                    flags="A",
                                )
                                / getStr
                            )
                            http_reply = sr1(request, verbose=0)

        self.write_results()

    def write_results(self) -> None:
        """
        Write results out to a JSON file.
        """

        os.makedirs("output", exist_ok=True)
        filename = os.path.join("output", self.target + ".json")

        results = {
            "hops": self.hops,
            "max_ttl": self.max_ttl,
            "timeout": self.timeout,
            "time": str(datetime.now()),
        }

        if not os.path.exists(filename):
            output = {"url": self.target, "protocol": {self.protocol: []}}
        else:
            with open(filename, "r") as f:
                output = json.load(f)

            if args.protocol not in output["protocol"]:
                output["protocol"][self.protocol] = []

        output["protocol"][self.protocol].append(results)

        with open(filename, "w") as outfile:
            log.info(f"Writing results to {filename}...")
            json.dump(output, outfile)


class Hop(dict):
    def __init__(self, source, ttl, sent_time, reply_time):
        self.source = source
        self.ttl = ttl
        self.location = geolocate(source)
        self.asn = asn_lookup(source)
        self.rtt = get_rtt(sent_time, reply_time)
        self.dns = dns_lookup(source) or ""

    def __getattr__(self, attr):
        return self[attr]

    def __repr__(self):
        return (
            f"{self.ttl:<5}"
            f"{self.source:<20.20}"
            f"{self.dns:<40.40}"
            f"{self.location:<40.40}"
            f"{self.asn:<20.20}"
            f"{self.rtt}ms"
        )


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

    for target in targets:
        traceroute = Traceroute(
            target=target,
            protocol=args.protocol,
            max_ttl=args.max_ttl,
            timeout=args.timeout,
        )
        traceroute.run()
