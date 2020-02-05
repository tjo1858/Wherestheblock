#!/usr/bin/env python3

import argparse
import json
import logging
import os
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


class trcrt:
    def __init__(self, target, protocol="icmp", max_ttl=30, timeout=5):
        self.target = target
        self.max_ttl = max_ttl
        self.timeout = timeout
        self.protocol = protocol

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
            f"\033[1m{'TTL': <5} {'IP' : <25} {'DNS' :<40} {'GEOLOCATION' : <40} {'ASN': <20} RTT\033[0m"
        )
        hops = []

        for hop in range(1, self.max_ttl + 1):
            pkt = IP(dst=self.target, ttl=hop) / self.payload
            reply = sr1(pkt, verbose=0, timeout=self.timeout)

            if reply is None:
                log.info(f"{hop:<5} *")

            else:
                hops.append(self.format_hop(reply, hop, pkt))

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
                else:
                    if reply.type == 3:
                        break

        self.results = {
            "hops": hops,
            "max_ttl": self.max_ttl,
            "timeout": self.timeout,
            "time": str(datetime.now()),
        }
        log.debug(f"Results: \n{json.dumps(self.results, indent=4)}")
        self.write_results()

    def format_hop(self, reply, hop, pkt) -> dict:
        """
        Format traceroute reply results into json
        :param reply: scapy reply packet
        :param hop: hop number
        :param pkt: original packet sent out
        :return: hop results dictionary
        """
        hop_dict = {
            "ttl": hop,
            "dns": dns_lookup(reply.src) or "",
            "location": geolocate(reply.src),
            "asn": asn_lookup(reply.src),
            "rtt": get_rtt(pkt.sent_time, reply.time),
        }

        output = f"{hop:<5} {reply.src} {hop_dict['dns']:<40} {hop_dict['location']:<40} {hop_dict['asn']:<20} {hop_dict['rtt']}ms"
        if reply.type == 3:
            output += " ✓"

        log.info(output)

        return hop_dict

    def write_results(self) -> None:
        """
        Write results out to a JSON file.
        """

        os.makedirs("output", exist_ok=True)
        filename = os.path.join("output", self.target + ".json")

        if not os.path.exists(filename):
            output = {"url": self.target, "protocol": {self.protocol: []}}
        else:
            with open(filename, "r") as f:
                output = json.load(f)

            if args.protocol not in output["protocol"]:
                output["protocol"][self.protocol] = []

        output["protocol"][self.protocol].append(self.results)

        with open(filename, "w") as outfile:
            log.info(f"Writing results to {filename}...")
            json.dump(output, outfile)


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
        traceroute = trcrt(
            target=target,
            protocol=args.protocol,
            max_ttl=args.max_ttl,
            timeout=args.timeout,
        )
        traceroute.run()
