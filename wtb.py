#!/usr/bin/env python3

import argparse
import json
import logging
import multiprocessing
import os
import socket
import sys
import time
from datetime import datetime
from itertools import repeat

import coloredlogs
from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, sr1, load_layer
from utils.asn_lookup import asn_lookup
from utils.csv_utils import read_csv_input_file
from utils.dns_lookup import dns_lookup
from utils.geolocate import geolocate
from utils.rtt import get_rtt

logging.getLogger("scapy").setLevel(logging.ERROR)
log = logging.getLogger(__name__)
coloredlogs.install(level="INFO", fmt="%(message)s")


class Traceroute(dict):
    """
    Represents an individual traceroute to a target.
    """

    def __init__(
        self, target: str, protocol: str = "icmp", max_ttl: int = 30, timeout: int = 5
    ) -> None:
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
            load_layer("http")
            self.payload = TCP(dport=80, flags="S")

        self.run()
        return

    def run(self) -> None:
        """
        Run the traceroute to the target, taking into account predetermined
        maximum hop count, protocol, and timeout.
        """

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
                # no response, endpoint is likely dropping this traffic
                if reply is None:
                    self.hops.append(
                        Hop(source="*", ttl=ttl, sent_time=pkt.sent_time, reply_time="")
                    )

                else:
                    hop = Hop(
                        source=reply.src,
                        ttl=ttl,
                        sent_time=pkt.sent_time,
                        reply_time=reply.time,
                    )

                    if reply.haslayer(ICMP):
                        if reply.type == 3:
                            hop.response = "✓"

                    else:
                        # if we received a response back that is not ICMP,
                        # we likely received back a SYN/ACK for an HTTP request.
                        # respond with an ACK and our desired target.
                        # TODO: handle the response

                        if self.protocol == "http":

                            # first, save the hop response for the initial SYN/ACK
                            self.hops.append(hop)

                            # now, send the HTTP request to the target
                            request_data = f"GET / HTTP/1.1\r\nHost: {self.target}\r\n"
                            http_request = IP(dst=self.target) / TCP() / request_data
                            http_reply = sr1(
                                http_request, verbose=0, timeout=self.timeout
                            )

                            # if we got a reply, save it with the TCP flags
                            # TODO: decide if we want to save the packet data?
                            if http_reply:
                                self.hops.append(
                                    Hop(
                                        source=http_reply.src,
                                        ttl=ttl,
                                        sent_time=http_request.sent_time,
                                        reply_time=http_reply.time,
                                        response=http_reply.sprintf("%TCP.flags%"),
                                    )
                                )
                                break
                            # otherwise, we got no response
                            else:
                                hop = Hop(
                                    source="",
                                    ttl=ttl,
                                    sent_time=http_request.sent_time,
                                    reply_time=0,
                                )

                    self.hops.append(hop)

        self.write_results()

    def write_results(self) -> None:
        """
        Write results out to a JSON file. Additionally, receive the multiprocessing
        lock and write out our results to stdout.
        """
        filename = os.path.join("output", self.target + ".json")

        # acquire the lock so we do not garble up output on stdout
        # for multiple targets
        lock.acquire()
        log.info(
            f"\033[1m{'TTL':<5} {'IP':<20} {'DNS':40} {'GEOLOCATION':40} {'ASN':20} {'RTT':8} RESPONSE\033[0m"
        )
        for hop in self.hops:
            log.info(hop)
        log.info(f"\033[1mWriting results to {filename}...\033[0m")
        lock.release()

        # rewrite the hop list as dictionaries (maybe this can be done more elegantly)
        self.hops = [vars(hop) for hop in self.hops]

        os.makedirs("output", exist_ok=True)

        results = {
            "hops": self.hops,
            "max_ttl": self.max_ttl,
            "timeout": self.timeout,
            "time": str(datetime.now()),
        }

        # if we have no output file already existing, we will create one
        if not os.path.exists(filename):
            output = {"url": self.target, "protocol": {self.protocol: []}}
        else:
            # otherwise, we will load it and append the results for this
            # traceroute to the list for the given protocol
            with open(filename, "r") as f:
                output = json.load(f)

            if self.protocol not in output["protocol"].keys():
                output["protocol"][self.protocol] = []

        output["protocol"][self.protocol].append(results)

        with open(filename, "w") as outfile:
            json.dump(output, outfile)


class Hop(dict):
    """
    Represents an individual hop en route to a target.
    """

    def __init__(
        self, source: str, ttl: int, sent_time: int, reply_time: int, response: str = ""
    ) -> None:
        self.source = source
        self.ttl = ttl
        self.location = geolocate(source)
        self.asn = asn_lookup(source)
        self.rtt = get_rtt(sent_time, reply_time)
        self.dns = dns_lookup(source) or ""
        self.extra_data = ""
        self.response = response

    def __getattr__(self, attr):
        return self[attr]

    def __repr__(self):
        return (
            f"{self.ttl:<5} "
            f"{self.source:<20.20} "
            f"{self.dns:<40.40} "
            f"{self.location:<40.40} "
            f"{self.asn:<20.20} "
            f"{self.rtt:<8.8} "
            f"{self.response}"
        )


def init(stdout_lock: multiprocessing.Lock) -> None:
    """
    Initialize the global multiprocessing lock for output to stdout.
    """
    global lock
    lock = stdout_lock


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
        choices=["udp", "tcp", "icmp", "http", "dns", "tls"],
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
        "--threads",
        default=4,
        type=int,
        help="Maximum number of concurrent traceroutes.",
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

    targets = []

    if args.csv:
        targets = read_csv_input_file(args.csv)
        if not targets:
            sys.exit(1)

    elif args.target:
        targets.append(args.target)

    else:
        log.error("You must provide either a target or an input file. Exiting...")
        parser.print_help()
        sys.exit(1)

    # only spawn multiple threads if we have multiple targets
    if len(targets) < args.threads:
        thread_count = len(targets)
    else:
        thread_count = args.threads

    start_time = time.time()

    # create a lock for the multiprocessing pool for output to stdout
    stdout_lock = multiprocessing.Lock()

    # initialize a thread pool for each target in the list
    with multiprocessing.Pool(
        processes=thread_count, initializer=init, initargs=(stdout_lock,)
    ) as pool:

        # zip up the arguments as all of the targets, repeating the protocol,
        # max_ttl, and timeout for each individual traceroute
        pool.starmap(
            Traceroute,
            zip(
                targets,
                repeat(args.protocol),
                repeat(args.max_ttl),
                repeat(args.timeout),
            ),
        )

    log.info(f"Total elapsed time: {time.time() - start_time:.2f}")
