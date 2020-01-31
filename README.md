# wheres the block

## preflight requirements

### dependencies
to install all required dependencies for this project, run:
		

    pip3 install -r requirements.txt

# instructions

## usage

        usage: Perform a traceroute against a given target(s). [-h]
                                                           [-c CSV | -t TARGET]
                                                           [-P {udp,tcp,icmp,lft,http,dns}]
                                                           [-m MAX_TTL] [-v]
    
    optional arguments:
      -h, --help            show this help message and exit
      -c CSV, --csv CSV     Input CSV file.
      -t TARGET, --target TARGET
                            Target destination.
      -P {udp,tcp,icmp,lft,http,dns}, --protocol {udp,tcp,icmp,lft,http,dns}
                            protocol choice (default: udp)
      -m MAX_TTL, --max_ttl MAX_TTL
                            Set the max time-to-live (max number of hops) used in
                            outgoing probe packets.
      -v, --verbose         Enable verbose logging.



## run with an input file

    python3 wtb.py --csv block_urls/ua.csv

## run with a single target

 
    python3 wtb.py --target www.google.com



