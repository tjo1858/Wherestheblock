import csv
import os

# run this from inside of the censorship directory

# get all of the files in the output directory
dirname = "../output/"
files = list()
for (dirpath, dirnames, filenames) in os.walk(dirname):
    files += [os.path.join(dirpath, file) for file in filenames]

for file in files:

    # first, find all of the http output
    linesplit = file.split("/")
    protocol = linesplit[2]
    if protocol == "http":

        # now, grab the corresponding tcp traceroute (if exists)
        linesplit[2] = "tcp"
        tcp_filepath = "/".join(linesplit)

        if os.path.exists(tcp_filepath):
            with open(file, "r") as http_file:
                reader = csv.DictReader(http_file)
                found_http = 0

                # go through and try to find number of hops away that target is.
                # if we dont see the "timed out" message, we hit the target
                try:
                    for ct, row in enumerate(reader):
                        if row["Message"] != "timed out":
                            found_http = ct
                            break
                except:
                    pass

                # if we actually found the target, go for tcp
                if found_http != 0:
                    with open(tcp_filepath, "r") as tcp_file:
                        reader = csv.DictReader(tcp_file)
                        found_tcp = 0

                        # super janky i know. find the ip address of the target
                        # as recorded by traceroute
                        for ct, row in enumerate(reader):
                            if "traceroute to" in row["Response_Message"]:
                                ip = row["Response_Message"].split("(")[1].split(")")[0]

                            else:
                                # otherwise, try to see if we have hit the target
                                # ip address in the output
                                if ip in row["Response_Message"]:
                                    found_tcp = ct
                                    break

                    # if we hit the target in tcp, then check the hop count.
                    # if we have significantly less hops for http than we do for tcp,
                    # we may have potentially found censorship
                    if found_tcp != 0:
                        if found_http < found_tcp - 3:
                            website_url = os.path.basename(file)[:-4]
                            print(
                                f"Potential censorship found for {website_url}.\n"
                                f"HTTP hops: {found_http}, TCP hops: {found_tcp}."
                                f"TCP file:\n{tcp_filepath}\n"
                                f"HTTP:\n{file}\n\n"
                            )

