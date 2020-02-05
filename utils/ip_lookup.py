import socket


def ip_lookup(hostname: str) -> str:
    """
    Lookup an IP address for a given hostname.
    :param hostname: host to look up
    :return: IP address string
    """

    try:
        host_ip = socket.gethostbyname(hostname)
    except socket.error:
        return
    return host_ip
