import os

import geoip2.database
import geoip2.errors

asn_reader = geoip2.database.Reader(
    os.path.join("geolite_databases", "GeoLite2-ASN.mmdb")
)


def asn_lookup(target: str):
    """
    Lookup an IP addresses ASN organization and system number.
    :param target: input IP address
    :return: string containing {system number}:{organization}
    """
    try:
        geolookup = asn_reader.asn(target)
    except geoip2.errors.AddressNotFoundError:
        return ""

    return (
        str(geolookup.autonomous_system_number)
        + ":"
        + geolookup.autonomous_system_organization
    )
