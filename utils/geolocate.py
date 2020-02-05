import os

import geoip2.database
import geoip2.errors

city_reader = geoip2.database.Reader(
    os.path.join("geolite_databases", "GeoLite2-City.mmdb")
)


def geolocate(target: str) -> str:
    """
    Get the geolocation of a target IP address, using the Maxmind database.
    https://www.maxmind.com/en/home
    :param target: target IP address
    :return: string containing the {city}, {country}, if found
    """

    location = ""
    try:
        geolookup = city_reader.city(target)
    except geoip2.errors.AddressNotFoundError:
        return location

    if geolookup.country.name:
        location += f"{geolookup.country.name}"

    if geolookup.city.name:
        location += f", {geolookup.city.name}"

    return location
