import re

ICAO_REGEX = re.compile(r"^[0-9A-F]{6}$")

def valid_icao(icao):
    return bool(ICAO_REGEX.match(icao))
