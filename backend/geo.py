"""MaxMind GeoLite2 (local, offline) IP -> location/ASN lookups.

Local .mmdb reads are sub-millisecond, so a simple in-process LRU cache is enough --
there's no network round-trip to save by additionally persisting lookups to SQLite.
"""

import ipaddress
import logging
from functools import lru_cache
from typing import Optional

import geoip2.database
import geoip2.errors

from backend.config import settings

logger = logging.getLogger("dashboard.geo")

_city_reader: Optional[geoip2.database.Reader] = None
_asn_reader: Optional[geoip2.database.Reader] = None
_readers_loaded = False


def _load_readers() -> None:
    global _city_reader, _asn_reader, _readers_loaded
    if _readers_loaded:
        return
    _readers_loaded = True
    try:
        _city_reader = geoip2.database.Reader(settings.geoip_city_db)
    except (FileNotFoundError, ValueError):
        logger.warning("GeoLite2 City DB not found at %s -- globe arcs will be disabled", settings.geoip_city_db)
    try:
        _asn_reader = geoip2.database.Reader(settings.geoip_asn_db)
    except (FileNotFoundError, ValueError):
        logger.warning("GeoLite2 ASN DB not found at %s -- ASN/ISP info will be blank", settings.geoip_asn_db)


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


@lru_cache(maxsize=8192)
def lookup(ip: str) -> Optional[dict]:
    """Return {lat, lon, city, country, country_code, asn, as_org} or None if unresolvable."""
    if not is_public_ip(ip):
        return None

    _load_readers()
    if _city_reader is None:
        return None

    try:
        city_resp = _city_reader.city(ip)
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return None

    lat = city_resp.location.latitude
    lon = city_resp.location.longitude
    if lat is None or lon is None:
        return None

    asn = None
    as_org = None
    if _asn_reader is not None:
        try:
            asn_resp = _asn_reader.asn(ip)
            asn = asn_resp.autonomous_system_number
            as_org = asn_resp.autonomous_system_organization
        except (geoip2.errors.AddressNotFoundError, ValueError):
            pass

    return {
        "lat": lat,
        "lon": lon,
        "city": city_resp.city.name,
        "country": city_resp.country.name,
        "country_code": city_resp.country.iso_code,
        "asn": asn,
        "as_org": as_org,
    }
