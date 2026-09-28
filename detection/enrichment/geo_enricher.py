"""
Geolocation Enrichment: IP → Country/Region/City/ASN using MaxMind GeoLite2.

Data Source:
    MaxMind GeoLite2 (City + ASN) — free tier
    License: GeoLite2 EULA, free with attribution, redistribution allowed
    Signup: https://www.maxmind.com/en/geolite2/signup
    No per-query rate limit (local .mmdb file lookups)

Accuracy Caveats (must be documented in any output):
    - City/region-level accuracy only (~95% country, ~55-80% city — MaxMind's own figures)
    - Completely unreliable for VPN/proxy/Tor/CGNAT traffic
    - Private RFC1918 IPs have no real geolocation
    - CSE-CIC-IDS2018 lab IPs are private → synthetic geo assigned for demo only
    - Geographic origin alone does NOT indicate maliciousness
"""

import ipaddress
import logging
import os
import random
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Try to import geoip2; gracefully degrade if not installed
try:
    import geoip2.database
    import geoip2.errors
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False
    logger.warning(
        "geoip2 package not installed. Geolocation enrichment will use synthetic data. "
        "Install with: pip install geoip2>=4.8.0"
    )

CONFIG_DIR = Path(__file__).parent.parent / "config"
DATA_DIR = Path(__file__).parent.parent / "data"

# Standard caveat string included in every geo result
ACCURACY_CAVEAT = (
    "City-level accuracy only (~55-80%); unreliable for VPN/proxy/CGNAT traffic. "
    "Private/lab IPs use synthetic coordinates for demonstration."
)

# Synthetic geo data for demo/lab environments
# Maps private IP subnets to plausible-looking geo coordinates
SYNTHETIC_GEO_POOL = [
    {"country": "United States", "country_code": "US", "region": "Virginia",
     "city": "Ashburn", "latitude": 39.0438, "longitude": -77.4874,
     "asn": 14618, "asn_org": "Amazon.com Inc."},
    {"country": "United States", "country_code": "US", "region": "Oregon",
     "city": "Boardman", "latitude": 45.8399, "longitude": -119.7006,
     "asn": 16509, "asn_org": "Amazon.com Inc."},
    {"country": "Germany", "country_code": "DE", "region": "Hesse",
     "city": "Frankfurt", "latitude": 50.1109, "longitude": 8.6821,
     "asn": 24940, "asn_org": "Hetzner Online GmbH"},
    {"country": "Russia", "country_code": "RU", "region": "Moscow",
     "city": "Moscow", "latitude": 55.7558, "longitude": 37.6173,
     "asn": 49505, "asn_org": "Selectel Ltd."},
    {"country": "China", "country_code": "CN", "region": "Beijing",
     "city": "Beijing", "latitude": 39.9042, "longitude": 116.4074,
     "asn": 4134, "asn_org": "China Telecom"},
    {"country": "Netherlands", "country_code": "NL", "region": "North Holland",
     "city": "Amsterdam", "latitude": 52.3676, "longitude": 4.9041,
     "asn": 60781, "asn_org": "LeaseWeb Netherlands B.V."},
    {"country": "Brazil", "country_code": "BR", "region": "São Paulo",
     "city": "São Paulo", "latitude": -23.5505, "longitude": -46.6333,
     "asn": 28573, "asn_org": "Claro S.A."},
    {"country": "India", "country_code": "IN", "region": "Maharashtra",
     "city": "Mumbai", "latitude": 19.0760, "longitude": 72.8777,
     "asn": 55836, "asn_org": "Reliance Jio Infocomm Limited"},
    {"country": "United Kingdom", "country_code": "GB", "region": "England",
     "city": "London", "latitude": 51.5074, "longitude": -0.1278,
     "asn": 5089, "asn_org": "Virgin Media Limited"},
    {"country": "Japan", "country_code": "JP", "region": "Tokyo",
     "city": "Tokyo", "latitude": 35.6762, "longitude": 139.6503,
     "asn": 2516, "asn_org": "KDDI Corporation"},
    {"country": "South Korea", "country_code": "KR", "region": "Seoul",
     "city": "Seoul", "latitude": 37.5665, "longitude": 126.9780,
     "asn": 4766, "asn_org": "Korea Telecom"},
    {"country": "Singapore", "country_code": "SG", "region": "Singapore",
     "city": "Singapore", "latitude": 1.3521, "longitude": 103.8198,
     "asn": 24482, "asn_org": "SG.GS"},
    {"country": "Ukraine", "country_code": "UA", "region": "Kyiv",
     "city": "Kyiv", "latitude": 50.4501, "longitude": 30.5234,
     "asn": 13188, "asn_org": "Content Delivery Network Ltd"},
    {"country": "Romania", "country_code": "RO", "region": "Bucharest",
     "city": "Bucharest", "latitude": 44.4268, "longitude": 26.1025,
     "asn": 9009, "asn_org": "M247 Europe SRL"},
    {"country": "Canada", "country_code": "CA", "region": "Ontario",
     "city": "Toronto", "latitude": 43.6532, "longitude": -79.3832,
     "asn": 577, "asn_org": "Bell Canada"},
]


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private (RFC1918 / link-local / loopback)."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except (ValueError, TypeError):
        return True  # Treat invalid IPs as private (no geo)


def _deterministic_synthetic_geo(ip_str: str) -> Dict[str, Any]:
    """
    Return a deterministic synthetic geo entry for a given IP.
    Uses a hash of the IP to pick consistently from the pool,
    so the same IP always gets the same synthetic location.
    """
    idx = hash(ip_str) % len(SYNTHETIC_GEO_POOL)
    entry = SYNTHETIC_GEO_POOL[idx].copy()
    entry["is_private"] = True
    entry["is_synthetic"] = True
    entry["accuracy_caveat"] = (
        "SYNTHETIC: This is a private/lab IP address with no real geolocation. "
        "Coordinates are assigned for demonstration purposes only."
    )
    return entry


class GeoEnricher:
    """
    IP geolocation enrichment using MaxMind GeoLite2 (City + ASN).

    Gracefully degrades:
    - If geoip2 library not installed → synthetic data only
    - If .mmdb files not found → synthetic data only
    - If IP is private (RFC1918) → synthetic data for demo
    - If lookup fails → empty geo context

    Data Source: MaxMind GeoLite2 (free tier)
    License: GeoLite2 EULA — free, attribution required
    Rate Limits: None (local file lookups)
    """

    def __init__(
        self,
        city_db_path: Optional[str] = None,
        asn_db_path: Optional[str] = None,
        synthetic_for_private: bool = True,
    ):
        """
        Args:
            city_db_path: Path to GeoLite2-City.mmdb file.
            asn_db_path: Path to GeoLite2-ASN.mmdb file.
            synthetic_for_private: If True, generate synthetic geo for private IPs.
        """
        self.synthetic_for_private = synthetic_for_private
        self.city_reader = None
        self.asn_reader = None
        self._available = False

        # Resolve paths from env or defaults
        if city_db_path is None:
            city_db_path = os.getenv(
                "GEOLITE2_CITY_DB",
                str(DATA_DIR / "geolite2" / "GeoLite2-City.mmdb")
            )
        if asn_db_path is None:
            asn_db_path = os.getenv(
                "GEOLITE2_ASN_DB",
                str(DATA_DIR / "geolite2" / "GeoLite2-ASN.mmdb")
            )

        if HAS_GEOIP2:
            try:
                if Path(city_db_path).exists():
                    self.city_reader = geoip2.database.Reader(city_db_path)
                    logger.info(f"GeoLite2 City database loaded: {city_db_path}")
                else:
                    logger.warning(
                        f"GeoLite2 City DB not found at {city_db_path}. "
                        "Download from https://www.maxmind.com/en/geolite2/signup"
                    )
            except Exception as e:
                logger.error(f"Failed to load GeoLite2 City DB: {e}")

            try:
                if Path(asn_db_path).exists():
                    self.asn_reader = geoip2.database.Reader(asn_db_path)
                    logger.info(f"GeoLite2 ASN database loaded: {asn_db_path}")
                else:
                    logger.warning(
                        f"GeoLite2 ASN DB not found at {asn_db_path}. "
                        "Download from https://www.maxmind.com/en/geolite2/signup"
                    )
            except Exception as e:
                logger.error(f"Failed to load GeoLite2 ASN DB: {e}")

            self._available = self.city_reader is not None
        else:
            logger.warning("GeoIP2 not available — using synthetic geo data only")

        mode = "live (MaxMind)" if self._available else "synthetic only"
        logger.info(f"GeoEnricher initialized in {mode} mode")

    def enrich(self, ip: str) -> Dict[str, Any]:
        """
        Enrich an IP address with geolocation data.

        Args:
            ip: IPv4 or IPv6 address string.

        Returns:
            Dict with: country, country_code, region, city, latitude, longitude,
                       asn, asn_org, is_private, is_synthetic, accuracy_caveat
        """
        # Handle private / lab IPs
        if _is_private_ip(ip):
            if self.synthetic_for_private:
                return _deterministic_synthetic_geo(ip)
            return self._empty_result(ip, is_private=True)

        # Try real GeoLite2 lookup
        if self._available:
            return self._real_lookup(ip)

        # Fallback: synthetic for everything if no DB available
        return _deterministic_synthetic_geo(ip)

    def _real_lookup(self, ip: str) -> Dict[str, Any]:
        """Perform actual GeoLite2 database lookup."""
        result = {
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "asn": None,
            "asn_org": None,
            "is_private": False,
            "is_synthetic": False,
            "accuracy_caveat": ACCURACY_CAVEAT,
        }

        # City lookup
        if self.city_reader:
            try:
                city_resp = self.city_reader.city(ip)
                result["country"] = city_resp.country.name
                result["country_code"] = city_resp.country.iso_code
                result["region"] = (
                    city_resp.subdivisions.most_specific.name
                    if city_resp.subdivisions
                    else None
                )
                result["city"] = city_resp.city.name
                result["latitude"] = city_resp.location.latitude
                result["longitude"] = city_resp.location.longitude
            except geoip2.errors.AddressNotFoundError:
                logger.debug(f"No city data for IP {ip}")
            except Exception as e:
                logger.warning(f"GeoLite2 city lookup error for {ip}: {e}")

        # ASN lookup
        if self.asn_reader:
            try:
                asn_resp = self.asn_reader.asn(ip)
                result["asn"] = asn_resp.autonomous_system_number
                result["asn_org"] = asn_resp.autonomous_system_organization
            except geoip2.errors.AddressNotFoundError:
                logger.debug(f"No ASN data for IP {ip}")
            except Exception as e:
                logger.warning(f"GeoLite2 ASN lookup error for {ip}: {e}")

        return result

    def _empty_result(self, ip: str, is_private: bool = False) -> Dict[str, Any]:
        """Return empty geo result."""
        return {
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "asn": None,
            "asn_org": None,
            "is_private": is_private,
            "is_synthetic": False,
            "accuracy_caveat": ACCURACY_CAVEAT,
        }

    def close(self):
        """Close database readers."""
        if self.city_reader:
            self.city_reader.close()
        if self.asn_reader:
            self.asn_reader.close()

    def __del__(self):
        self.close()
