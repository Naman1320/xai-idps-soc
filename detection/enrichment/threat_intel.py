"""
Threat Intelligence Enrichment: IP reputation lookup via AbuseIPDB free tier.

Data Source:
    AbuseIPDB — free tier API
    License: Free API, rate-limited
    Signup: https://www.abuseipdb.com/register
    Rate Limits: 1,000 checks/day on free tier (verify current limits on signup)

Design Decisions:
    - Results are cached locally (in-memory with optional TTL) to avoid
      redundant API calls and stay within rate limits
    - Gracefully degrades if no API key configured (returns unknown status)
    - known_bad threshold is configurable (default: abuse_confidence >= 50)
    - Private IPs are never queried (always return clean/unknown)

Research Value:
    Threat-intel reputation score is used as an ACTUAL INPUT to detection/triage
    logic via the w4 weight in the composite risk formula. This is NOT just a
    dashboard decoration — an IP with high abuse reports WILL increase the
    alert's composite risk score.
"""

import ipaddress
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

import httpx

logger = logging.getLogger(__name__)

CONFIG_DIR = Path(__file__).parent.parent / "config"

# AbuseIPDB API endpoint
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except (ValueError, TypeError):
        return True


class ThreatIntelCache:
    """
    Simple in-memory cache for threat-intel lookups.
    Prevents redundant API calls and helps stay within rate limits.
    """

    def __init__(self, ttl_hours: int = 24):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._ttl_seconds = ttl_hours * 3600
        self._hits = 0
        self._misses = 0

    def get(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get cached result for an IP, or None if expired/missing."""
        entry = self._cache.get(ip)
        if entry is None:
            self._misses += 1
            return None

        if time.time() - entry["_cached_at"] > self._ttl_seconds:
            del self._cache[ip]
            self._misses += 1
            return None

        self._hits += 1
        return entry

    def put(self, ip: str, data: Dict[str, Any]) -> None:
        """Cache a result for an IP."""
        data["_cached_at"] = time.time()
        self._cache[ip] = data

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "cached_ips": len(self._cache),
            "hits": self._hits,
            "misses": self._misses,
        }


class ThreatIntelEnricher:
    """
    Threat intelligence enrichment using AbuseIPDB free tier.

    Provides IP reputation scoring that feeds into the composite risk formula
    as the w4 weight. This is an actual triage input, not just visualization.

    Gracefully degrades:
    - If no API key configured → returns default/unknown scores
    - If rate limit exceeded → returns cached or default scores
    - If IP is private → returns clean (not queried)

    Data Source: AbuseIPDB free tier
    License: Free API key required
    Rate Limits: 1,000 checks/day on free tier
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_ttl_hours: int = 24,
        known_bad_threshold: int = 50,
        timeout: float = 5.0,
    ):
        """
        Args:
            api_key: AbuseIPDB API key. If None, reads from ABUSEIPDB_API_KEY env var.
            cache_ttl_hours: How long to cache results (default: 24 hours).
            known_bad_threshold: AbuseIPDB confidence score >= this = "known bad".
            timeout: HTTP request timeout in seconds.
        """
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        self.known_bad_threshold = known_bad_threshold
        self.timeout = timeout
        self.cache = ThreatIntelCache(ttl_hours=cache_ttl_hours)

        self._available = self.api_key is not None and len(self.api_key) > 0
        self._queries_today = 0
        self._daily_limit = 1000  # AbuseIPDB free tier

        if self._available:
            logger.info(
                f"ThreatIntelEnricher initialized with AbuseIPDB API key "
                f"(cache TTL: {cache_ttl_hours}h, threshold: {known_bad_threshold})"
            )
        else:
            logger.warning(
                "No AbuseIPDB API key configured. Threat-intel enrichment will "
                "return default scores. Set ABUSEIPDB_API_KEY env var or pass api_key."
            )

    def check_ip(self, ip: str) -> Dict[str, Any]:
        """
        Check an IP's threat reputation.

        Args:
            ip: IPv4 or IPv6 address string.

        Returns:
            Dict with:
                - abuse_confidence_score: 0-100 (higher = more malicious)
                - total_reports: Number of abuse reports
                - is_known_bad: Bool (score >= threshold)
                - last_reported_at: ISO timestamp or None
                - usage_type: str or None (e.g., "Data Center/Web Hosting")
                - provider: "abuseipdb" or "none"
                - is_cached: Whether result came from cache
                - data_available: Whether real data was obtained
        """
        # Never query private IPs
        if _is_private_ip(ip):
            return self._default_result(ip, reason="private_ip")

        # Check cache first
        cached = self.cache.get(ip)
        if cached is not None:
            result = {k: v for k, v in cached.items() if not k.startswith("_")}
            result["is_cached"] = True
            return result

        # If no API key, return default
        if not self._available:
            return self._default_result(ip, reason="no_api_key")

        # Check daily rate limit
        if self._queries_today >= self._daily_limit:
            logger.warning(
                f"AbuseIPDB daily rate limit ({self._daily_limit}) reached. "
                f"Returning default score for {ip}."
            )
            return self._default_result(ip, reason="rate_limited")

        # Perform API lookup
        return self._api_lookup(ip)

    def _api_lookup(self, ip: str) -> Dict[str, Any]:
        """Perform actual AbuseIPDB API lookup."""
        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json",
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": "90",
                "verbose": "",
            }

            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(
                    ABUSEIPDB_API_URL,
                    headers=headers,
                    params=params,
                )

            self._queries_today += 1

            if response.status_code == 200:
                data = response.json().get("data", {})
                result = {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "is_known_bad": data.get("abuseConfidenceScore", 0) >= self.known_bad_threshold,
                    "last_reported_at": data.get("lastReportedAt"),
                    "usage_type": data.get("usageType"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "country_code": data.get("countryCode"),
                    "provider": "abuseipdb",
                    "is_cached": False,
                    "data_available": True,
                }
                # Cache the result
                self.cache.put(ip, result)
                return result

            elif response.status_code == 429:
                logger.warning(f"AbuseIPDB rate limit hit for {ip}")
                return self._default_result(ip, reason="rate_limited")
            else:
                logger.warning(
                    f"AbuseIPDB API error for {ip}: "
                    f"HTTP {response.status_code} - {response.text[:200]}"
                )
                return self._default_result(ip, reason="api_error")

        except httpx.TimeoutException:
            logger.warning(f"AbuseIPDB timeout for {ip}")
            return self._default_result(ip, reason="timeout")
        except Exception as e:
            logger.error(f"AbuseIPDB lookup error for {ip}: {e}")
            return self._default_result(ip, reason="error")

    def _default_result(self, ip: str, reason: str = "unknown") -> Dict[str, Any]:
        """Return default threat-intel result when data is unavailable."""
        return {
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "is_known_bad": False,
            "last_reported_at": None,
            "usage_type": None,
            "isp": None,
            "domain": None,
            "country_code": None,
            "provider": "none",
            "is_cached": False,
            "data_available": False,
            "unavailable_reason": reason,
        }

    def get_threat_score_normalized(self, ip: str) -> float:
        """
        Get a normalized threat score (0.0-1.0) suitable for the risk formula.

        This is the value that feeds into w4 * threat_intel in the composite
        risk score. Maps AbuseIPDB's 0-100 confidence to 0.0-1.0.

        For IPs with no data, returns 0.0 (benefit of the doubt).
        """
        result = self.check_ip(ip)
        if not result.get("data_available", False):
            return 0.0
        return result.get("abuse_confidence_score", 0) / 100.0

    def lookup(self, ip: str) -> Dict[str, Any]:
        """Convenience alias for check_ip."""
        return self.check_ip(ip)

    @property
    def stats(self) -> Dict[str, Any]:
        """Return usage statistics."""
        return {
            "api_available": self._available,
            "queries_today": self._queries_today,
            "daily_limit": self._daily_limit,
            "remaining": self._daily_limit - self._queries_today,
            "cache": self.cache.stats,
        }
