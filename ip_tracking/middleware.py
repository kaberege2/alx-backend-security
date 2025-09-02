from __future__ import annotations

import ipaddress
import json
from typing import Optional

from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin

from django.core.cache import cache
from django.conf import settings
from django.utils import timezone

from ipware import get_client_ip

from .models import RequestLog, BlockedIP

# Optional: tiny, safe geolocation helper using ipinfo (or any HTTP endpoint)
# We keep the call behind a cache and setting flags to avoid perf issues.
try:
    import requests  # noqa: WPS433
except Exception:  # pragma: no cover
    requests = None


GEO_CACHE_PREFIX = "geoip:"
GEO_CACHE_TTL = getattr(settings, "IP_TRACKING_GEO_TTL_SECONDS", 60 * 60 * 24)  # 24h
BLOCKLIST_CACHE_PREFIX = "blocked_ip:"
BLOCKLIST_CACHE_TTL = getattr(settings, "IP_TRACKING_BLOCKED_TTL_SECONDS", 60 * 10)  # 10m


def anonymize_ip(ip: str) -> str:
    """
    Truncate IPv4 to /24 and IPv6 to /64 to reduce identifiability (privacy).
    """
    try:
        ipa = ipaddress.ip_address(ip)
        if isinstance(ipa, ipaddress.IPv4Address):
            # zero the last octet
            parts = ip.split(".")
            parts[-1] = "0"
            return ".".join(parts)
        # IPv6: zero the last 64 bits
        network = ipaddress.IPv6Network(f"{ip}/64", strict=False)
        return str(network.network_address)
    except Exception:
        return ip  # fallback to original if parsing fails


def geolocate_ip(ip: str) -> tuple[Optional[str], Optional[str]]:
    """
    Resolve (country, city) with caching; returns (None, None) on failure or when disabled.
    - Uses IPINFO_TOKEN from settings (optional).
    """
    if not getattr(settings, "IP_TRACKING_ENABLE_GEOLOCATION", False):
        return None, None

    cache_key = f"{GEO_CACHE_PREFIX}{ip}"
    cached = cache.get(cache_key)
    if cached:
        return cached.get("country"), cached.get("city")

    token = getattr(settings, "IPINFO_TOKEN", None)
    endpoint = getattr(settings, "IP_TRACKING_GEO_ENDPOINT", None)  # allow custom
    if requests is None or not token:
        return None, None

    try:
        url = endpoint or f"https://ipinfo.io/{ip}?token={token}"
        resp = requests.get(url, timeout=2.5)  # keep tight timeout
        if resp.ok:
            data = resp.json()
            country = data.get("country")
            city = data.get("city")
            cache.set(cache_key, {"country": country, "city": city}, GEO_CACHE_TTL)
            return country, city
    except Exception:
        pass

    return None, None


class IPTrackingMiddleware(MiddlewareMixin):
    """
    Task 0/1/2:
    - Logs request IP, timestamp, path.
    - Blocks blacklisted IPs.
    - Enriches log with geolocation (cached).
    """

    def process_request(self, request):
        # Resolve client IP robustly (handles proxies/load balancers)
        ip, _is_routable = get_client_ip(request)
        if ip is None:
            ip = "0.0.0.0"

        # Blocklist check (cached)
        if self._is_blocked(ip):
            return HttpResponseForbidden("Forbidden")

        # Log ASAP (anonymize before persist if policy requires)
        store_raw_ip = getattr(settings, "IP_TRACKING_STORE_RAW_IP", False)
        ip_to_store = ip if store_raw_ip else anonymize_ip(ip)

        country, city = geolocate_ip(ip)

        try:
            RequestLog.objects.create(
                ip_address=ip_to_store,
                timestamp=timezone.now(),
                path=request.path[:512],
                country=country,
                city=city,
            )
        except Exception:
            # Swallow logging errors to never break request flow
            pass

        # Attach for downstream if needed
        request.client_ip = ip
        request.client_ip_anonymized = ip_to_store

    @staticmethod
    def _is_blocked(ip: str) -> bool:
        cache_key = f"{BLOCKLIST_CACHE_PREFIX}{ip}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        exists = BlockedIP.objects.filter(ip_address=ip).exists()
        cache.set(cache_key, exists, BLOCKLIST_CACHE_TTL)
        return exists
