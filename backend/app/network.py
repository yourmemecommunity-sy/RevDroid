"""Collect URLs, domains and IP addresses from string literals in the code."""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit

STRING_LITERAL = re.compile(r'"((?:[^"\\\n]|\\.){4,500})"')
URL_RE = re.compile(r"\b((?:https?|wss?|ftp)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)")
IP_RE = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?![\d.])")

# Namespace / spec / licence URLs that every app contains and that are not network traffic.
NOISE_HOSTS = {
    "schemas.android.com", "www.w3.org", "w3.org", "xml.org", "ns.adobe.com", "www.apache.org", "apache.org",
    "schemas.xmlsoap.org", "purl.org", "xmlpull.org", "java.sun.com", "xmlns.jcp.org", "json-schema.org",
    "schemas.microsoft.com", "www.slf4j.org", "developer.android.com", "www.gnu.org", "opensource.org",
    "creativecommons.org", "localhost",
}


class EndpointCollector:
    def __init__(self, max_locations: int = 5) -> None:
        self.urls: dict[str, dict[str, Any]] = {}
        self.ips: dict[str, dict[str, Any]] = {}
        self.max_locations = max_locations

    def _add(self, store: dict, key: str, extra: dict, file: str, line: int) -> None:
        item = store.setdefault(key, {**extra, "count": 0, "locations": []})
        item["count"] += 1
        if len(item["locations"]) < self.max_locations:
            item["locations"].append({"file": file, "line": line})

    def feed_line(self, text: str, file: str, line: int) -> None:
        if '"' not in text:
            return
        for lit in STRING_LITERAL.finditer(text):
            value = lit.group(1)
            for m in URL_RE.finditer(value):
                url = m.group(1).rstrip(".,;)'")
                host = (urlsplit(url).hostname or "").lower()
                if not host or host in NOISE_HOSTS or "." not in host and not _is_ip(host):
                    continue
                self._add(self.urls, url, {"url": url, "host": host, "scheme": url.split(":", 1)[0].lower()},
                          file, line)
            if "://" in value:  # IPs inside URLs are already covered by the URL host
                continue
            for m in IP_RE.finditer(value):
                ip = m.group(1)
                if ip in ("0.0.0.0", "255.255.255.255") or ip.startswith("0."):
                    continue
                self._add(self.ips, ip, {"ip": ip, "scope": _ip_scope(ip)}, file, line)

    def result(self) -> dict[str, Any]:
        domains: dict[str, dict[str, Any]] = defaultdict(lambda: {"count": 0, "schemes": set()})
        for u in self.urls.values():
            d = domains[u["host"]]
            d["count"] += u["count"]
            d["schemes"].add(u["scheme"])
        # hosts that are IPs also show up in the IP list
        for u in self.urls.values():
            if _is_ip(u["host"]) and u["host"] not in self.ips:
                self.ips[u["host"]] = {"ip": u["host"], "scope": _ip_scope(u["host"]),
                                       "count": u["count"], "locations": u["locations"]}
        return {
            "urls": sorted(self.urls.values(), key=lambda u: (-u["count"], u["url"]))[:500],
            "domains": sorted(({"domain": k, "count": v["count"], "schemes": sorted(v["schemes"]),
                                "insecure": "http" in v["schemes"] or "ws" in v["schemes"]}
                               for k, v in domains.items()), key=lambda d: (-d["count"], d["domain"])),
            "ips": sorted(self.ips.values(), key=lambda i: (-i["count"], i["ip"])),
        }


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _ip_scope(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private"
    if addr.is_multicast or addr.is_reserved:
        return "reserved"
    return "public"
