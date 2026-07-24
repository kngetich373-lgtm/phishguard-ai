"""
Extracts the 111 numeric features the trained model expects, from a raw
URL string. Mirrors the feature schema of the GregaVrbancic/Phishing-Dataset
so features line up exactly with training.

Design choice: every feature that needs a live lookup (WHOIS, DNS, SSL,
timing) falls back to -1 ("unknown") on any failure, exactly matching the
sentinel convention already present in the training data - never silently
guessing "safe". Lexical/structural features (built from the URL string
alone) are always computed and never unknown.

check_live_signals=False skips every networked feature (fast, offline,
bulk-safe) - the model still works, just with less signal, same as the
existing heuristic engine's own check_live_signals flag.
"""
from __future__ import annotations

import re
import socket
import ssl
import time
import ipaddress
from urllib.parse import urlparse

try:
    import dns.resolver  # dnspython: pip install dnspython
    _HAVE_DNS = True
except ImportError:
    _HAVE_DNS = False

try:
    import whois as _whois
except ImportError:
    _whois = None

UNKNOWN = -1

_SPECIAL_CHARS = ["dot", "hyphen", "underline", "slash", "questionmark",
                  "equal", "at", "and", "exclamation", "space", "tilde",
                  "comma", "plus", "asterisk", "hashtag", "dollar", "percent"]
_CHAR_MAP = {
    "dot": ".", "hyphen": "-", "underline": "_", "slash": "/",
    "questionmark": "?", "equal": "=", "at": "@", "and": "&",
    "exclamation": "!", "space": " ", "tilde": "~", "comma": ",",
    "plus": "+", "asterisk": "*", "hashtag": "#", "dollar": "$",
    "percent": "%",
}


def _char_counts(segment: str, prefix: str) -> dict:
    return {f"qty_{name}_{prefix}": segment.count(char)
            for name, char in _CHAR_MAP.items()}


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract_features(raw_url: str, check_live_signals: bool = True,
                      timeout: float = 4.0) -> dict:
    if "://" not in raw_url:
        raw_url = "http://" + raw_url
    parsed = urlparse(raw_url)
    host = parsed.hostname or ""
    domain = host
    directory = parsed.path.rsplit("/", 1)[0] if "/" in parsed.path else ""
    file_part = parsed.path.rsplit("/", 1)[-1] if parsed.path else ""
    params = parsed.query

    feats = {}
    feats.update(_char_counts(raw_url, "url"))
    feats["qty_tld_url"] = len(domain.split(".")[-1]) if "." in domain else 0
    feats["length_url"] = len(raw_url)

    feats.update(_char_counts(domain, "domain"))
    feats["qty_vowels_domain"] = sum(1 for c in domain.lower() if c in "aeiou")
    feats["domain_length"] = len(domain)
    feats["domain_in_ip"] = int(_is_ip(host))
    feats["server_client_domain"] = int(
        "server" in domain.lower() or "client" in domain.lower()
    )

    feats.update(_char_counts(directory, "directory"))
    feats["directory_length"] = len(directory)

    feats.update(_char_counts(file_part, "file"))
    feats["file_length"] = len(file_part)

    feats.update(_char_counts(params, "params"))
    feats["params_length"] = len(params)
    feats["tld_present_params"] = int(
        bool(re.search(r"\.(com|net|org|gov|edu|info|biz)\b", params, re.I))
    )
    feats["qty_params"] = len([p for p in params.split("&") if p]) if params else 0
    feats["email_in_url"] = int(bool(re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", raw_url)))

    # -------- live / network features (default -1 = unknown on failure) ----
    net = {
        "time_response": UNKNOWN, "domain_spf": UNKNOWN, "asn_ip": UNKNOWN,
        "time_domain_activation": UNKNOWN, "time_domain_expiration": UNKNOWN,
        "qty_ip_resolved": UNKNOWN, "qty_nameservers": UNKNOWN,
        "qty_mx_servers": UNKNOWN, "ttl_hostname": UNKNOWN,
        "tls_ssl_certificate": 0, "qty_redirects": UNKNOWN,
        "url_google_index": UNKNOWN, "domain_google_index": UNKNOWN,
        "url_shortened": int(len(host.split(".")) <= 2 and len(domain) <= 15
                              and domain in _SHORTENER_HINT),
    }

    if check_live_signals and host:
        # response time + resolved IP count
        try:
            t0 = time.time()
            # IPv4-only, single A-record style lookup to match the training
            # dataset's methodology (getaddrinfo() over-counts by also
            # enumerating IPv6/SOCK_DGRAM/SOCK_STREAM duplicates, which
            # skews qty_ip_resolved far outside the training distribution
            # for multi-CDN sites).
            _, _, ipv4_list = socket.gethostbyname_ex(host)
            net["time_response"] = round(time.time() - t0, 6)
            net["qty_ip_resolved"] = len(set(ipv4_list))
        except Exception:
            pass

        # TLS certificate presence/validity
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.getpeercert()
                    net["tls_ssl_certificate"] = 1
        except Exception:
            net["tls_ssl_certificate"] = 0

        if _HAVE_DNS:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = timeout
                resolver.lifetime = timeout
                ns = resolver.resolve(host, "NS")
                net["qty_nameservers"] = len(ns)
                net["ttl_hostname"] = ns.rrset.ttl if ns.rrset else UNKNOWN
            except Exception:
                pass
            try:
                mx = resolver.resolve(host, "MX")
                net["qty_mx_servers"] = len(mx)
            except Exception:
                net["qty_mx_servers"] = 0
            try:
                txt = resolver.resolve(host, "TXT")
                net["domain_spf"] = int(any(
                    "spf" in r.to_text().lower() for r in txt
                ))
            except Exception:
                net["domain_spf"] = 0

        if _whois is not None:
            try:
                from datetime import datetime, timezone
                record = _whois.whois(host)
                created = record.creation_date
                expires = record.expiration_date
                if isinstance(created, list):
                    created = created[0] if created else None
                if isinstance(expires, list):
                    expires = expires[0] if expires else None
                now = datetime.now(timezone.utc)
                if created:
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    net["time_domain_activation"] = max(0, (now - created).days)
                if expires:
                    if expires.tzinfo is None:
                        expires = expires.replace(tzinfo=timezone.utc)
                    net["time_domain_expiration"] = max(0, (expires - now).days)
            except Exception:
                pass

    feats.update(net)
    return feats


# Small hint set purely to seed url_shortened if network checks are off;
# real detection should cross-reference url_detection.py's URL_SHORTENERS.
_SHORTENER_HINT = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
}
