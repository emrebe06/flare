# -*- coding: utf-8 -*-
import hashlib
import html
import ipaddress
import re
import socket
import ssl
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse, parse_qs, unquote
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.error import URLError, HTTPError

from src.core.models import (
    APP_NAME, APP_VERSION, OFFICIAL_DOMAINS, MARK_NAMES,
    SUSPICIOUS_TLDS, SHORTENER_DOMAINS, PAYMENT_WORDS, PHISHING_WORDS,
    PRESSURE_WORDS, OFF_PLATFORM_WORDS, SOCIAL_ENGINEERING_WORDS,
    COMMON_SCAM_PATTERNS
)

# Regex patterns
IBAN_PATTERN = re.compile(r"\bTR\s?\d{2}(?:\s?\d{4}){5}\s?\d{2}\b", re.IGNORECASE)
PHONE_PATTERN = re.compile(r"(?:(?:\+?90)|0)?\s?5\d{2}\s?\d{3}\s?\d{2}\s?\d{2}")
EMAIL_PATTERN = re.compile(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", re.IGNORECASE)

def normalize_text(value: str) -> str:
    value = value or ""
    tr_map = str.maketrans({
        "İ": "i", "I": "i", "ı": "i",
        "Ğ": "g", "ğ": "g",
        "Ü": "u", "ü": "u",
        "Ş": "s", "ş": "s",
        "Ö": "o", "ö": "o",
        "Ç": "c", "ç": "c",
    })
    return value.translate(tr_map).lower()


def safe_strip(value: Optional[str]) -> str:
    return (value or "").strip()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def is_probably_url(value: str) -> bool:
    value = safe_strip(value)
    if not value:
        return False
    if value.startswith(("http://", "https://")):
        return True
    if "." in value and " " not in value:
        return True
    return False


def ensure_scheme(url: str) -> str:
    url = safe_strip(url)
    if not url:
        return url
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def split_words(value: str) -> List[str]:
    return re.findall(r"[a-zA-ZğüşöçıİĞÜŞÖÇ0-9_.-]+", value or "")


def unique_list(items: Iterable[str]) -> List[str]:
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


class DomainTools:
    BLOCKED_HOSTS = {"localhost", "localhost.localdomain"}

    @staticmethod
    def parse_url(raw_url: str) -> Dict[str, Any]:
        url = ensure_scheme(raw_url)
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        tld = host.split(".")[-1] if "." in host else ""
        labels = host.split(".") if host else []
        registered = DomainTools.guess_registered_domain(host)
        return {
            "raw": raw_url,
            "normalized": url,
            "scheme": parsed.scheme,
            "host": host,
            "port": parsed.port,
            "path": path,
            "query": query,
            "tld": tld,
            "labels": labels,
            "registered_domain": registered,
            "query_keys": sorted(parse_qs(query).keys()),
        }

    @staticmethod
    def is_blocked_network_host(host: str) -> bool:
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return True
        if host in DomainTools.BLOCKED_HOSTS or host.endswith(".localhost"):
            return True

        candidates: List[str] = []
        try:
            candidates.append(str(ipaddress.ip_address(host)))
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                candidates.extend({item[4][0] for item in infos})
            except socket.gaierror:
                return False
            except Exception:
                return True

        for candidate in candidates:
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                return True
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                return True
        return False

    @staticmethod
    def is_blocked_network_url(url: str) -> bool:
        parsed = DomainTools.parse_url(url)
        return DomainTools.is_blocked_network_host(parsed.get("host", ""))

    @staticmethod
    def guess_registered_domain(host: str) -> str:
        if not host:
            return ""
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        if len(parts) >= 3 and parts[-2] in {"com", "net", "org", "gov", "edu"} and parts[-1] == "tr":
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    @staticmethod
    def is_ip_host(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except Exception:
            return False

    @staticmethod
    def has_punycode(host: str) -> bool:
        return "xn--" in (host or "")

    @staticmethod
    def suspicious_hyphen_count(host: str) -> int:
        return (host or "").count("-")

    @staticmethod
    def contains_mark(host: str, platform: str) -> bool:
        h = normalize_text(host)
        marks = MARK_NAMES.get(platform, [])
        return any(normalize_text(m) in h for m in marks)

    @staticmethod
    def is_official(host: str, platform: str) -> bool:
        host = (host or "").lower()
        official = OFFICIAL_DOMAINS.get(platform, [])
        return host in official or any(host.endswith("." + d) for d in official)

    @staticmethod
    def is_shortener(host: str) -> bool:
        h = (host or "").lower()
        return h in SHORTENER_DOMAINS

    @staticmethod
    def similarity_score(a: str, b: str) -> float:
        # C++ Starfall Core ile ezilecek, fakat fallback olarak burada kalıyor.
        try:
            from src.core.bindings import starfall_similarity
            return starfall_similarity(a, b)
        except Exception:
            pass

        a = normalize_text(a)
        b = normalize_text(b)
        if a == b:
            return 1.0
        if not a or not b:
            return 0.0
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            cur = [i]
            for j, cb in enumerate(b, 1):
                ins = cur[j - 1] + 1
                delete = prev[j] + 1
                sub = prev[j - 1] + (0 if ca == cb else 1)
                cur.append(min(ins, delete, sub))
            prev = cur
        dist = prev[-1]
        max_len = max(len(a), len(b))
        return 1.0 - (dist / max_len)

    @staticmethod
    def fetch_headers(url: str, timeout: int = 6) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "attempted": True,
            "ok": False,
            "status": None,
            "final_url": None,
            "headers": {},
            "error": "",
        }
        try:
            if DomainTools.is_blocked_network_url(url):
                info["error"] = "Blocked private, local, reserved, or metadata network target."
                return info

            class SafeRedirectHandler(HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    if DomainTools.is_blocked_network_url(newurl):
                        raise URLError("Blocked redirect to private, local, reserved, or metadata network target.")
                    return super().redirect_request(req, fp, code, msg, headers, newurl)

            req = Request(
                url,
                method="GET",
                headers={
                    "User-Agent": f"{APP_NAME}/{APP_VERSION} passive-check",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
            )
            opener = build_opener(SafeRedirectHandler)
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read(250_000)
                info["ok"] = True
                info["status"] = getattr(resp, "status", None)
                info["final_url"] = resp.geturl()
                info["headers"] = dict(resp.headers.items())
                try:
                    info["sample_text"] = raw.decode("utf-8", errors="ignore")
                except Exception:
                    info["sample_text"] = ""
        except HTTPError as e:
            info["status"] = e.code
            info["error"] = f"HTTPError: {e}"
            try:
                info["headers"] = dict(e.headers.items())
            except Exception:
                pass
        except URLError as e:
            info["error"] = f"URLError: {e}"
        except Exception as e:
            info["error"] = f"{type(e).__name__}: {e}"
        return info

    @staticmethod
    def ssl_info(host: str, port: int = 443, timeout: int = 5) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "attempted": True,
            "ok": False,
            "subject": "",
            "issuer": "",
            "not_before": "",
            "not_after": "",
            "error": "",
            "is_free_ssl": False,
        }
        if not host or DomainTools.is_blocked_network_host(host):
            info["error"] = "Host boş, IP host, lokal veya özel ağ hedefi."
            return info
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    info["ok"] = True
                    info["subject"] = str(cert.get("subject", ""))
                    
                    # Issuer bilgisini çek
                    issuer_info = str(cert.get("issuer", ""))
                    info["issuer"] = issuer_info
                    info["not_before"] = str(cert.get("notBefore", ""))
                    info["not_after"] = str(cert.get("notAfter", ""))
                    
                    # Akıllı SSL Analizi: Ücretsiz veya kolay sağlanan otomasyon sertifikalarını tespit et
                    free_issuers = ["let's encrypt", "zerossl", "cpanel", "cloudflare", "sectigo", "dv ssl"]
                    if any(fi in issuer_info.lower() for fi in free_issuers):
                        info["is_free_ssl"] = True
        except Exception as e:
            info["error"] = f"{type(e).__name__}: {e}"
        return info


class TextScanner:
    @staticmethod
    def scan(text: str) -> Dict[str, Any]:
        # C++ hızlı tarayıcı ile ezilebilir, fallback olarak burada kalıyor.
        try:
            from src.core.bindings import starfall_scan_text
            cpp_res = starfall_scan_text(text)
            if cpp_res:
                return cpp_res
        except Exception:
            pass

        raw = text or ""
        norm = normalize_text(unquote(html.unescape(raw)))
        words = split_words(norm)
        found_payment = TextScanner.find_keywords(norm, PAYMENT_WORDS)
        found_phishing = TextScanner.find_keywords(norm, PHISHING_WORDS)
        found_pressure = TextScanner.find_keywords(norm, PRESSURE_WORDS)
        found_off_platform = TextScanner.find_keywords(norm, OFF_PLATFORM_WORDS)
        found_social_engineering = TextScanner.find_keywords(norm, SOCIAL_ENGINEERING_WORDS)
        ibans = unique_list([m.group(0).replace(" ", "") for m in IBAN_PATTERN.finditer(raw)])
        phones = unique_list([m.group(0) for m in PHONE_PATTERN.finditer(raw)])
        emails = unique_list([m.group(0) for m in EMAIL_PATTERN.finditer(raw)])
        regex_hits = []
        for pattern in COMMON_SCAM_PATTERNS:
            if re.search(pattern, norm, flags=re.IGNORECASE):
                regex_hits.append(pattern)
        return {
            "length": len(raw),
            "word_count": len(words),
            "sha256": sha256_text(raw) if raw else "",
            "payment_keywords": found_payment,
            "phishing_keywords": found_phishing,
            "pressure_keywords": found_pressure,
            "off_platform_keywords": found_off_platform,
            "social_engineering_keywords": found_social_engineering,
            "ibans": ibans,
            "phones": phones,
            "emails": emails,
            "regex_hits": regex_hits,
        }

    @staticmethod
    def find_keywords(norm_text: str, keywords: Iterable[str]) -> List[str]:
        hits = []
        for kw in keywords:
            if normalize_text(kw) in norm_text:
                hits.append(kw)
        return unique_list(hits)
