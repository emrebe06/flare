#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
URL'den HTML indirip Flame ile pasif analiz raporu üretir.

Cloudflare/403 gibi korumalarda bypass denemez; durum rapora yazılır.
"""

import argparse
import json
import re
import time
from pathlib import Path
from typing import Any, Dict, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from src.core.engine import RiskEngine
from src.core.models import AnalysisInput
from src.core.scanners import DomainTools, ensure_scheme
from src.utils.file_parsers import parse_html_file
from src.utils.reporter import ReportWriter


def safe_name(value: str) -> str:
    value = re.sub(r"^https?://", "", value.strip().lower())
    value = re.sub(r"[^a-z0-9._-]+", "_", value)
    return value[:90].strip("._-") or "scan"


def download_html(url: str, timeout: int = 12) -> Tuple[str, Dict[str, Any]]:
    normalized = ensure_scheme(url)
    info: Dict[str, Any] = {
        "attempted": True,
        "ok": False,
        "status": None,
        "final_url": None,
        "headers": {},
        "error": "",
    }
    if DomainTools.is_blocked_network_url(normalized):
        info["error"] = "Blocked private, local, reserved, or metadata network target."
        return "", info

    req = Request(
        normalized,
        method="GET",
        headers={
            "User-Agent": "Flame/0.2 passive-html-download",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.7",
        },
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read(2_000_000)
            info["ok"] = True
            info["status"] = getattr(resp, "status", None)
            info["final_url"] = resp.geturl()
            info["headers"] = dict(resp.headers.items())
            charset = resp.headers.get_content_charset() or "utf-8"
            return raw.decode(charset, errors="ignore"), info
    except HTTPError as exc:
        info["status"] = exc.code
        info["error"] = f"HTTPError: {exc}"
        try:
            info["headers"] = dict(exc.headers.items())
        except Exception:
            pass
    except URLError as exc:
        info["error"] = f"URLError: {exc}"
    except Exception as exc:
        info["error"] = f"{type(exc).__name__}: {exc}"
    return "", info


def main() -> int:
    parser = argparse.ArgumentParser(description="URL'den HTML indir, Flame ile tara, JSON/TXT rapor üret.")
    parser.add_argument("url", help="Taranacak ilan veya iş ilanı URL'si")
    parser.add_argument("--format", choices=["json", "txt"], default="json", help="Rapor formatı")
    parser.add_argument("--out-dir", default="reports", help="Çıktı klasörü")
    parser.add_argument("--kind", default="job", choices=["auto", "job", "marketplace"], help="İlan türü")
    parser.add_argument("--title", default="", help="İlan başlığı biliniyorsa ekle")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = int(time.time())
    base = f"{stamp}_{safe_name(args.url)}"
    html_path = out_dir / f"{base}.html"
    report_path = out_dir / f"{base}.{args.format}"

    html_text, fetch_info = download_html(args.url)
    parsed_text = ""
    links = []
    if html_text:
        html_path.write_text(html_text, encoding="utf-8", errors="ignore")
        parsed_text, links = parse_html_file(str(html_path))

    notes = [
        f"HTML indirme durumu: {'başarılı' if fetch_info.get('ok') else 'başarısız'}",
        f"HTTP durum: {fetch_info.get('status')}",
        f"İndirme hatası: {fetch_info.get('error') or '-'}",
    ]
    data = AnalysisInput(
        url=args.url,
        pasted_text=parsed_text,
        notes="\n".join(notes),
        platform_hint="auto",
        allow_network_fetch=False,
        listing_title=args.title,
        listing_kind=args.kind,
    )
    result = RiskEngine().analyze(data)
    result.url_info["download"] = fetch_info
    result.url_info["downloaded_html_path"] = str(html_path) if html_text else ""
    result.url_info["extracted_links_count"] = len(links)

    if args.format == "json":
        payload = {
            "download": fetch_info,
            "downloaded_html_path": str(html_path) if html_text else "",
            "report_path": str(report_path),
            "result": result.to_dict(),
        }
        report_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    else:
        ReportWriter.write_txt(result, str(report_path))

    print(f"Rapor: {report_path}")
    if html_text:
        print(f"HTML: {html_path}")
    else:
        print(f"HTML indirilemedi: {fetch_info.get('error') or fetch_info.get('status')}")
    print(f"Karar: {result.verdict} | Skor: {result.risk_score}/100")
    print(f"İş ilanı: {result.listing_info.get('classification', '-')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
