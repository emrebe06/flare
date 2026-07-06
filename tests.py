# -*- coding: utf-8 -*-
"""
Focused regression checks for Flame & Starfall Core.
Run with: python tests.py
"""

import tempfile
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

import main  # noqa: F401 - import must not fail; GUI is not started on import.
from main import cli_analyze
from src.core.engine import RiskEngine
from src.core.models import AnalysisInput, AnalysisResult, RiskSignal
from src.core.scanners import DomainTools, TextScanner
from src.utils.reporter import ReportWriter


def signal_codes(result):
    return {signal.code for signal in result.signals}


def test_cpp_or_python_scanner_detects_blacklist_fixtures():
    text = "IBAN TR120000000000000000000000 ve WhatsApp 0555 555 55 55"
    scan = TextScanner.scan(text)
    assert "TR120000000000000000000000" in scan.get("ibans", [])
    assert scan.get("phones"), "phone scanner should detect Turkish mobile numbers"

    result = RiskEngine().analyze(AnalysisInput(pasted_text=text))
    codes = signal_codes(result)
    assert "IBAN_FOUND" in codes
    assert "BLACKLISTED_IBAN_FOUND" in codes
    assert "BLACKLISTED_PHONE_FOUND" in codes


def test_social_engineering_script_is_flagged():
    sample = (
        "Müşteri hizmetleri hesabınız kısıtlandı dedi. "
        "Kurye sigortası için onay kodu ve emanet ödeme gerekiyor."
    )
    result = RiskEngine().analyze(AnalysisInput(pasted_text=sample))
    codes = signal_codes(result)
    assert "SOCIAL_ENGINEERING_SCRIPT" in codes
    assert "SCAM_PATTERN_REGEX" in codes


def test_xmll_job_iban_mule_scenario_is_flagged():
    sample = (
        "Evden paketleme iş ilanı için başvuru alıyoruz. "
        "Ödemeler IBAN üzerinden yapılacak, Papara hesabı açıp para transferi başına komisyon kazanacaksınız."
    )
    result = RiskEngine().analyze(AnalysisInput(pasted_text=sample))
    codes = signal_codes(result)
    assert "ML_SCENARIO_JOB_IBAN_MULE" in codes
    assert result.ml_info.get("model_loaded") is True
    if result.ml_info.get("numpy", {}).get("available"):
        assert result.ml_info.get("numpy", {}).get("feature_dim", 0) >= 8


def test_real_site_can_still_have_malicious_listing_context():
    result = RiskEngine().analyze(
        AnalysisInput(
            url="https://www.sahibinden.com/ilan/vasita-otomobil",
            pasted_text="İlan için kapora at, WhatsApp'tan yaz. Elden olmaz, IBAN veriyorum dekont at, acele başkası alacak.",
            platform_hint="sahibinden",
        )
    )
    codes = signal_codes(result)
    assert "OFFICIAL_DOMAIN" in codes
    assert "TRUSTED_SITE_MALICIOUS_LISTING_CONTEXT" in codes
    assert "ML_SCENARIO_TRUSTED_SITE_MALICIOUS_LISTING" in codes


def test_fake_site_with_iban_payment_context_is_critical():
    result = RiskEngine().analyze(
        AnalysisInput(
            url="https://sahibinden-odeme-onay.xyz/guvenli-odeme",
            pasted_text="Güvenli ödeme için IBAN üzerinden havale yapın, dekontu WhatsApp'tan gönderin.",
            platform_hint="sahibinden",
        )
    )
    codes = signal_codes(result)
    assert "BRAND_IN_NON_OFFICIAL_DOMAIN" in codes
    assert "FAKE_SITE_PAYMENT_FRAUD_CONTEXT" in codes
    assert "ML_SCENARIO_FAKE_SITE_IBAN_FRAUD" in codes


def test_private_network_fetch_is_blocked():
    blocked = DomainTools.fetch_headers("http://127.0.0.1:8080/admin")
    assert blocked["attempted"] is True
    assert blocked["ok"] is False
    assert "Blocked private" in blocked["error"]
    assert DomainTools.is_blocked_network_url("http://localhost:8000") is True
    assert DomainTools.is_blocked_network_url("http://169.254.169.254/latest/meta-data") is True


def test_html_report_escapes_untrusted_content():
    result = AnalysisResult(
        app="Flame",
        version="test",
        created_at="2026-07-06T00:00:00+03:00",
        risk_score=80,
        verdict="<script>alert(1)</script>",
        summary="<img src=x onerror=alert(1)>",
        signals=[
            RiskSignal(
                code="XSS_TEST",
                title="<script>alert(2)</script>",
                description="<b onclick=alert(3)>bad</b>",
                points=10,
                severity="high",
                evidence={"payload": "<script>alert(4)</script>"},
            )
        ],
        url_info={},
        text_info={},
        ml_info={},
        recommendations=["<a href=javascript:alert(5)>click</a>"],
        safety_notice="<svg onload=alert(6)>",
    )

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "report.html"
        ReportWriter.write_html(result, str(path))
        html = path.read_text(encoding="utf-8")

    assert "<script>alert" not in html
    assert "<a href=" not in html
    assert "&lt;script&gt;alert" in html
    assert "&lt;svg onload" in html


def test_official_domain_remains_low_risk():
    result = RiskEngine().analyze(
        AnalysisInput(
            url="https://www.sahibinden.com/ilan/emlak-konut-satilik",
            pasted_text="Resmi platform içi güvenli ödeme. Kesinlikle dışarıdan ödeme kabul edilmez.",
            platform_hint="sahibinden",
        )
    )
    assert result.risk_score < 20
    assert result.verdict == "Düşük risk"


def test_cli_splits_url_from_following_text():
    output = StringIO()
    with redirect_stdout(output):
        assert cli_analyze(["https://trendyol-cuzdan-onay.xyz/odeme", "WhatsApp", "onay", "kodu"]) == 0
    assert '"host": "trendyol-cuzdan-onay.xyz"' in output.getvalue()


def run_all():
    tests = [
        test_cpp_or_python_scanner_detects_blacklist_fixtures,
        test_social_engineering_script_is_flagged,
        test_xmll_job_iban_mule_scenario_is_flagged,
        test_real_site_can_still_have_malicious_listing_context,
        test_fake_site_with_iban_payment_context_is_critical,
        test_private_network_fetch_is_blocked,
        test_html_report_escapes_untrusted_content,
        test_official_domain_remains_low_risk,
        test_cli_splits_url_from_following_text,
    ]
    for test in tests:
        test()
        print(f"[OK] {test.__name__}")


if __name__ == "__main__":
    run_all()
