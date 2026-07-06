# -*- coding: utf-8 -*-
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

from src.core.scanners import TextScanner, normalize_text, sha256_text, unique_list


EMAIL_PATTERN = re.compile(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", re.IGNORECASE)

ROLE_GROUPS = {
    "yazılım/IT": ["yazılım", "yazilim", "developer", "frontend", "backend", "full stack", "it", "bilgi işlem"],
    "dijital pazarlama": ["dijital pazarlama", "seo", "reklam", "google ads", "meta ads", "performans pazarlama"],
    "grafik tasarım": ["grafik tasarım", "grafik tasarim", "photoshop", "illustrator", "indesign", "canva", "görsel tasarım"],
    "sosyal medya": ["sosyal medya", "instagram", "facebook", "linkedin", "içerik paylaşımı", "icerik paylasimi"],
    "web/wordpress": ["wordpress", "web sitesi", "web yönetimi", "web yonetimi", "içerik girişi", "icerik girisi"],
    "satış/destek": ["satış", "satis", "müşteri", "musteri", "destek", "çağrı merkezi", "cagri merkezi"],
    "operasyon/lojistik": ["operasyon", "lojistik", "depo", "sevkiyat", "kurye"],
}

STALE_PATTERNS = [
    re.compile(r"(\d+)\s*(?:gün|gun)\s*(?:önce|once)", re.IGNORECASE),
    re.compile(r"(\d+)\s*(?:ay)\s*(?:önce|once)", re.IGNORECASE),
]


JOB_WORDS = [
    "iş ilanı", "is ilani", "personel", "eleman", "kariyer", "başvuru", "basvuru",
    "maaş", "maas", "prim", "sigorta", "sgk", "vardiya", "tam zamanlı",
    "part time", "freelance", "uzaktan", "home office", "evden çalışma",
    "evden calisma", "paketleme işi", "paketleme isi", "müşteri temsilcisi",
    "musteri temsilcisi", "çağrı merkezi", "cagri merkezi",
    "linkedin jobs", "kariyer.net", "yenibiris", "eleman.net", "işkur", "iskur",
    "indeed", "secretcv", "iş başvurusu", "is basvurusu", "ilan no",
]

FAKE_JOB_WORDS = [
    "ibanınızı kullanacağız", "ibaninizi kullanacagiz", "papara hesabı aç",
    "papara hesabi ac", "banka hesabını kullan", "banka hesabini kullan",
    "para transferi", "komisyon kazan", "hesabına para gelecek",
    "hesabina para gelecek", "dekont gönder", "dekont gonder",
    "ön ödeme", "on odeme", "başvuru ücreti", "basvuru ucreti",
    "evrak ücreti", "evrak ucreti", "sigorta ücreti", "sigorta ucreti",
    "eğitim ücreti", "egitim ucreti", "teminat", "kapora", "kimlik ön yüz",
    "kimlik on yuz", "onay kodu", "sms kodu", "whatsapp'tan başvur",
    "whatsapptan basvur", "telegramdan yaz", "hemen başla", "hemen basla",
]

LOW_QUALITY_WORDS = [
    "detaylar whatsapp", "detaylar wp", "dm gel", "sadece ciddi olanlar",
    "yüksek kazanç", "yuksek kazanc", "günlük ödeme", "gunluk odeme",
    "tecrübe şart değil", "tecrube sart degil", "yaş sınırı yok",
    "yas siniri yok", "öğrenci olur", "ogrenci olur", "acil eleman",
    "az çalış çok kazan", "az calis cok kazan",
]

LEGIT_JOB_WORDS = [
    "şirket adı", "sirket adi", "pozisyon", "departman", "lokasyon",
    "iş tanımı", "is tanimi", "aranan nitelikler", "sorumluluklar",
    "çalışma saatleri", "calisma saatleri", "yan haklar", "sgk",
    "resmi başvuru", "resmi basvuru", "kvkk", "insan kaynakları",
    "insan kaynaklari",
    "linkedin", "kariyer.net", "işkur", "iskur", "yenibiris", "eleman.net",
    "başvuru formu", "basvuru formu", "firma profili", "company profile",
]

JOB_BOARD_DOMAINS = {
    "linkedin.com": "linkedin",
    "kariyer.net": "kariyer",
    "yenibiris.com": "yenibiris",
    "eleman.net": "eleman",
    "iskur.gov.tr": "iskur",
    "indeed.com": "indeed",
    "secretcv.com": "secretcv",
    "isbul.net": "isbul",
    "jooble.org": "jooble",
    "glassdoor.com": "glassdoor",
    "remoteok.com": "remoteok",
    "sahibinden.com": "sahibinden",
}

JOB_PATH_WORDS = [
    "jobs", "job", "is-ilan", "is_ilan", "isilan", "ilan", "kariyer",
    "career", "careers", "basvuru", "başvuru", "eleman", "personel",
]

WORK_MODE_HINTS = {
    "remote": ["uzaktan", "home office", "evden çalışma", "evden calisma", "remote"],
    "hybrid": ["hibrit", "hybrid"],
    "onsite": ["ofis", "saha", "mağaza", "magaza", "şube", "sube"],
}

SALARY_PATTERNS = [
    re.compile(
        r"(?:maa[şs]|ücret|ucret|gelir|kazanç|kazanc)\D{0,24}"
        r"(\d{2,3}(?:[.\s]\d{3})+|\d{4,6})\s*(?:tl|try|₺)?",
        re.IGNORECASE,
    ),
    re.compile(
        r"(\d{2,3}(?:[.\s]\d{3})+|\d{4,6})\s*(?:tl|try|₺)",
        re.IGNORECASE,
    ),
]


@dataclass
class ListingSnapshot:
    created_at: str
    risk_score: int
    verdict: str
    fake_probability: int
    useless_probability: int
    quality_score: int
    text_hash: str
    extracted: Dict[str, Any] = field(default_factory=dict)


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _hits(norm: str, words: List[str]) -> List[str]:
    return unique_list([word for word in words if normalize_text(word) in norm])


def _extract_salary(text: str) -> List[int]:
    values: List[int] = []
    for pattern in SALARY_PATTERNS:
        for match in pattern.finditer(text or ""):
            raw = re.sub(r"\D", "", match.group(1))
            if not raw:
                continue
            try:
                value = int(raw)
            except ValueError:
                continue
            if 1_000 <= value <= 2_000_000:
                values.append(value)
    return unique_list(values)


def _work_mode(norm: str) -> str:
    for mode, words in WORK_MODE_HINTS.items():
        if _hits(norm, words):
            return mode
    return "unknown"


def _job_board_from_url(url: str) -> Dict[str, Any]:
    parsed = urlparse(url if "://" in (url or "") else "https://" + (url or ""))
    host = (parsed.hostname or "").lower()
    path = normalize_text(parsed.path or "")
    for domain, platform in JOB_BOARD_DOMAINS.items():
        if host == domain or host.endswith("." + domain):
            return {
                "is_known_job_board": True,
                "platform": platform,
                "host": host,
                "path_has_job_hint": any(word in path for word in JOB_PATH_WORDS),
            }
    return {
        "is_known_job_board": False,
        "platform": "unknown",
        "host": host,
        "path_has_job_hint": any(word in path for word in JOB_PATH_WORDS),
    }


def _classification(fake_probability: int, useless_probability: int, quality_score: int) -> str:
    if fake_probability >= 75:
        return "Sahte iş ilanı riski yüksek"
    if fake_probability >= 45:
        return "Şüpheli iş ilanı"
    if useless_probability >= 65:
        return "Gereksiz/spam ilan olabilir"
    if quality_score >= 70:
        return "Takip edilmeye değer"
    if quality_score >= 45:
        return "Doğrulama ile incelenebilir"
    return "Zayıf veya eksik ilan"


def _detected_roles(norm: str) -> List[str]:
    roles = []
    for role, words in ROLE_GROUPS.items():
        if any(normalize_text(word) in norm for word in words):
            roles.append(role)
    return roles


def _stale_days(text: str) -> Optional[int]:
    norm = normalize_text(text or "")
    for idx, pattern in enumerate(STALE_PATTERNS):
        match = pattern.search(norm)
        if not match:
            continue
        value = int(match.group(1))
        return value if idx == 0 else value * 30
    return None


def _stale_days_from_url(url: str) -> Optional[int]:
    parsed = urlparse(url if "://" in (url or "") else "https://" + (url or ""))
    params = parse_qs(parsed.query or "")
    for key in ("jobAge", "job_age", "age"):
        if key in params and params[key]:
            try:
                return int(float(params[key][0]))
            except ValueError:
                pass
    return None


def _query_title_hint(url: str) -> str:
    parsed = urlparse(url if "://" in (url or "") else "https://" + (url or ""))
    params = parse_qs(parsed.query or "")
    for key in ("ckey", "keywords", "q"):
        if key in params and params[key]:
            value = unquote(params[key][0]).strip()
            if value:
                return value
    return ""


def _decision(
    fake_probability: int,
    useless_probability: int,
    quality_score: int,
    overload_score: int,
    stale_days: Optional[int],
    asks_money_or_account: bool,
) -> Dict[str, Any]:
    reasons: List[str] = []
    if fake_probability >= 75 or asks_money_or_account:
        return {
            "apply_decision": "Başvurma",
            "decision_level": "danger",
            "decision_reason": "İlan para, IBAN/Papara, hesap kullandırma veya açık dolandırıcılık sinyali taşıyor.",
        }
    if fake_probability >= 45:
        return {
            "apply_decision": "Başvurma / önce doğrula",
            "decision_level": "danger",
            "decision_reason": "İlanda sahte veya kötü niyetli iş akışına benzeyen güçlü işaretler var.",
        }
    if stale_days is not None and stale_days >= 45:
        reasons.append(f"İlan yaklaşık {stale_days} gündür yayında görünüyor.")
    if overload_score >= 70:
        reasons.append("Tek pozisyona çok fazla farklı meslek/uzmanlık yüklenmiş.")
    elif overload_score >= 40:
        reasons.append("Rol kapsamı geniş; birden fazla iş aynı kişiden bekleniyor olabilir.")
    if useless_probability >= 65:
        reasons.append("İlan belirsiz, spam veya düşük kaliteli görünüyor.")
    if quality_score < 45:
        reasons.append("İlan bilgileri eksik veya doğrulanabilir ayrıntı az.")

    if reasons:
        return {
            "apply_decision": "Dikkatli başvur / önce sor",
            "decision_level": "warning",
            "decision_reason": " ".join(reasons),
        }
    if quality_score >= 70:
        return {
            "apply_decision": "Başvurulabilir",
            "decision_level": "positive",
            "decision_reason": "İlan yapılı, görev/nitelik/lokasyon gibi temel bilgiler dolu ve güçlü dolandırıcılık sinyali yok.",
        }
    return {
        "apply_decision": "Doğrula, sonra başvur",
        "decision_level": "neutral",
        "decision_reason": "Ağır risk yok ama ilan bilgileri karar vermek için tam güçlü değil.",
    }


def _clean_lines(text: str) -> List[str]:
    lines = []
    for line in (text or "").replace("\r", "\n").split("\n"):
        line = re.sub(r"\s+", " ", line).strip(" -•\t")
        if line:
            lines.append(line)
    return lines


def _first_match(patterns: List[str], text: str) -> str:
    for pattern in patterns:
        match = re.search(pattern, text or "", flags=re.IGNORECASE)
        if match:
            return re.sub(r"\s+", " ", match.group(1)).strip(" :-–")
    return ""


def _section_after(lines: List[str], headers: List[str], stop_headers: List[str]) -> List[str]:
    norm_headers = [normalize_text(item).rstrip(":") for item in headers]
    norm_stops = [normalize_text(item).rstrip(":") for item in stop_headers]
    started = False
    out: List[str] = []
    for line in lines:
        norm = normalize_text(line).rstrip(":")
        is_header = any(norm == header or norm.startswith(header + " ") for header in norm_headers)
        is_stop = any(norm == stop or norm.startswith(stop + " ") for stop in norm_stops)
        if started and is_stop:
            break
        if is_header:
            started = True
            tail = re.sub(r"^[^:]{2,45}:\s*", "", line).strip()
            if tail and normalize_text(tail) != norm:
                out.append(tail)
            continue
        if started:
            out.append(line)
    return out[:30]


def _extract_job_details(text: str, title: str, url: str) -> Dict[str, Any]:
    lines = _clean_lines(text)
    joined = "\n".join(lines)
    norm = normalize_text(joined)
    stop_headers = [
        "iş açıklaması", "is aciklamasi", "aranan nitelikler", "görev tanımı",
        "gorev tanimi", "tercih sebepleri", "biz ne sunuyoruz", "başvuru",
        "basvuru", "nitelikler", "sorumluluklar",
    ]

    inferred_title = title.strip()
    if not inferred_title:
        query_hint = _query_title_hint(url)
        if query_hint:
            inferred_title = query_hint
    if not inferred_title:
        generic_title_lines = {
            "is aciklamasi", "iş açıklaması", "aranan nitelikler", "gorev tanimi",
            "görev tanımı", "tercih sebepleri", "biz ne sunuyoruz", "basvuru", "başvuru",
            "ana içeriğe geç", "ana icerige gec", "linkedin", "iş ilanları", "is ilanlari",
            "kişiler", "kisiler", "learning", "oturum aç", "oturum ac", "hemen katıl", "hemen katil",
        }
        for line in lines[:8]:
            norm_line = normalize_text(line)
            if (
                norm_line in generic_title_lines
                or norm_line.startswith(("lokasyon", "calisma", "çalışma", "window.", "function", "var ", "const ", "let "))
                or "javascript" in norm_line
            ):
                continue
            if 8 <= len(line) <= 100:
                inferred_title = line
                break

    location = _first_match([
        r"Lokasyon\s*:\s*([^\n]+)",
        r"(?:Konum|Yer)\s*:\s*([^\n]+)",
        r"\b(Ankara|İstanbul|Istanbul|İzmir|Izmir|Bursa|Antalya|Konya|Adana|Kocaeli|Gebze)\b[^\n,]*",
    ], joined)
    work_type = _first_match([
        r"Çalışma Şekli\s*:\s*([^\n]+)",
        r"Calisma Sekli\s*:\s*([^\n]+)",
        r"Çalışma Türü\s*:\s*([^\n]+)",
    ], joined)

    qualifications = _section_after(lines, ["Aranan Nitelikler", "Nitelikler"], stop_headers)
    responsibilities = _section_after(lines, ["Görev Tanımı", "Gorev Tanimi", "Sorumluluklar"], stop_headers)
    preferred = _section_after(lines, ["Tercih Sebepleri", "Tercihen"], stop_headers)
    benefits = _section_after(lines, ["Biz Ne Sunuyoruz", "Yan Haklar"], stop_headers)
    application = _section_after(lines, ["Başvuru", "Basvuru"], stop_headers)

    tools = _hits(norm, [
        "wordpress", "seo", "adobe photoshop", "photoshop", "illustrator",
        "indesign", "canva", "linkedin", "instagram", "facebook",
        "sosyal medya", "grafik tasarım", "grafik tasarim",
    ])
    sectors = _hits(norm, [
        "medikal", "ambulans", "otomotiv", "ihracat", "özel amaçlı araç",
        "ozel amacli arac", "dijital pazarlama", "grafik tasarım", "grafik tasarim",
    ])
    languages = _hits(norm, ["ingilizce", "english", "almanca", "arapça", "arapca"])
    application_channels = []
    emails = unique_list(EMAIL_PATTERN.findall(joined))
    if emails:
        application_channels.append("e-posta")
    if "portfolio" in norm or "portfolyo" in norm:
        application_channels.append("portfolyo")
    if "cv" in norm:
        application_channels.append("cv")

    return {
        "title": inferred_title,
        "location": location,
        "work_type": work_type,
        "qualifications": qualifications[:12],
        "responsibilities": responsibilities[:12],
        "preferred": preferred[:10],
        "benefits": benefits[:10],
        "application": application[:8],
        "application_channels": unique_list(application_channels),
        "emails": emails[:5],
        "tools": tools[:20],
        "sectors": sectors[:20],
        "languages": languages[:10],
        "source_url": url,
    }


class JobListingAnalyzer:
    @staticmethod
    def analyze(url: str, text: str, notes: str = "", title: str = "", kind: str = "auto") -> Dict[str, Any]:
        combined = "\n".join([title or "", url or "", text or "", notes or ""])
        norm = normalize_text(combined)
        scan = TextScanner.scan(combined)
        board = _job_board_from_url(url)

        job_hits = _hits(norm, JOB_WORDS)
        fake_hits = _hits(norm, FAKE_JOB_WORDS)
        low_hits = _hits(norm, LOW_QUALITY_WORDS)
        legit_hits = _hits(norm, LEGIT_JOB_WORDS)
        salaries = _extract_salary(combined)
        work_mode = _work_mode(norm)
        details = _extract_job_details(text, title, url)
        role_groups = _detected_roles(norm)
        requirement_count = len(details.get("qualifications", [])) + len(details.get("responsibilities", [])) + len(details.get("preferred", []))
        overload_score = 0
        overload_score += max(0, len(role_groups) - 2) * 18
        overload_score += 20 if requirement_count >= 24 else 10 if requirement_count >= 16 else 0
        overload_score += 15 if len(details.get("tools", [])) >= 8 else 0
        overload_score = max(0, min(100, overload_score))
        stale = _stale_days_from_url(url)
        if stale is None:
            stale = _stale_days(combined)

        content_length = len("\n".join([title or "", text or ""]).strip())
        looks_like_job = bool(job_hits) or kind == "job" or board["is_known_job_board"] or board["path_has_job_hint"]
        has_company_signal = bool(re.search(r"\b(?:ltd|limited|a\.ş|anonim|şti|şirket|sirket|holding|firmamız|firmamiz|kurumumuz)\b", norm))
        has_location_signal = bool(details.get("location")) or bool(re.search(r"\b(?:istanbul|ankara|izmir|bursa|antalya|konya|adana|kocaeli|gebze|remote|uzaktan|ofis)\b", norm))
        has_role_signal = bool(job_hits) or bool(re.search(r"\b(?:developer|yazilim|satış|satis|muhasebe|operasyon|destek|kurye|garson|kasiyer)\b", norm))
        has_description_signal = bool(details.get("qualifications")) or bool(details.get("responsibilities"))
        asks_money_or_account = bool(fake_hits) or bool(scan.get("ibans")) or "papara" in norm

        fake_probability = 0
        fake_probability += min(45, len(fake_hits) * 12)
        fake_probability += 28 if scan.get("ibans") else 0
        fake_probability += 20 if "papara" in norm or "banka hesab" in norm else 0
        fake_probability += 18 if scan.get("off_platform_keywords") else 0
        fake_probability += 15 if scan.get("pressure_keywords") else 0
        fake_probability += 12 if salaries and max(salaries) >= 120_000 and work_mode == "remote" else 0
        fake_probability += 10 if not has_company_signal and looks_like_job else 0
        fake_probability += 8 if looks_like_job and board["platform"] == "unknown" and "whatsapp" in norm else 0
        if has_description_signal and has_location_signal and not fake_hits and not scan.get("ibans"):
            fake_probability -= 18

        useless_probability = 0
        useless_probability += min(45, len(low_hits) * 10)
        useless_probability += 18 if looks_like_job and len(combined) < 220 else 0
        useless_probability += 15 if not has_role_signal and looks_like_job else 0
        useless_probability += 12 if not has_location_signal and work_mode == "unknown" and looks_like_job else 0
        useless_probability += 12 if "sadece ciddi" in norm or "dm gel" in norm else 0
        useless_probability += 25 if looks_like_job and content_length < 80 else 0
        useless_probability += min(30, overload_score // 2)
        useless_probability += 20 if stale is not None and stale >= 45 else 0

        quality_score = 45
        quality_score += min(30, len(legit_hits) * 7)
        quality_score += 10 if board["is_known_job_board"] else 0
        quality_score += 8 if has_company_signal else 0
        quality_score += 8 if has_location_signal else 0
        quality_score += 8 if salaries else 0
        quality_score += 8 if work_mode != "unknown" else 0
        quality_score += 12 if details.get("qualifications") else 0
        quality_score += 12 if details.get("responsibilities") else 0
        quality_score += 6 if details.get("application_channels") else 0
        quality_score += 6 if details.get("tools") else 0
        quality_score -= 20 if looks_like_job and content_length < 80 else 0
        quality_score -= min(25, overload_score // 3)
        quality_score -= 12 if stale is not None and stale >= 45 else 0
        quality_score -= min(40, fake_probability // 2)
        quality_score -= min(25, useless_probability // 3)

        fake_probability = max(0, min(100, fake_probability))
        useless_probability = max(0, min(100, useless_probability))
        quality_score = max(0, min(100, quality_score))

        missing = []
        if looks_like_job and not has_company_signal:
            missing.append("şirket/kurum bilgisi")
        if looks_like_job and not has_location_signal:
            missing.append("lokasyon veya çalışma modeli")
        if looks_like_job and not salaries:
            missing.append("maaş/ücret aralığı")
        if looks_like_job and not legit_hits and not has_description_signal:
            missing.append("iş tanımı ve nitelikler")
        if looks_like_job and content_length < 80:
            missing.append("ilan metni okunamadı veya çok kısa")

        red_flags = []
        yellow_flags = []
        if asks_money_or_account:
            red_flags.append("IBAN/Papara/banka hesabı veya para akışı istiyor")
        if fake_hits:
            red_flags.append("Sahte iş ilanlarında görülen kelimeler var")
        if overload_score >= 70:
            yellow_flags.append("Tek ilana çok fazla meslek/uzmanlık yüklenmiş")
        elif overload_score >= 40:
            yellow_flags.append("Rol kapsamı geniş; beklentiler görüşmede netleştirilmeli")
        if stale is not None and stale >= 45:
            yellow_flags.append(f"İlan uzun süredir yayında görünüyor ({stale} gün)")
        if not salaries:
            yellow_flags.append("Maaş/ücret aralığı belirtilmemiş")

        decision = _decision(
            fake_probability,
            useless_probability,
            quality_score,
            overload_score,
            stale,
            asks_money_or_account,
        )

        return {
            "is_job_listing": looks_like_job,
            "classification": _classification(fake_probability, useless_probability, quality_score) if looks_like_job else "İş ilanı gibi görünmüyor",
            **decision,
            "source_platform": board["platform"],
            "source_host": board["host"],
            "is_known_job_board": board["is_known_job_board"],
            "content_length": content_length,
            "fake_probability": fake_probability,
            "useless_probability": useless_probability,
            "quality_score": quality_score,
            "overload_score": overload_score,
            "detected_roles": role_groups,
            "requirement_count": requirement_count,
            "stale_days": stale,
            "red_flags": red_flags,
            "yellow_flags": yellow_flags,
            "work_mode": work_mode,
            "details": details,
            "salary_values": salaries[:5],
            "job_keywords": job_hits[:20],
            "fake_job_keywords": fake_hits[:20],
            "low_quality_keywords": low_hits[:20],
            "legit_keywords": legit_hits[:20],
            "missing_fields": missing,
            "asks_money_or_account": asks_money_or_account,
            "text_hash": sha256_text(combined) if combined else "",
        }


class ListingMonitor:
    def __init__(self, path: Optional[Path] = None) -> None:
        root = Path(__file__).resolve().parents[2]
        self.path = path or (root / "data" / "listing_watch.json")

    def _load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "items": {}}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {"version": 1, "items": {}}

    def _save(self, db: Dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(db, ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def key_for(url: str, text: str, title: str = "") -> str:
        base = (url or "").strip().lower() or "\n".join((title or "", (text or "")[:500]))
        return sha256_text(base)[:20]

    def record(self, data: Any, result: Any, listing_info: Dict[str, Any]) -> Dict[str, Any]:
        db = self._load()
        items = db.setdefault("items", {})
        key = self.key_for(getattr(data, "url", ""), getattr(data, "pasted_text", ""), getattr(data, "listing_title", ""))
        previous = items.get(key)

        snapshot = ListingSnapshot(
            created_at=_now(),
            risk_score=int(getattr(result, "risk_score", 0)),
            verdict=str(getattr(result, "verdict", "")),
            fake_probability=int(listing_info.get("fake_probability", 0)),
            useless_probability=int(listing_info.get("useless_probability", 0)),
            quality_score=int(listing_info.get("quality_score", 0)),
            text_hash=str(listing_info.get("text_hash", "")),
            extracted={
                "salary_values": listing_info.get("salary_values", []),
                "work_mode": listing_info.get("work_mode", "unknown"),
                "missing_fields": listing_info.get("missing_fields", []),
            },
        )

        changes = self._changes(previous, snapshot)
        history = list(previous.get("history", [])) if previous else []
        history.append(asdict(snapshot))
        history = history[-20:]

        items[key] = {
            "key": key,
            "url": getattr(data, "url", ""),
            "title": getattr(data, "listing_title", "") or self._guess_title(getattr(data, "pasted_text", "")),
            "platform": getattr(data, "platform_hint", ""),
            "first_seen": previous.get("first_seen") if previous else snapshot.created_at,
            "last_seen": snapshot.created_at,
            "classification": listing_info.get("classification", ""),
            "latest": asdict(snapshot),
            "changes": changes,
            "history": history,
        }
        self._save(db)

        return {
            "watch_key": key,
            "first_seen": items[key]["first_seen"],
            "last_seen": items[key]["last_seen"],
            "seen_count": len(history),
            "changes": changes,
            "store_path": str(self.path),
        }

    def list_items(self) -> List[Dict[str, Any]]:
        db = self._load()
        items = list(db.get("items", {}).values())
        items.sort(key=lambda item: item.get("last_seen", ""), reverse=True)
        return items

    @staticmethod
    def _guess_title(text: str) -> str:
        for line in (text or "").splitlines():
            line = line.strip()
            if 8 <= len(line) <= 90:
                return line
        return "Başlıksız ilan"

    @staticmethod
    def _changes(previous: Optional[Dict[str, Any]], snapshot: ListingSnapshot) -> List[str]:
        if not previous:
            return ["İlan ilk kez izlemeye alındı."]
        old = previous.get("latest", {})
        changes = []
        if old.get("text_hash") and old.get("text_hash") != snapshot.text_hash:
            changes.append("İlan metni değişmiş.")
        if int(old.get("risk_score", 0)) != snapshot.risk_score:
            changes.append(f"Risk skoru {old.get('risk_score', 0)} -> {snapshot.risk_score}.")
        if int(old.get("fake_probability", 0)) != snapshot.fake_probability:
            changes.append(f"Sahte ilan olasılığı {old.get('fake_probability', 0)} -> {snapshot.fake_probability}.")
        old_salary = old.get("extracted", {}).get("salary_values", [])
        new_salary = snapshot.extracted.get("salary_values", [])
        if old_salary != new_salary:
            changes.append("Maaş/ücret bilgisi değişmiş.")
        return changes or ["Önemli değişiklik yok."]
