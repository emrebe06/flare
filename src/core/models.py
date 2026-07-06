# -*- coding: utf-8 -*-
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

APP_NAME = "Flame"
APP_VERSION = "0.2.0"
CORE_TECH_NAME = "Starfall"

SAFE_NOTICE = (
    "Bu araç pasif analiz yapar. Kesin hüküm vermez. "
    "Şüpheli durumlarda ödeme yapmayın, ekran görüntülerini saklayın ve resmi kanallara başvurun."
)

OFFICIAL_DOMAINS = {
    "sahibinden": [
        "sahibinden.com",
        "www.sahibinden.com",
        "secure.sahibinden.com",
        "banaozel.sahibinden.com",
    ],
    "dolap": [
        "dolap.com",
        "www.dolap.com",
    ],
    "letgo": [
        "letgo.com",
        "www.letgo.com",
    ],
    "trendyol": [
        "trendyol.com",
        "www.trendyol.com",
        "m.trendyol.com",
    ],
    "hepsiburada": [
        "hepsiburada.com",
        "www.hepsiburada.com",
    ],
    "yemeksepeti": [
        "yemeksepeti.com",
        "www.yemeksepeti.com",
    ],
    "getir": [
        "getir.com",
        "www.getir.com",
    ],
    "n11": [
        "n11.com",
        "www.n11.com",
    ],
    "ciceksepeti": [
        "ciceksepeti.com",
        "www.ciceksepeti.com",
    ],
    "pazarama": [
        "pazarama.com",
        "www.pazarama.com",
    ]
}

MARK_NAMES = {
    "sahibinden": [
        "sahibinden",
        "s-param",
        "paramguvende",
        "param-guvende",
        "sparam",
        "sahibindencom",
    ],
    "dolap": [
        "dolap",
        "dolap-guvenli",
        "dolap-odeme",
    ],
    "letgo": [
        "letgo",
        "letgo-odeme",
        "letgo-guvenli",
    ],
    "trendyol": [
        "trendyol",
        "trendyol-odeme",
        "trendyol-destek",
        "trendyol-cuzdan",
    ],
    "hepsiburada": [
        "hepsiburada",
        "hepsipay",
        "hepsiburada-odeme",
    ],
    "yemeksepeti": [
        "yemeksepeti",
        "yemeksepeti-odeme",
        "yemeksepeti-cuzdan",
    ],
    "getir": [
        "getir",
        "getir-odeme",
        "getir-cuzdan",
    ],
    "n11": [
        "n11",
        "n11-odeme",
    ],
    "ciceksepeti": [
        "ciceksepeti",
        "ciceksepeti-odeme",
    ],
    "pazarama": [
        "pazarama",
        "pazarama-odeme",
    ]
}

SUSPICIOUS_TLDS = {
    "shop", "top", "xyz", "click", "live", "site", "online", "store",
    "icu", "cyou", "rest", "monster", "beauty", "quest", "bond", "info",
    "cc", "tk", "ml", "ga", "cf", "gq"
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "soo.gd",
    "rebrand.ly", "shorturl.at", "rb.gy", "lnkd.in",
}

PAYMENT_WORDS = [
    "iban", "havale", "eft", "kapora", "odeme", "ödeme", "kart bilgisi",
    "kredi karti", "kredi kartı", "cvv", "3d secure", "dekont",
    "para gonder", "para gönder", "fast", "papara", "ininal",
]

PHISHING_WORDS = [
    "param guvende", "param güvende", "s-param", "guvenli odeme", "güvenli ödeme",
    "odeme onay", "ödeme onay", "ilan onay", "kargo onay", "kargo ucreti",
    "kargo ücreti", "satici onayi", "satıcı onayı", "hesap dogrulama",
    "hesap doğrulama", "kimlik dogrulama", "kimlik doğrulama",
    "siparis onay", "sipariş onay", "cuzdanim", "cüzdanım", "cuzdan onay",
]

PRESSURE_WORDS = [
    "hemen", "son fiyat", "acele", "bugun", "bugün", "simdi", "şimdi",
    "ayirdim", "ayırdım", "son urun", "son ürün", "kapora at",
    "bekletmem", "baskasi alacak", "başkası alacak",
]

OFF_PLATFORM_WORDS = [
    "whatsapp", "wp", "telegram", "dm", "instagram", "linkten devam",
    "buradan yaz", "uygulama disi", "uygulama dışı",
]

SOCIAL_ENGINEERING_WORDS = [
    "kurye gelecek", "kurye yonlendirdim", "kurye yönlendirdim",
    "hesap askida", "hesap askıda", "hesabiniz kisitlandi", "hesabınız kısıtlandı",
    "musteri hizmetleri", "müşteri hizmetleri", "canli destek", "canlı destek",
    "tek kullanimlik kod", "tek kullanımlık kod", "sms kodu", "onay kodu",
    "dogrulama kodu", "doğrulama kodu", "iban teyit", "sigorta ucreti",
    "sigorta ücreti", "kargo sigortasi", "kargo sigortası", "emanet odeme",
    "emanet ödeme", "escrow", "kapida guvenli odeme", "kapıda güvenli ödeme",
]

COMMON_SCAM_PATTERNS = [
    r"param\s*g[üu]vende",
    r"s[-\s]?param",
    r"iban\s*[:\-]?",
    r"tr\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}",
    r"whats\s?app",
    r"link(?:ten|e)?\s+(?:odeme|ödeme|devam|gir)",
    r"(?:havale|eft)\s+(?:yap|gonder|gönder)",
    r"(?:kapora|on odeme|ön ödeme)\s+(?:at|gonder|gönder)",
    r"(?:sms|onay|do[ğg]rulama)\s*kodu",
    r"(?:kurye|kargo)\s+(?:sigortas[ıi]|ucreti|ücreti)",
    r"(?:hesap|ilan)\s+(?:ask[ıi]da|kisitlandi|kısıtlandı)",
]

@dataclass
class RiskSignal:
    code: str
    title: str
    description: str
    points: int
    severity: str = "info"
    evidence: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AnalysisInput:
    url: str = ""
    pasted_text: str = ""
    notes: str = ""
    platform_hint: str = "sahibinden"
    allow_network_fetch: bool = False

@dataclass
class AnalysisResult:
    app: str
    version: str
    created_at: str
    risk_score: int
    verdict: str
    summary: str
    signals: List[RiskSignal]
    url_info: Dict[str, Any]
    text_info: Dict[str, Any]
    ml_info: Dict[str, Any]
    recommendations: List[str]
    safety_notice: str = SAFE_NOTICE

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
