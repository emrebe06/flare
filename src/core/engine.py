# -*- coding: utf-8 -*-
from pathlib import Path
from typing import List, Dict, Any, Iterable
from src.core.models import (
    APP_NAME, APP_VERSION, SAFE_NOTICE, AnalysisInput, AnalysisResult,
    RiskSignal, OFFICIAL_DOMAINS, SUSPICIOUS_TLDS, SHORTENER_DOMAINS,
    PAYMENT_WORDS, PHISHING_WORDS, PRESSURE_WORDS, OFF_PLATFORM_WORDS,
    SOCIAL_ENGINEERING_WORDS,
    COMMON_SCAM_PATTERNS
)
from src.core.scanners import DomainTools, TextScanner, safe_strip, sha256_text, normalize_text
from src.core.listing_monitor import JobListingAnalyzer, ListingMonitor

def clamp(value: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, int(value)))

class RiskEngine:
    def analyze(self, data: AnalysisInput) -> AnalysisResult:
        signals: List[RiskSignal] = []
        url_info: Dict[str, Any] = {}
        fetched_text = ""

        # Paketli şüpheli veri kontrolü (fallback ile)
        is_blacklisted_iban = False
        is_blacklisted_phone = False
        try:
            from src.core.bindings import starfall_check_iban, starfall_check_phone
        except Exception:
            starfall_check_iban = None
            starfall_check_phone = None

        if safe_strip(data.url):
            url_info = DomainTools.parse_url(data.url)
            detected_platform = DomainTools.detect_platform(url_info.get("host", ""))
            effective_platform = detected_platform if detected_platform != "unknown" else data.platform_hint
            url_info["detected_platform"] = detected_platform
            url_info["effective_platform"] = effective_platform
            signals.extend(self._analyze_url(url_info, effective_platform))

            if data.allow_network_fetch:
                headers_info = DomainTools.fetch_headers(url_info["normalized"])
                url_info["network"] = headers_info
                if headers_info.get("sample_text"):
                    fetched_text = headers_info["sample_text"]
                if headers_info.get("final_url") and headers_info.get("final_url") != url_info["normalized"]:
                    final = DomainTools.parse_url(headers_info["final_url"])
                    url_info["final_url_info"] = final
                    if final.get("host") != url_info.get("host"):
                        signals.append(RiskSignal(
                            code="REDIRECT_DIFFERENT_HOST",
                            title="Farklı domaine yönlendirme",
                            description="Bağlantı açıldığında farklı bir host adına yönleniyor.",
                            points=15,
                            severity="medium",
                            evidence={"from": url_info.get("host"), "to": final.get("host")},
                        ))
                host = url_info.get("host") or ""
                if host:
                    ssl_data = DomainTools.ssl_info(host)
                    url_info["ssl"] = ssl_data
                    
                    # Akıllı SSL Analizi
                    is_official = DomainTools.is_official(host, effective_platform)
                    if ssl_data.get("ok") and ssl_data.get("is_free_ssl") and not is_official:
                        signals.append(RiskSignal(
                            code="FREE_SSL_ON_SUSPICIOUS_DOMAIN",
                            title="Şüpheli domainde ücretsiz SSL kullanımı",
                            description="Sitenin HTTPS olması güvenli olduğunu göstermez. Ücretsiz/otomatik sertifika sağlayıcısı tespit edildi.",
                            points=15,
                            severity="medium",
                            evidence={"issuer": ssl_data.get("issuer")},
                        ))
            else:
                url_info["network"] = {"attempted": False, "note": "Ağ taraması kapalı."}

        combined_text = "\n".join([
            data.url or "",
            data.pasted_text or "",
            data.notes or "",
            fetched_text or "",
        ])
        text_info = TextScanner.scan(combined_text)
        effective_platform = url_info.get("effective_platform", data.platform_hint) if url_info else data.platform_hint
        signals.extend(self._analyze_text(text_info, effective_platform, url_info))
        ml_info = self._analyze_ml(combined_text)
        signals.extend(self._signals_from_ml(ml_info))
        signals.extend(self._contextual_site_intent_signals(url_info, ml_info, signals))
        listing_info = JobListingAnalyzer.analyze(
            data.url,
            data.pasted_text,
            data.notes,
            data.listing_title,
            data.listing_kind,
        )
        signals.extend(self._signals_from_listing_info(listing_info))
        signals = self._filter_job_listing_false_positives(signals, listing_info)

        # Paketli şüpheli veri sorguları
        ibans = text_info.get("ibans", [])
        phones = text_info.get("phones", [])
        if starfall_check_iban:
            for iban in ibans:
                if starfall_check_iban(iban):
                    is_blacklisted_iban = True
                    break
        if starfall_check_phone:
            for phone in phones:
                if starfall_check_phone(phone):
                    is_blacklisted_phone = True
                    break

        if is_blacklisted_iban:
            signals.append(RiskSignal(
                code="BLACKLISTED_IBAN_FOUND",
                title="İhbar edilmiş şüpheli IBAN",
                description="Bu IBAN daha önce dolandırıcılık bildirimlerinde yer almıştır!",
                points=45,
                severity="critical",
            ))
        if is_blacklisted_phone:
            signals.append(RiskSignal(
                code="BLACKLISTED_PHONE_FOUND",
                title="İhbar edilmiş şüpheli telefon",
                description="Bu telefon numarası daha önce dolandırıcılık bildirimlerinde yer almıştır!",
                points=40,
                severity="critical",
            ))

        risk_score = clamp(sum(s.points for s in signals))
        verdict = self._verdict(risk_score)
        summary = self._summary(verdict, risk_score, signals)
        recs = self._recommendations(risk_score, signals)
        if listing_info.get("is_job_listing") or data.listing_kind == "job":
            try:
                result_stub = type("ResultStub", (), {"risk_score": risk_score, "verdict": verdict})()
                listing_info["monitor"] = ListingMonitor().record(data, result_stub, listing_info)
            except Exception as exc:
                listing_info["monitor"] = {"error": f"{type(exc).__name__}: {exc}"}

        return AnalysisResult(
            app=APP_NAME,
            version=APP_VERSION,
            created_at=now_iso_string(),
            risk_score=risk_score,
            verdict=verdict,
            summary=summary,
            signals=signals,
            url_info=url_info,
            text_info=text_info,
            ml_info=ml_info,
            listing_info=listing_info,
            recommendations=recs,
        )

    def _analyze_ml(self, text: str) -> Dict[str, Any]:
        data_dir = Path(__file__).resolve().parents[2] / "data"
        large_model = data_dir / "flame_probability.xmll"
        model_path = large_model if large_model.exists() else data_dir / "fraud_scenarios.xmll"
        try:
            from src.core.bindings import starfall_ml_analyze
            ml_info = starfall_ml_analyze(text, str(model_path))
        except Exception as exc:
            ml_info = {"model_loaded": False, "error": f"{type(exc).__name__}: {exc}", "features": [], "scenarios": []}

        features = ml_info.get("features", [])
        try:
            import numpy as np
            values = np.array([float(item.get("value", 0.0)) for item in features], dtype=np.float32)
            max_value = float(values.max()) if values.size else 0.0
            normalized = (values / max_value).tolist() if max_value > 0 else values.tolist()
            ml_info["numpy"] = {
                "available": True,
                "feature_dim": int(values.size),
                "feature_sum": float(values.sum()) if values.size else 0.0,
                "feature_norm": float(np.linalg.norm(values)) if values.size else 0.0,
                "normalized_vector": normalized,
            }
        except Exception as exc:
            ml_info["numpy"] = {"available": False, "error": f"{type(exc).__name__}: {exc}"}
        return ml_info

    def _signals_from_ml(self, ml_info: Dict[str, Any]) -> List[RiskSignal]:
        signals: List[RiskSignal] = []
        scenarios = ml_info.get("scenarios", [])
        for scenario in scenarios[:4]:
            score = float(scenario.get("score", 0.0))
            threshold = float(scenario.get("threshold", 1.0))
            if score < threshold:
                continue
            severity = scenario.get("severity", "high")
            points = 35 if severity == "critical" else 25
            signals.append(RiskSignal(
                code=f"ML_SCENARIO_{str(scenario.get('id', 'unknown')).upper()}",
                title=scenario.get("title", "Fraud scenario"),
                description="Starfall ML senaryo modeli bu metinde birleşik dolandırıcılık akışı olabileceğini işaretledi.",
                points=points,
                severity=severity,
                evidence={
                    "score": round(score, 2),
                    "threshold": threshold,
                    "hits": scenario.get("hits", [])[:12],
                    "model_loaded": ml_info.get("model_loaded", False),
                },
            ))
        return signals

    def _contextual_site_intent_signals(
        self,
        url_info: Dict[str, Any],
        ml_info: Dict[str, Any],
        signals: List[RiskSignal],
    ) -> List[RiskSignal]:
        if not url_info:
            return []

        out: List[RiskSignal] = []
        host = url_info.get("host", "")
        official = any(signal.code == "OFFICIAL_DOMAIN" for signal in signals)
        fake_or_suspicious_site = any(signal.code in {
            "BRAND_IN_NON_OFFICIAL_DOMAIN",
            "LOOKALIKE_DOMAIN",
            "RISKY_TLD",
            "PUNYCODE_DOMAIN",
            "IP_AS_HOST",
        } for signal in signals)
        scenario_ids = {
            str(item.get("id", "")): item
            for item in ml_info.get("scenarios", [])
            if float(item.get("score", 0.0)) >= float(item.get("threshold", 1.0))
        }

        listing_risk_ids = {
            "trusted_site_malicious_listing",
            "listing_advance_payment",
            "malicious_listing_owner",
            "job_iban_mule",
            "job_upfront_fee",
        }
        if official and scenario_ids.keys() & listing_risk_ids:
            out.append(RiskSignal(
                code="TRUSTED_SITE_MALICIOUS_LISTING_CONTEXT",
                title="Gerçek sitede riskli ilan veya ilan sahibi",
                description="Domain resmi görünüyor; ancak ilan/metin içeriği platform dışı ödeme, IBAN, kapora, hesap kullandırma veya kötü niyetli ilan sahibi sinyali taşıyor.",
                points=35,
                severity="critical",
                evidence={"host": host, "matched_scenarios": sorted(scenario_ids.keys() & listing_risk_ids)},
            ))

        scam_site_ids = {"fake_site_iban_fraud", "fake_escrow_payment", "scam_site_full_flow", "identity_otp_takeover"}
        if fake_or_suspicious_site and scenario_ids.keys() & scam_site_ids:
            out.append(RiskSignal(
                code="FAKE_SITE_PAYMENT_FRAUD_CONTEXT",
                title="Sahte veya şüpheli sitede ödeme kandırması",
                description="Domain güven vermiyor ve içerik IBAN, sahte güvenli ödeme, kimlik/kod veya kart bilgisi akışıyla birleşiyor.",
                points=40,
                severity="critical",
                evidence={"host": host, "matched_scenarios": sorted(scenario_ids.keys() & scam_site_ids)},
            ))

        return out

    def _signals_from_listing_info(self, listing_info: Dict[str, Any]) -> List[RiskSignal]:
        signals: List[RiskSignal] = []
        if not listing_info.get("is_job_listing"):
            return signals

        fake_probability = int(listing_info.get("fake_probability", 0))
        useless_probability = int(listing_info.get("useless_probability", 0))
        quality_score = int(listing_info.get("quality_score", 0))

        signals.append(RiskSignal(
            code="JOB_LISTING_DETECTED",
            title="İş ilanı içeriği tespit edildi",
            description="Metin iş ilanı veya iş başvurusu akışı gibi görünüyor; sahte ilan, gereksiz ilan ve ilan kalitesi ayrıca değerlendirildi.",
            points=0,
            severity="info",
            evidence={
                "classification": listing_info.get("classification"),
                "quality_score": quality_score,
                "work_mode": listing_info.get("work_mode"),
            },
        ))

        level = listing_info.get("decision_level", "neutral")
        decision_points = {"positive": -12, "neutral": 0, "warning": 12, "danger": 35}.get(level, 0)
        decision_severity = {"positive": "positive", "neutral": "info", "warning": "medium", "danger": "critical"}.get(level, "info")
        signals.append(RiskSignal(
            code="JOB_APPLY_DECISION",
            title=f"Başvuru kararı: {listing_info.get('apply_decision', '-')}",
            description=listing_info.get("decision_reason", "İlan için başvuru kararı üretildi."),
            points=decision_points,
            severity=decision_severity,
            evidence={
                "decision": listing_info.get("apply_decision"),
                "level": level,
                "red_flags": listing_info.get("red_flags", []),
                "yellow_flags": listing_info.get("yellow_flags", []),
            },
        ))

        if int(listing_info.get("overload_score", 0)) >= 40:
            signals.append(RiskSignal(
                code="JOB_LISTING_OVERLOADED_ROLE",
                title="İlan kapsamı fazla geniş",
                description="Tek pozisyonda birden fazla meslek veya çok fazla uzmanlık alanı isteniyor. Bu ilan sahte olmak zorunda değil; ama iş yükü ve beklenti görüşmede netleştirilmeli.",
                points=12 if int(listing_info.get("overload_score", 0)) < 70 else 22,
                severity="medium",
                evidence={
                    "overload_score": listing_info.get("overload_score"),
                    "detected_roles": listing_info.get("detected_roles", []),
                    "requirement_count": listing_info.get("requirement_count", 0),
                },
            ))

        if listing_info.get("stale_days") is not None and int(listing_info.get("stale_days", 0)) >= 45:
            signals.append(RiskSignal(
                code="JOB_LISTING_STALE",
                title="İlan uzun süredir yayında olabilir",
                description="İlan çok uzun süredir yayındaysa pozisyon kapanmış, güncellenmemiş veya sürekli dönen düşük kaliteli ilan olabilir.",
                points=10,
                severity="medium",
                evidence={"stale_days": listing_info.get("stale_days")},
            ))

        if listing_info.get("is_known_job_board"):
            signals.append(RiskSignal(
                code="KNOWN_JOB_BOARD_LINK",
                title="Bilinen iş ilanı platformu",
                description="Bağlantı bilinen bir iş ilanı veya kariyer platformuna ait görünüyor; yine de ilan içeriği ve iletişim akışı ayrıca değerlendirilmelidir.",
                points=-6,
                severity="positive",
                evidence={
                    "platform": listing_info.get("source_platform"),
                    "host": listing_info.get("source_host"),
                },
            ))

        if int(listing_info.get("content_length", 0)) < 80:
            signals.append(RiskSignal(
                code="JOB_LISTING_CONTENT_MISSING",
                title="İlan metni eksik veya okunamadı",
                description="Link iş ilanı gibi duruyor ancak sayfa metni okunamadı veya çok kısa kaldı. Lütfen ilanı tarayıcıdan HTML olarak kaydedip Dosyadan Analiz Et ile yükleyin ya da ilan açıklamasını metin kutusuna yapıştırın.",
                points=50,
                severity="medium",
                evidence={
                    "content_length": listing_info.get("content_length", 0),
                    "missing_fields": listing_info.get("missing_fields", []),
                },
            ))

        if fake_probability >= 75:
            signals.append(RiskSignal(
                code="JOB_LISTING_FAKE_HIGH_RISK",
                title="Sahte iş ilanı riski yüksek",
                description="İlanda IBAN/Papara/banka hesabı kullandırma, ücret isteme, WhatsApp'a taşıma veya gerçekçi olmayan kazanç sinyalleri birleşiyor.",
                points=35,
                severity="critical",
                evidence={
                    "fake_probability": fake_probability,
                    "keywords": listing_info.get("fake_job_keywords", []),
                    "asks_money_or_account": listing_info.get("asks_money_or_account", False),
                },
            ))
        elif fake_probability >= 45:
            signals.append(RiskSignal(
                code="JOB_LISTING_SUSPICIOUS",
                title="Şüpheli iş ilanı",
                description="İlanda sahte veya kötü niyetli iş akışına benzeyen bazı işaretler bulundu.",
                points=20,
                severity="high",
                evidence={
                    "fake_probability": fake_probability,
                    "keywords": listing_info.get("fake_job_keywords", []),
                },
            ))

        if useless_probability >= 65:
            signals.append(RiskSignal(
                code="JOB_LISTING_LOW_QUALITY_SPAM",
                title="Gereksiz/spam iş ilanı olabilir",
                description="İlan kısa, belirsiz, DM/WhatsApp odaklı veya iş tanımı açısından zayıf görünüyor.",
                points=10,
                severity="medium",
                evidence={
                    "useless_probability": useless_probability,
                    "low_quality_keywords": listing_info.get("low_quality_keywords", []),
                    "missing_fields": listing_info.get("missing_fields", []),
                },
            ))

        if quality_score >= 70 and fake_probability < 35:
            signals.append(RiskSignal(
                code="JOB_LISTING_QUALITY_POSITIVE",
                title="İlan bilgileri görece tutarlı",
                description="Şirket, pozisyon, lokasyon veya iş tanımı gibi doğrulanabilir alanlar daha dolu görünüyor.",
                points=-10,
                severity="positive",
                evidence={
                    "quality_score": quality_score,
                    "legit_keywords": listing_info.get("legit_keywords", []),
                },
            ))

        return signals

    def _filter_job_listing_false_positives(
        self,
        signals: List[RiskSignal],
        listing_info: Dict[str, Any],
    ) -> List[RiskSignal]:
        if not listing_info.get("is_job_listing"):
            return signals
        if int(listing_info.get("quality_score", 0)) < 70:
            return signals
        if int(listing_info.get("fake_probability", 0)) >= 45:
            return signals
        if listing_info.get("asks_money_or_account"):
            return signals

        serious_payment = {
            "iban", "papara", "havale", "eft", "kapora", "kart bilgisi",
            "kredi karti", "kredi kartı", "cvv", "3d secure", "dekont",
            "para gonder", "para gönder", "ininal",
        }
        weak_off_platform = {"dm", "instagram", "linkedin", "facebook"}
        weak_social = {"musteri hizmetleri", "müşteri hizmetleri", "canli destek", "canlı destek"}
        weak_pressure = {"hemen"}
        serious_ml_hits = {
            "iban", "papara", "kapora", "havale", "eft", "para transferi",
            "komisyon", "on odeme", "ön ödeme", "evrak ucreti", "evrak ücreti",
            "sigorta ucreti", "sigorta ücreti", "whatsapp",
        }

        filtered: List[RiskSignal] = []
        for signal in signals:
            code = signal.code
            evidence = signal.evidence or {}

            if code == "PAYMENT_KEYWORDS":
                keywords = {normalize_text(item) for item in evidence.get("keywords", [])}
                if keywords and not (keywords & {normalize_text(item) for item in serious_payment}):
                    continue

            if code == "PHISHING_KEYWORDS":
                keywords = {normalize_text(item) for item in evidence.get("keywords", [])}
                if keywords <= {"param guvende", "param güvende"}:
                    continue

            if code == "OFF_PLATFORM_CONTACT":
                keywords = {normalize_text(item) for item in evidence.get("keywords", [])}
                if keywords and keywords <= {normalize_text(item) for item in weak_off_platform}:
                    continue

            if code == "SOCIAL_ENGINEERING_SCRIPT":
                keywords = {normalize_text(item) for item in evidence.get("keywords", [])}
                if keywords and keywords <= {normalize_text(item) for item in weak_social}:
                    continue

            if code == "URGENCY_PRESSURE":
                keywords = {normalize_text(item) for item in evidence.get("keywords", [])}
                if keywords and keywords <= {normalize_text(item) for item in weak_pressure}:
                    continue

            if code == "SCAM_PATTERN_REGEX":
                patterns = set(evidence.get("patterns", []))
                if patterns and patterns <= {r"param\s*g[Ã¼u]vende", r"param\s*g[üu]vende"}:
                    continue

            if code.startswith("ML_SCENARIO_"):
                hits = {normalize_text(item) for item in evidence.get("hits", [])}
                if not (hits & {normalize_text(item) for item in serious_ml_hits}):
                    continue

            if code == "TRUSTED_SITE_MALICIOUS_LISTING_CONTEXT":
                continue

            filtered.append(signal)

        if len(filtered) != len(signals):
            filtered.append(RiskSignal(
                code="JOB_LISTING_BOILERPLATE_FILTERED",
                title="İş ilanı dışı sayfa metni süzüldü",
                description="İlan kaliteli ve tutarlı göründüğü için Sahibinden/HTML sayfa şablonundan gelen genel ödeme, sosyal medya veya destek kelimeleri risk hesabından çıkarıldı.",
                points=-8,
                severity="positive",
                evidence={
                    "quality_score": listing_info.get("quality_score"),
                    "classification": listing_info.get("classification"),
                },
            ))
        return filtered

    def _analyze_url(self, info: Dict[str, Any], platform: str) -> List[RiskSignal]:
        signals: List[RiskSignal] = []
        host = info.get("host") or ""
        registered = info.get("registered_domain") or ""
        tld = info.get("tld") or ""
        path = info.get("path") or ""
        query = info.get("query") or ""

        if not host:
            signals.append(RiskSignal(
                code="URL_NO_HOST",
                title="URL host bilgisi yok",
                description="Bağlantıda analiz edilebilir domain/host bilgisi bulunamadı.",
                points=20,
                severity="medium",
            ))
            return signals

        is_official = DomainTools.is_official(host, platform)
        contains_mark = DomainTools.contains_mark(host, platform)

        if contains_mark and not is_official:
            signals.append(RiskSignal(
                code="BRAND_IN_NON_OFFICIAL_DOMAIN",
                title="Marka adını taklit eden resmi olmayan domain",
                description="Domain, platform/marka adını içeriyor fakat resmi domain gibi görünmüyor.",
                points=35,
                severity="high",
                evidence={"host": host, "registered_domain": registered, "platform": platform},
            ))

        if is_official:
            signals.append(RiskSignal(
                code="OFFICIAL_DOMAIN",
                title="Resmi domaine benziyor",
                description="Host bilinen resmi domain listesiyle uyumlu.",
                points=-20,
                severity="positive",
                evidence={"host": host},
            ))

        if DomainTools.is_shortener(registered) or DomainTools.is_shortener(host):
            signals.append(RiskSignal(
                code="URL_SHORTENER",
                title="Kısaltılmış bağlantı",
                description="Kısaltılmış linkler hedefi gizleyebilir. Ödeme/kimlik doğrulama için risklidir.",
                points=20,
                severity="medium",
                evidence={"host": host},
            ))

        if tld in SUSPICIOUS_TLDS:
            signals.append(RiskSignal(
                code="RISKY_TLD",
                title="Riskli/ucuz TLD kullanımı",
                description="Dolandırıcılık sitelerinde sık görülen TLD sınıfı kullanılmış olabilir.",
                points=10,
                severity="low",
                evidence={"tld": tld},
            ))

        if DomainTools.has_punycode(host):
            signals.append(RiskSignal(
                code="PUNYCODE_DOMAIN",
                title="Punycode domain",
                description="Alan adında unicode taklit riski olabilir.",
                points=25,
                severity="high",
                evidence={"host": host},
            ))

        if DomainTools.is_ip_host(host):
            signals.append(RiskSignal(
                code="IP_AS_HOST",
                title="Domain yerine IP adresi",
                description="Ödeme/ilan işlemlerinde direkt IP host kullanımı şüphelidir.",
                points=25,
                severity="high",
                evidence={"host": host},
            ))

        hyphens = DomainTools.suspicious_hyphen_count(host)
        if hyphens >= 3:
            signals.append(RiskSignal(
                code="MANY_HYPHENS",
                title="Domain adında çok fazla tire",
                description="Taklit/phishing domainlerinde uzun ve tireli adlar sık görülür.",
                points=10,
                severity="low",
                evidence={"hyphen_count": hyphens},
            ))

        official_bases = OFFICIAL_DOMAINS.get(platform, [])
        best_similarity = 0.0
        best_domain = ""
        for official in official_bases:
            ratio = DomainTools.similarity_score(registered, official)
            if ratio > best_similarity:
                best_similarity = ratio
                best_domain = official
        if 0.72 <= best_similarity < 1.0 and not is_official:
            signals.append(RiskSignal(
                code="LOOKALIKE_DOMAIN",
                title="Resmi domaine benzeyen alan adı",
                description="Domain adı resmi domaine benziyor ama aynı değil.",
                points=25,
                severity="high",
                evidence={"registered_domain": registered, "looks_like": best_domain, "similarity": round(best_similarity, 3)},
            ))

        norm_path_query = normalize_text(path + " " + query)
        if any(k in norm_path_query for k in ["odeme", "ödeme", "payment", "guvende", "onay", "verify"]):
            signals.append(RiskSignal(
                code="PAYMENT_WORD_IN_URL",
                title="URL içinde ödeme/onay kelimeleri",
                description="Ödeme/onay ifadeleri özellikle resmi domain dışında riskli olabilir.",
                points=15 if not is_official else 3,
                severity="medium" if not is_official else "low",
                evidence={"path": path, "query_keys": info.get("query_keys", [])},
            ))

        if len(host) > 45:
            signals.append(RiskSignal(
                code="VERY_LONG_HOST",
                title="Çok uzun host adı",
                description="Uzun domainler kullanıcıyı yanıltmak için kullanılabilir.",
                points=8,
                severity="low",
                evidence={"length": len(host)},
            ))

        return signals

    def _analyze_text(self, text_info: Dict[str, Any], platform: str, url_info: Dict[str, Any]) -> List[RiskSignal]:
        signals: List[RiskSignal] = []
        host = url_info.get("host", "") if url_info else ""
        is_official = DomainTools.is_official(host, platform) if host else False

        phishing = text_info.get("phishing_keywords", [])
        if phishing:
            points = 35 if not is_official else 8
            signals.append(RiskSignal(
                code="PHISHING_KEYWORDS",
                title="Phishing/ödeme doğrulama ifadeleri",
                description="Metinde sahte ödeme veya güvenli ödeme akışlarında sık görülen ifadeler var.",
                points=points,
                severity="high" if points >= 30 else "low",
                evidence={"keywords": phishing[:20]},
            ))

        payment = text_info.get("payment_keywords", [])
        if payment:
            signals.append(RiskSignal(
                code="PAYMENT_KEYWORDS",
                title="Platform dışı ödeme sinyali",
                description="IBAN, havale/EFT, kapora veya kart bilgisi gibi ödeme sinyalleri bulundu.",
                points=25,
                severity="high",
                evidence={"keywords": payment[:20]},
            ))

        ibans = text_info.get("ibans", [])
        if ibans:
            signals.append(RiskSignal(
                code="IBAN_FOUND",
                title="IBAN bulundu",
                description="İlan/mesaj akışında IBAN geçmesi platform dışı ödeme riskini artırır.",
                points=30,
                severity="high",
                evidence={"count": len(ibans), "sample_hashes": [sha256_text(i)[:12] for i in ibans[:5]]},
            ))

        phones = text_info.get("phones", [])
        if phones:
            signals.append(RiskSignal(
                code="PHONE_FOUND",
                title="Telefon/WhatsApp iletişim sinyali",
                description="Telefon numarası bulunması platform dışına taşıma riski yaratabilir.",
                points=8,
                severity="low",
                evidence={"count": len(phones)},
            ))

        off_platform = text_info.get("off_platform_keywords", [])
        if off_platform:
            signals.append(RiskSignal(
                code="OFF_PLATFORM_CONTACT",
                title="Platform dışı iletişim çağrısı",
                description="WhatsApp/Telegram/DM gibi platform dışı iletişim sinyalleri bulundu.",
                points=18,
                severity="medium",
                evidence={"keywords": off_platform[:20]},
            ))

        social_engineering = text_info.get("social_engineering_keywords", [])
        if social_engineering:
            signals.append(RiskSignal(
                code="SOCIAL_ENGINEERING_SCRIPT",
                title="Sosyal mühendislik senaryosu sinyali",
                description="Metinde kurye, destek, hesap kısıtlama, onay kodu veya emanet ödeme gibi kandırma akışlarında kullanılan ifadeler bulundu.",
                points=22,
                severity="high",
                evidence={"keywords": social_engineering[:20]},
            ))

        pressure = text_info.get("pressure_keywords", [])
        if pressure:
            signals.append(RiskSignal(
                code="URGENCY_PRESSURE",
                title="Acele/kapora baskısı",
                description="Acele ettirme ve kapora baskısı dolandırıcılık senaryolarında yaygındır.",
                points=12,
                severity="medium",
                evidence={"keywords": pressure[:20]},
            ))

        regex_hits = text_info.get("regex_hits", [])
        if regex_hits:
            signals.append(RiskSignal(
                code="SCAM_PATTERN_REGEX",
                title="Bilinen dolandırıcılık kalıbı",
                description="Metin, bilinen şüpheli kalıplardan biriyle eşleşti.",
                points=18,
                severity="medium",
                evidence={"patterns": regex_hits[:10]},
            ))

        return signals

    def _verdict(self, score: int) -> str:
        if score >= 75:
            return "Yüksek risk"
        if score >= 45:
            return "Orta risk"
        if score >= 20:
            return "Düşük-orta risk"
        return "Düşük risk"

    def _summary(self, verdict: str, score: int, signals: List[RiskSignal]) -> str:
        high = [s for s in signals if s.severity in ("high", "critical")]
        med = [s for s in signals if s.severity == "medium"]
        if verdict == "Yüksek risk":
            return f"{score}/100 risk puanı. Kesinlikle işlem yapmayın; resmi platform dışına çıkmayın."
        if verdict == "Orta risk":
            return f"{score}/100 risk puanı. İşlem yapmadan önce dikkatli doğrulama gerekli."
        if high or med:
            return f"{score}/100 risk puanı. Bazı şüpheli sinyaller var; temkinli olun."
        return f"{score}/100 risk puanı. Belirgin ağır risk sinyali bulunmadı; yine de resmi akış dışına çıkmayın."

    def _recommendations(self, score: int, signals: List[RiskSignal]) -> List[str]:
        recs = [
            "Ödemeyi yalnızca resmi platform veya resmi uygulama üzerinden yapın.",
            "SMS/WhatsApp/DM ile gelen ödeme linklerine kart veya kimlik bilgisi girmeyin.",
            "Ekran görüntüsü, ilan linki, mesajlar, IBAN ve dekont gibi kanıtları saklayın.",
        ]
        codes = {s.code for s in signals}
        if "BRAND_IN_NON_OFFICIAL_DOMAIN" in codes or "LOOKALIKE_DOMAIN" in codes:
            recs.insert(0, "Bu bağlantı resmi domaine benzemiyor; link üzerinden işlem yapmayın.")
        if "IBAN_FOUND" in codes or "PAYMENT_KEYWORDS" in codes:
            recs.insert(0, "IBAN/havale/EFT ile para göndermeyin; bu güçlü bir risk sinyalidir.")
        if "ML_SCENARIO_JOB_IBAN_MULE" in codes:
            recs.insert(0, "İş ilanı bahanesiyle IBAN, Papara veya banka hesabı kullandırmayı kabul etmeyin; bu ciddi hukuki ve finansal risk doğurabilir.")
        if "ML_SCENARIO_JOB_UPFRONT_FEE" in codes:
            recs.insert(0, "İş başvurusu için eğitim, evrak, sigorta veya başvuru ücreti isteyen akışlara para göndermeyin.")
        if "JOB_LISTING_FAKE_HIGH_RISK" in codes:
            recs.insert(0, "Bu iş ilanında sahte ilan riski yüksek; IBAN/Papara/banka hesabı, kimlik veya ön ödeme paylaşmayın.")
        if "JOB_APPLY_DECISION" in codes:
            decision_signal = next((s for s in signals if s.code == "JOB_APPLY_DECISION"), None)
            if decision_signal:
                recs.insert(0, f"Başvuru kararı: {decision_signal.evidence.get('decision', '-')}. {decision_signal.description}")
        if "JOB_LISTING_OVERLOADED_ROLE" in codes:
            recs.insert(0, "Bu ilan birden fazla işi tek kişiden bekliyor olabilir; başvurmadan önce maaş, öncelikler, ekip yapısı ve günlük sorumlulukları net sorun.")
        if "JOB_LISTING_STALE" in codes:
            recs.insert(0, "İlan uzun süredir yayındaysa pozisyonun hâlâ açık olup olmadığını resmi kanaldan doğrulayın.")
        if "JOB_LISTING_LOW_QUALITY_SPAM" in codes:
            recs.insert(0, "İlan gereksiz/spam gibi görünüyorsa başvurmadan önce şirket adı, resmi kariyer sayfası, lokasyon ve iş tanımını doğrulayın.")
        if "JOB_LISTING_CONTENT_MISSING" in codes:
            recs.insert(0, "Analiz tamamlanamadı: ilan metni okunamadı. Tarayıcıda sayfayı açıp HTML olarak kaydedin ve GUI'de Dosyadan Analiz Et ile yükleyin; alternatif olarak ilan açıklamasını metin kutusuna yapıştırın.")
        if "JOB_LISTING_QUALITY_POSITIVE" in codes:
            recs.append("İlan daha tutarlı görünse bile başvuruyu resmi kariyer sayfası veya kurumsal e-posta üzerinden doğrulayın.")
        if "TRUSTED_SITE_MALICIOUS_LISTING_CONTEXT" in codes:
            recs.insert(0, "Site gerçek görünse bile ilan sahibinin istediği IBAN, kapora, WhatsApp veya hesap kullandırma akışını platform dışına taşımayın.")
        if "FAKE_SITE_PAYMENT_FRAUD_CONTEXT" in codes:
            recs.insert(0, "Sahte veya şüpheli sitede ödeme, kart, kimlik veya IBAN bilgisi paylaşmayın; sayfayı kapatıp resmi uygulamadan kontrol edin.")
        if "FREE_SSL_ON_SUSPICIOUS_DOMAIN" in codes:
            recs.insert(0, "Bağlantının HTTPS olması sitenin güvenli olduğunu kanıtlamaz; taklit domain tespit edildi.")
        if score >= 45:
            recs.append("Şüpheli durumu platform destek ekibine, bankanıza ve gerekirse resmi mercilere bildirin.")
        return unique_list_recs_helper(recs)

def unique_list_recs_helper(items: Iterable[str]) -> List[str]:
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out

def now_iso_string() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="seconds")
