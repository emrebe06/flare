# -*- coding: utf-8 -*-
import html
import json
from typing import List
from src.core.models import AnalysisResult, APP_NAME, APP_VERSION

class ReportWriter:
    @staticmethod
    def _html(value: object) -> str:
        return html.escape(str(value), quote=True)

    @staticmethod
    def write_json(result: AnalysisResult, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, ensure_ascii=False, indent=2)

    @staticmethod
    def write_txt(result: AnalysisResult, path: str) -> None:
        lines: List[str] = []
        lines.append(f"{result.app} (Powered by Starfall) Risk Raporu")
        lines.append("=" * 60)
        lines.append(f"Tarih: {result.created_at}")
        lines.append(f"Skor: {result.risk_score}/100")
        lines.append(f"Karar: {result.verdict}")
        lines.append("")
        lines.append(result.summary)
        lines.append("")
        lines.append("Sinyaller")
        lines.append("-" * 60)
        for i, sig in enumerate(result.signals, 1):
            lines.append(f"{i}. [{sig.severity}] {sig.title} (+{sig.points})")
            lines.append(f"   Kod: {sig.code}")
            lines.append(f"   Açıklama: {sig.description}")
            if sig.evidence:
                lines.append(f"   Kanıt: {json.dumps(sig.evidence, ensure_ascii=False)}")
            lines.append("")
        lines.append("Öneriler")
        lines.append("-" * 60)
        for rec in result.recommendations:
            lines.append(f"- {rec}")
        lines.append("")
        lines.append("URL Bilgisi")
        lines.append("-" * 60)
        lines.append(json.dumps(result.url_info, ensure_ascii=False, indent=2))
        lines.append("")
        lines.append("Metin Bilgisi")
        lines.append("-" * 60)
        lines.append(json.dumps(result.text_info, ensure_ascii=False, indent=2))
        lines.append("")
        lines.append("ML / Senaryo Bilgisi")
        lines.append("-" * 60)
        lines.append(json.dumps(result.ml_info, ensure_ascii=False, indent=2))
        lines.append("")
        lines.append("Güvenlik Notu")
        lines.append("-" * 60)
        lines.append(result.safety_notice)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    @staticmethod
    def write_html(result: AnalysisResult, path: str) -> None:
        # Şık ve modern HTML rapor şablonu (Starfall temalı)
        signals_html = ""
        for i, sig in enumerate(result.signals, 1):
            badge_color = "#333"
            if sig.severity == "critical":
                badge_color = "#dc3545"
            elif sig.severity == "high":
                badge_color = "#fd7e14"
            elif sig.severity == "medium":
                badge_color = "#ffc107"
            elif sig.severity == "positive":
                badge_color = "#28a745"
            elif sig.severity == "low":
                badge_color = "#17a2b8"
                
            evidence_str = ""
            if sig.evidence:
                evidence_json = json.dumps(sig.evidence, ensure_ascii=False)
                evidence_str = f'<div class="evidence"><strong>Kanıt:</strong> {ReportWriter._html(evidence_json)}</div>'

            signals_html += f"""
            <div class="signal-card {ReportWriter._html(sig.severity)}">
                <div class="signal-header">
                    <span class="badge" style="background-color: {badge_color};">{ReportWriter._html(sig.severity.upper())}</span>
                    <span class="signal-title">{ReportWriter._html(sig.title)} (+{ReportWriter._html(sig.points)})</span>
                </div>
                <div class="signal-desc">{ReportWriter._html(sig.description)}</div>
                {evidence_str}
            </div>
            """

        recs_html = "".join([f"<li>{ReportWriter._html(rec)}</li>" for rec in result.recommendations])

        verdict_class = "low"
        if result.risk_score >= 75:
            verdict_class = "critical"
        elif result.risk_score >= 45:
            verdict_class = "high"
        elif result.risk_score >= 20:
            verdict_class = "medium"

        html_content = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{ReportWriter._html(result.app)} Risk Analiz Raporu</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa;
            color: #333;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background: #fff;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.05);
        }}
        header {{
            border-bottom: 2px solid #eaeaea;
            padding-bottom: 15px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        h1 {{
            margin: 0;
            font-size: 24px;
            color: #1a1a1a;
        }}
        .tech-tag {{
            font-size: 12px;
            background: #eef2f7;
            padding: 4px 8px;
            border-radius: 4px;
            color: #555;
        }}
        .meta-info {{
            color: #777;
            font-size: 14px;
            margin-bottom: 20px;
        }}
        .verdict-box {{
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            color: #fff;
            text-align: center;
        }}
        .verdict-box.critical {{ background-color: #dc3545; }}
        .verdict-box.high {{ background-color: #fd7e14; }}
        .verdict-box.medium {{ background-color: #ffc107; color: #333; }}
        .verdict-box.low {{ background-color: #28a745; }}
        
        .score {{
            font-size: 48px;
            font-weight: bold;
            margin: 0;
        }}
        .verdict-title {{
            font-size: 20px;
            font-weight: 600;
            margin: 5px 0;
        }}
        .summary {{
            font-size: 15px;
            margin-top: 10px;
            opacity: 0.9;
        }}
        
        h2 {{
            font-size: 18px;
            border-bottom: 1px solid #eee;
            padding-bottom: 8px;
            margin-top: 30px;
        }}
        
        .signal-card {{
            background: #fff;
            border: 1px solid #eaeaea;
            border-left: 4px solid #ccc;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 15px;
        }}
        .signal-card.critical {{ border-left-color: #dc3545; }}
        .signal-card.high {{ border-left-color: #fd7e14; }}
        .signal-card.medium {{ border-left-color: #ffc107; }}
        .signal-card.positive {{ border-left-color: #28a745; }}
        
        .signal-header {{
            display: flex;
            align-items: center;
            margin-bottom: 8px;
        }}
        .badge {{
            color: white;
            font-size: 11px;
            font-weight: bold;
            padding: 3px 6px;
            border-radius: 3px;
            margin-right: 10px;
        }}
        .signal-title {{
            font-weight: 600;
            font-size: 15px;
        }}
        .signal-desc {{
            color: #666;
            font-size: 14px;
        }}
        .evidence {{
            font-family: monospace;
            background: #f1f3f5;
            padding: 8px;
            font-size: 12px;
            border-radius: 4px;
            margin-top: 8px;
            color: #555;
            word-break: break-all;
        }}
        
        ul.recs-list {{
            padding-left: 20px;
            line-height: 1.6;
            font-size: 14px;
        }}
        ul.recs-list li {{
            margin-bottom: 8px;
        }}
        
        footer {{
            margin-top: 40px;
            padding-top: 15px;
            border-top: 1px solid #eaeaea;
            font-size: 12px;
            color: #888;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ {ReportWriter._html(result.app)} Analiz Raporu</h1>
            <span class="tech-tag">Starfall Core v{ReportWriter._html(result.version)}</span>
        </header>
        
        <div class="meta-info">
            Tarih: {ReportWriter._html(result.created_at)} | Analiz Tipi: Platform Risk Analizi
        </div>
        
        <div class="verdict-box {verdict_class}">
            <div class="score">{ReportWriter._html(result.risk_score)}/100</div>
            <div class="verdict-title">{ReportWriter._html(result.verdict)}</div>
            <div class="summary">{ReportWriter._html(result.summary)}</div>
        </div>
        
        <h2>🔍 Tespit Edilen Risk Sinyalleri</h2>
        <div class="signals-container">
            {signals_html if result.signals else "<p>Hiçbir risk sinyali tespit edilmedi.</p>"}
        </div>
        
        <h2>💡 Önerilen Güvenlik Adımları</h2>
        <ul class="recs-list">
            {recs_html}
        </ul>
        
        <footer>
            {ReportWriter._html(result.safety_notice)}
        </footer>
    </div>
</body>
</html>
"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content.strip())
