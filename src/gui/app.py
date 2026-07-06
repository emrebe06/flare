# -*- coding: utf-8 -*-
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, Optional, Tuple

from src.core.models import AnalysisInput, AnalysisResult, APP_NAME, APP_VERSION
from src.core.engine import RiskEngine
from src.core.listing_monitor import ListingMonitor
from src.utils.reporter import ReportWriter
from src.utils.file_parsers import parse_html_file, parse_pdf_file
from src.gui.styles import (
    apply_modern_theme, BG_DARK, BG_CARD, BG_CARD_ALT, FG_LIGHT, FG_MUTED,
    COLOR_ACCENT, COLOR_SUCCESS, COLOR_WARNING, COLOR_DANGER, COLOR_BORDER
)

class FlameGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1150x800")
        self.minsize(950, 680)
        self.configure(background=BG_DARK)
        
        # Risk motoru çekirdeği
        self.engine = RiskEngine()
        self.monitor = ListingMonitor()
        self.current_result: Optional[AnalysisResult] = None
        self.worker_queue: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
        
        # Temayı uygula
        style = ttk.Style()
        apply_modern_theme(style)

        self._build_ui()
        self.after(100, self._poll_queue)

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        # Üst Header Bilgi Paneli
        header = ttk.Frame(self, padding=15)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)

        title = ttk.Label(header, text="🔥 Flame", style="Header.TLabel")
        title.grid(row=0, column=0, sticky="w")

        subtitle = ttk.Label(
            header,
            text="Pasif iş ilanı, ilan ve bağlantı risk analiz sistemi.",
            style="Muted.TLabel"
        )
        subtitle.grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 0))

        # Sekmeli Defter (Notebook)
        self.notebook = ttk.Notebook(self)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

        self.tab_analyze = ttk.Frame(self.notebook, padding=15)
        self.tab_result = ttk.Frame(self.notebook, padding=15)
        self.tab_monitor = ttk.Frame(self.notebook, padding=15)
        self.tab_help = ttk.Frame(self.notebook, padding=15)

        self.notebook.add(self.tab_analyze, text="Analiz")
        self.notebook.add(self.tab_result, text="Sonuçlar")
        self.notebook.add(self.tab_monitor, text="İlan İzleme")
        self.notebook.add(self.tab_help, text="Kılavuz & Yardım")

        self._build_analyze_tab()
        self._build_result_tab()
        self._build_monitor_tab()
        self._build_help_tab()

    def _build_analyze_tab(self) -> None:
        f = self.tab_analyze
        f.columnconfigure(0, weight=1)
        f.rowconfigure(5, weight=1)

        # Üst Link / URL Girişi ve Dosya Analizi
        top_grid = ttk.Frame(f)
        top_grid.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        top_grid.columnconfigure(0, weight=1)

        ttk.Label(top_grid, text="İlan / Ödeme / Phishing Bağlantısı", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w")
        
        self.url_var = tk.StringVar()
        self.url_entry = ttk.Entry(top_grid, textvariable=self.url_var)
        self.url_entry.grid(row=1, column=0, sticky="ew", pady=(4, 0), padx=(0, 10))

        # Dosya Analiz Butonları
        file_btns = ttk.Frame(top_grid)
        file_btns.grid(row=1, column=1, sticky="e")
        
        ttk.Button(file_btns, text="Dosyadan Analiz Et (HTML/PDF)", command=self.load_file).grid(row=0, column=0, sticky="e")

        # Seçenekler Paneli
        options = ttk.Frame(f, style="Card.TFrame", padding=10)
        options.grid(row=2, column=0, sticky="ew", pady=(0, 15))
        options.columnconfigure(5, weight=1)

        ttk.Label(options, text="Platform:", style="Card.TLabel").grid(row=0, column=0, sticky="w")
        self.platform_var = tk.StringVar(value="auto")
        
        platforms = [
            "auto", "sahibinden", "linkedin", "kariyer", "yenibiris", "eleman", "iskur",
            "indeed", "secretcv", "isbul", "jooble", "glassdoor", "remoteok",
            "dolap", "letgo", "trendyol", "hepsiburada", "yemeksepeti", "getir",
            "n11", "ciceksepeti", "pazarama",
        ]
        platform_box = ttk.Combobox(
            options,
            textvariable=self.platform_var,
            state="readonly",
            values=platforms,
            width=18
        )
        platform_box.grid(row=0, column=1, sticky="w", padx=(8, 20))

        self.fetch_var = tk.BooleanVar(value=True)
        self.fetch_check = ttk.Checkbutton(
            options,
            text="Ağdan pasif sayfa başlığı / SSL sertifikası oku",
            variable=self.fetch_var,
            style="TCheckbutton"
        )
        self.fetch_check.grid(row=0, column=2, sticky="w")

        ttk.Label(options, text="İlan Türü:", style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.listing_kind_var = tk.StringVar(value="auto")
        kind_box = ttk.Combobox(
            options,
            textvariable=self.listing_kind_var,
            state="readonly",
            values=["auto", "job", "marketplace"],
            width=18
        )
        kind_box.grid(row=1, column=1, sticky="w", padx=(8, 20), pady=(8, 0))

        ttk.Label(options, text="İlan Başlığı:", style="Card.TLabel").grid(row=1, column=2, sticky="w", pady=(8, 0))
        self.listing_title_var = tk.StringVar()
        title_entry = ttk.Entry(options, textvariable=self.listing_title_var)
        title_entry.grid(row=1, column=3, columnspan=3, sticky="ew", padx=(8, 0), pady=(8, 0))

        # Metin Girişi
        ttk.Label(f, text="Mesaj İçeriği / İlan Açıklaması / WhatsApp Konuşması", font=("Segoe UI", 10, "bold")).grid(row=4, column=0, sticky="w")
        
        # Standart Tkinter Text bileşenini modern renklere büründürüyoruz
        self.text_input = tk.Text(
            f, height=14, wrap="word", 
            bg=BG_CARD, fg=FG_LIGHT, 
            insertbackground=FG_LIGHT, 
            relief="flat", 
            highlightbackground=COLOR_BORDER,
            highlightcolor=COLOR_ACCENT,
            highlightthickness=1,
            padx=10, pady=10
        )
        self.text_input.grid(row=5, column=0, sticky="nsew", pady=(6, 15))

        # Notlar
        ttk.Label(f, text="Ek Analiz Notları", font=("Segoe UI", 10, "bold")).grid(row=6, column=0, sticky="w")
        self.notes_input = tk.Text(
            f, height=3, wrap="word",
            bg=BG_CARD, fg=FG_LIGHT,
            insertbackground=FG_LIGHT,
            relief="flat",
            highlightbackground=COLOR_BORDER,
            highlightcolor=COLOR_ACCENT,
            highlightthickness=1,
            padx=10, pady=5
        )
        self.notes_input.grid(row=7, column=0, sticky="ew", pady=(6, 15))

        # Alt Butonlar ve Durum
        btns = ttk.Frame(f)
        btns.grid(row=8, column=0, sticky="ew")
        btns.columnconfigure(3, weight=1)

        ttk.Button(btns, text="Taramayı Başlat", style="Accent.TButton", command=self.start_analysis).grid(row=0, column=0, sticky="w")
        ttk.Button(btns, text="Örnek Veri Yükle", command=self.fill_sample).grid(row=0, column=1, sticky="w", padx=(10, 0))
        ttk.Button(btns, text="Temizle", command=self.clear_inputs).grid(row=0, column=2, sticky="w", padx=(10, 0))

        self.status_var = tk.StringVar(value="Analiz için hazır.")
        ttk.Label(btns, textvariable=self.status_var, style="Muted.TLabel").grid(row=0, column=3, sticky="e")

    def _build_result_tab(self) -> None:
        f = self.tab_result
        f.columnconfigure(0, weight=1)
        f.rowconfigure(2, weight=1)

        # Üst Sonuç Başlık ve Butonlar
        top = ttk.Frame(f)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        top.columnconfigure(1, weight=1)

        # Skor ve Karar Paneli
        score_panel = ttk.Frame(top)
        score_panel.grid(row=0, column=0, sticky="w")
        
        self.score_var = tk.StringVar(value="Risk Skoru: -")
        self.verdict_var = tk.StringVar(value="Karar: Analiz Yok")
        
        self.score_label = tk.Label(
            score_panel, 
            textvariable=self.score_var, 
            font=("Segoe UI", 16, "bold"), 
            bg=BG_DARK, 
            fg=FG_LIGHT
        )
        self.score_label.grid(row=0, column=0, sticky="w")
        
        self.verdict_label = tk.Label(
            score_panel, 
            textvariable=self.verdict_var, 
            font=("Segoe UI", 16, "bold"), 
            bg=BG_DARK, 
            fg=FG_MUTED
        )
        self.verdict_label.grid(row=0, column=1, sticky="w", padx=(25, 0))

        # İhracat Butonları
        export = ttk.Frame(top)
        export.grid(row=0, column=2, sticky="e")
        ttk.Button(export, text="HTML Rapor", command=self.save_html).grid(row=0, column=0)
        ttk.Button(export, text="JSON Rapor", command=self.save_json).grid(row=0, column=1, padx=(8, 0))
        ttk.Button(export, text="TXT Rapor", command=self.save_txt).grid(row=0, column=2, padx=(8, 0))

        # Özet Mesaj Kutusu
        self.summary_var = tk.StringVar(value="Analiz yapıldıktan sonra sonuçlar burada görüntülenecektir.")
        self.summary_label = tk.Label(
            f, 
            textvariable=self.summary_var, 
            font=("Segoe UI", 11, "italic"), 
            bg=BG_CARD_ALT, 
            fg=FG_LIGHT,
            padx=10, 
            pady=10,
            justify="left",
            anchor="w",
            wraplength=950
        )
        self.summary_label.grid(row=1, column=0, sticky="ew", pady=(10, 15))

        # Detaylı Sonuç Ekranı
        self.result_text = tk.Text(
            f, wrap="word",
            bg=BG_CARD, fg=FG_LIGHT,
            insertbackground=FG_LIGHT,
            relief="flat",
            highlightbackground=COLOR_BORDER,
            highlightthickness=1,
            padx=10, pady=10
        )
        self.result_text.grid(row=2, column=0, sticky="nsew")
        self.result_text.configure(state="disabled")

    def _build_monitor_tab(self) -> None:
        f = self.tab_monitor
        f.columnconfigure(0, weight=1)
        f.rowconfigure(1, weight=1)

        top = ttk.Frame(f)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        top.columnconfigure(0, weight=1)

        ttk.Label(
            top,
            text="İzlenen iş ilanları",
            font=("Segoe UI", 12, "bold")
        ).grid(row=0, column=0, sticky="w")
        ttk.Button(top, text="Listeyi Yenile", command=self.refresh_monitor_tab).grid(row=0, column=1, sticky="e")

        columns = ("title", "class", "risk", "fake", "useless", "quality", "seen", "changed")
        self.monitor_tree = ttk.Treeview(f, columns=columns, show="headings", height=12)
        headings = {
            "title": "İlan",
            "class": "Karar",
            "risk": "Risk",
            "fake": "Sahte",
            "useless": "Gereksiz",
            "quality": "Kalite",
            "seen": "Tarama",
            "changed": "Son Değişim",
        }
        widths = {
            "title": 240,
            "class": 190,
            "risk": 60,
            "fake": 60,
            "useless": 70,
            "quality": 60,
            "seen": 60,
            "changed": 260,
        }
        for col in columns:
            self.monitor_tree.heading(col, text=headings[col])
            self.monitor_tree.column(col, width=widths[col], anchor="w")
        self.monitor_tree.grid(row=1, column=0, sticky="nsew")

        scroll = ttk.Scrollbar(f, orient="vertical", command=self.monitor_tree.yview)
        scroll.grid(row=1, column=1, sticky="ns")
        self.monitor_tree.configure(yscrollcommand=scroll.set)

        self.monitor_detail = tk.Text(
            f, height=8, wrap="word",
            bg=BG_CARD, fg=FG_LIGHT,
            insertbackground=FG_LIGHT,
            relief="flat",
            highlightbackground=COLOR_BORDER,
            highlightthickness=1,
            padx=10, pady=10
        )
        self.monitor_detail.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        self.monitor_detail.configure(state="disabled")
        self.monitor_tree.bind("<<TreeviewSelect>>", self._show_monitor_detail)
        self.refresh_monitor_tab()

    def _build_help_tab(self) -> None:
        f = self.tab_help
        f.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)
        
        help_text = tk.Text(
            f, wrap="word",
            bg=BG_CARD, fg=FG_LIGHT,
            relief="flat",
            highlightbackground=COLOR_BORDER,
            highlightthickness=1,
            padx=15, pady=15
        )
        help_text.grid(row=0, column=0, sticky="nsew")
        
        content = """
Flame Akıllı Risk Analiz Sistemi Kılavuzu

Bu araç; iş ilanı, ürün ilanı, ödeme bağlantısı ve gelen mesaj metinlerini pasif yöntemlerle inceler.
Amacı kesin hüküm vermek değil, kullanıcıya anlaşılır bir risk ve başvuru kararı üretmektir.

ÖNE ÇIKAN YETENEKLER:
--------------------------------------------------
1. İş ilanı karar motoru:
   İlanı "Başvurulabilir", "Dikkatli başvur / önce sor", "Doğrula, sonra başvur" veya "Başvurma" gibi net kararlarla özetler.

2. Gereksiz veya sorunlu ilan analizi:
   Tek ilanda çok fazla meslek istenmesi, maaş bilgisinin olmaması, ilanın çok eski görünmesi, belirsiz görev tanımı ve spam benzeri kalıpları işaretler.

3. Dolandırıcılık ve ödeme riski:
   IBAN, Papara, banka hesabı kullandırma, ön ödeme, evrak/sigorta ücreti, kapora, WhatsApp'a taşıma ve kimlik/kod isteme akışlarını yakalar.

4. HTML/PDF dosya analizi:
   Link okunamazsa sayfayı tarayıcıdan HTML olarak kaydedip "Dosyadan Analiz Et" ile yükleyebilirsiniz.

KULLANIM TAVSİYELERİ:
--------------------------------------------------
- İş ilanı başvurusunda IBAN, Papara, banka hesabı veya ön ödeme istenirse başvurmayın.
- Gerçek platformdaki ilan bile kötü niyetli olabilir; başvuru kararını ilan metniyle birlikte değerlendirin.
- Maaş, çalışma modeli, şirket adı, görev kapsamı ve başvuru kanalını netleştirmeden kişisel bilgi paylaşmayın.
"""
        help_text.insert("1.0", content.strip())
        help_text.configure(state="disabled")

    def refresh_monitor_tab(self) -> None:
        if not hasattr(self, "monitor_tree"):
            return
        for item_id in self.monitor_tree.get_children():
            self.monitor_tree.delete(item_id)
        self._monitor_items: Dict[str, Dict[str, Any]] = {}
        for item in self.monitor.list_items():
            latest = item.get("latest", {})
            changes = item.get("changes", [])
            row_id = item.get("key", "")
            self._monitor_items[row_id] = item
            self.monitor_tree.insert(
                "",
                "end",
                iid=row_id,
                values=(
                    item.get("title") or item.get("url") or "Başlıksız ilan",
                    item.get("classification", "-"),
                    latest.get("risk_score", "-"),
                    f"{latest.get('fake_probability', 0)}%",
                    f"{latest.get('useless_probability', 0)}%",
                    f"{latest.get('quality_score', 0)}%",
                    len(item.get("history", [])),
                    "; ".join(changes[:2]) if changes else "-",
                ),
            )

    def _show_monitor_detail(self, _event: Any = None) -> None:
        selected = self.monitor_tree.selection()
        if not selected:
            return
        item = self._monitor_items.get(selected[0], {})
        latest = item.get("latest", {})
        extracted = latest.get("extracted", {})
        lines = [
            f"Başlık: {item.get('title', '-')}",
            f"URL: {item.get('url', '-')}",
            f"Karar: {item.get('classification', '-')}",
            f"İlk görülme: {item.get('first_seen', '-')}",
            f"Son görülme: {item.get('last_seen', '-')}",
            f"Risk: {latest.get('risk_score', '-')}/100 | Sahte: {latest.get('fake_probability', 0)}% | Gereksiz: {latest.get('useless_probability', 0)}% | Kalite: {latest.get('quality_score', 0)}%",
            f"Çalışma modeli: {extracted.get('work_mode', '-')}",
            f"Maaş/ücret: {extracted.get('salary_values', [])}",
            f"Eksik alanlar: {', '.join(extracted.get('missing_fields', [])) or '-'}",
            "Değişimler:",
        ]
        for change in item.get("changes", []):
            lines.append(f"- {change}")
        self.monitor_detail.configure(state="normal")
        self.monitor_detail.delete("1.0", "end")
        self.monitor_detail.insert("1.0", "\n".join(lines))
        self.monitor_detail.configure(state="disabled")

    def load_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Dosya Seç (HTML, PDF veya Metin)",
            filetypes=[
                ("Tüm Desteklenenler", "*.html;*.htm;*.pdf;*.txt"),
                ("HTML Dosyaları", "*.html;*.htm"),
                ("PDF Dosyaları", "*.pdf"),
                ("Metin Dosyaları", "*.txt")
            ]
        )
        if not path:
            return
            
        ext = os.path.splitext(path)[1].lower()
        self.status_var.set("Dosya okunuyor...")
        
        if ext in (".html", ".htm"):
            text, links = parse_html_file(path)
        elif ext == ".pdf":
            text, links = parse_pdf_file(path)
        else:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                links = []
            except Exception as e:
                text = f"Dosya Okuma Hatası: {str(e)}"
                links = []

        # Arayüze doldur
        self.text_input.delete("1.0", "end")
        self.text_input.insert("1.0", text)
        
        if links:
            self.url_var.set(links[0])  # İlk bulunan linki URL kısmına koy
            self.notes_input.delete("1.0", "end")
            self.notes_input.insert("1.0", f"Dosyadan çıkarılan linkler:\n" + "\n".join(links))
        
        self.status_var.set(f"Dosya yüklendi: {os.path.basename(path)}")

    def fill_sample(self) -> None:
        self.url_var.set("https://kariyer-basvuru-onay.online/evden-paketleme")
        self.platform_var.set("sahibinden")
        self.listing_kind_var.set("job")
        self.listing_title_var.set("Evden paketleme iş ilanı - günlük ödeme")
        self.text_input.delete("1.0", "end")
        self.text_input.insert("1.0", (
            "Evden paketleme işi için hemen başlayabilirsiniz. Tecrübe şart değil, günlük ödeme var. "
            "Başvuru için WhatsApp'tan yazın. Ödemeler IBAN üzerinden yapılacak, Papara hesabı açıp "
            "para transferi başına komisyon kazanacaksınız. Evrak ve sigorta ücreti için önce küçük "
            "bir ödeme gerekiyor. IBAN: TR12 0000 0000 0000 0000 0000 00."
        ))
        self.notes_input.delete("1.0", "end")
        self.notes_input.insert("1.0", "İlan şirket adı ve resmi kariyer sayfası vermiyor; WhatsApp ve IBAN istiyor.")
        self.status_var.set("Örnek veri dolduruldu.")

    def clear_inputs(self) -> None:
        self.url_var.set("")
        self.listing_kind_var.set("auto")
        self.listing_title_var.set("")
        self.text_input.delete("1.0", "end")
        self.notes_input.delete("1.0", "end")
        self.status_var.set("Girişler temizlendi.")

    def start_analysis(self) -> None:
        data = AnalysisInput(
            url=self.url_var.get(),
            pasted_text=self.text_input.get("1.0", "end").strip(),
            notes=self.notes_input.get("1.0", "end").strip(),
            platform_hint=self.platform_var.get(),
            allow_network_fetch=self.fetch_var.get(),
            listing_title=self.listing_title_var.get().strip(),
            listing_kind=self.listing_kind_var.get(),
        )
        if not data.url and not data.pasted_text and not data.notes:
            messagebox.showwarning("Eksik Bilgi", "Analiz edebilmek için en azından bir URL veya metin girilmelidir.")
            return
            
        self.status_var.set("Analiz başlatılıyor...")
        t = threading.Thread(target=self._analysis_worker, args=(data,), daemon=True)
        t.start()

    def _analysis_worker(self, data: AnalysisInput) -> None:
        try:
            result = self.engine.analyze(data)
            self.worker_queue.put(("result", result))
        except Exception as e:
            self.worker_queue.put(("error", f"{type(e).__name__}: {e}"))

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.worker_queue.get_nowait()
                if kind == "result":
                    self.set_result(payload)
                elif kind == "error":
                    self.status_var.set("Analiz başarısız.")
                    messagebox.showerror("Analiz Hatası", str(payload))
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def set_result(self, result: AnalysisResult) -> None:
        self.current_result = result
        self.score_var.set(f"Risk Skoru: {result.risk_score}/100")
        self.verdict_var.set(f"Karar: {result.verdict}")
        codes = {signal.code for signal in result.signals}
        needs_html_upload = "JOB_LISTING_CONTENT_MISSING" in codes
        if needs_html_upload:
            self.summary_var.set(
                "İlan metni okunamadı. Lütfen sayfayı tarayıcıdan HTML olarak indirip "
                "'Dosyadan Analiz Et' ile yükleyin veya ilan açıklamasını metin kutusuna yapıştırın."
            )
        else:
            self.summary_var.set(result.summary)
        
        # Karar rengini güncelle
        if result.risk_score >= 75:
            self.score_label.configure(fg=COLOR_DANGER)
            self.verdict_label.configure(fg=COLOR_DANGER)
        elif result.risk_score >= 45:
            self.score_label.configure(fg=COLOR_WARNING)
            self.verdict_label.configure(fg=COLOR_WARNING)
        else:
            self.score_label.configure(fg=COLOR_SUCCESS)
            self.verdict_label.configure(fg=COLOR_SUCCESS)

        if needs_html_upload:
            self.status_var.set("İlan metni okunamadı; HTML dosyası yükleyin veya açıklamayı yapıştırın.")
        else:
            self.status_var.set("Analiz başarıyla tamamlandı.")
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.insert("end", self._format_result(result))
        self.result_text.configure(state="disabled")
        self.refresh_monitor_tab()
        self.notebook.select(self.tab_result)

    def _format_result(self, result: AnalysisResult) -> str:
        lines = []
        lines.append(f"{result.verdict} — Risk Puanı: {result.risk_score}/100")
        lines.append("=" * 80)
        lines.append(result.summary)
        lines.append("")
        listing = result.listing_info or {}
        if listing:
            lines.append("İş İlanı / İlan Kalitesi:")
            lines.append("-" * 80)
            lines.append(f"Sınıflandırma: {listing.get('classification', '-')}")
            lines.append(f"Başvuru kararı: {listing.get('apply_decision', '-')}")
            lines.append(f"Karar nedeni: {listing.get('decision_reason', '-')}")
            lines.append(f"Kaynak platform: {listing.get('source_platform', '-')}")
            lines.append(f"Kaynak host: {listing.get('source_host', '-')}")
            lines.append(f"Sahte iş ilanı olasılığı: {listing.get('fake_probability', 0)}%")
            lines.append(f"Gereksiz/spam ilan olasılığı: {listing.get('useless_probability', 0)}%")
            lines.append(f"Kalite puanı: {listing.get('quality_score', 0)}/100")
            lines.append(f"Aşırı kapsam puanı: {listing.get('overload_score', 0)}/100")
            if listing.get("detected_roles"):
                lines.append(f"Algılanan rol alanları: {', '.join(listing.get('detected_roles', []))}")
            if listing.get("red_flags"):
                lines.append("Kırmızı bayraklar:")
                for item in listing.get("red_flags", []):
                    lines.append(f"  - {item}")
            if listing.get("yellow_flags"):
                lines.append("Dikkat bayrakları:")
                for item in listing.get("yellow_flags", []):
                    lines.append(f"  - {item}")
            lines.append(f"Çalışma modeli: {listing.get('work_mode', '-')}")
            details = listing.get("details", {})
            if details:
                if details.get("title"):
                    lines.append(f"Pozisyon: {details.get('title')}")
                if details.get("location"):
                    lines.append(f"Lokasyon: {details.get('location')}")
                if details.get("work_type"):
                    lines.append(f"Çalışma şekli: {details.get('work_type')}")
                if details.get("tools"):
                    lines.append(f"Araçlar / konular: {', '.join(details.get('tools', [])[:12])}")
                if details.get("sectors"):
                    lines.append(f"Sektör / alan: {', '.join(details.get('sectors', [])[:8])}")
                if details.get("application_channels"):
                    lines.append(f"Başvuru kanalı: {', '.join(details.get('application_channels', []))}")
                if details.get("qualifications"):
                    lines.append("Aranan nitelikler:")
                    for item in details.get("qualifications", [])[:6]:
                        lines.append(f"  - {item}")
                if details.get("responsibilities"):
                    lines.append("Görev tanımı:")
                    for item in details.get("responsibilities", [])[:6]:
                        lines.append(f"  - {item}")
            if listing.get("salary_values"):
                lines.append(f"Maaş/ücret sinyali: {listing.get('salary_values')}")
            if listing.get("missing_fields"):
                lines.append(f"Eksik görünen alanlar: {', '.join(listing.get('missing_fields', []))}")
            monitor = listing.get("monitor", {})
            if monitor:
                lines.append(f"İzleme anahtarı: {monitor.get('watch_key', '-')}")
                lines.append(f"İzleme tarama sayısı: {monitor.get('seen_count', '-')}")
                for change in monitor.get("changes", []):
                    lines.append(f"- {change}")
            lines.append("")
        lines.append("🛡️ Risk Sinyalleri:")
        lines.append("-" * 80)
        for i, sig in enumerate(result.signals, 1):
            sign = "+" if sig.points >= 0 else ""
            lines.append(f"{i}. [{sig.severity.upper()}] {sig.title} ({sign}{sig.points})")
            lines.append(f"   Açıklama: {sig.description}")
            if sig.evidence:
                lines.append(f"   Kanıtlar: {sig.evidence}")
            lines.append("")
            
        lines.append("💡 Tavsiyeler & Öneriler:")
        lines.append("-" * 80)
        for rec in result.recommendations:
            lines.append(f"- {rec}")
        lines.append("")
        
        lines.append("🔧 Teknik Detaylar:")
        lines.append("-" * 80)
        if result.url_info:
            lines.append(f"Taranan Host: {result.url_info.get('host', '-')}")
            lines.append(f"Kayıtlı Domain: {result.url_info.get('registered_domain', '-')}")
            lines.append(f"TLD Uzantısı: {result.url_info.get('tld', '-')}")
            if "ssl" in result.url_info:
                ssl_d = result.url_info["ssl"]
                lines.append(f"SSL Durumu: {'Aktif (Sertifika Okundu)' if ssl_d.get('ok') else 'Başarısız'}")
                lines.append(f"SSL Otoritesi: {ssl_d.get('issuer', '-')}")
        lines.append(f"Metin Karakter Uzunluğu: {result.text_info.get('length', 0)}")
        lines.append(f"Tespit Edilen IBAN Sayısı: {len(result.text_info.get('ibans', []))}")
        lines.append(f"Tespit Edilen Telefon Sayısı: {len(result.text_info.get('phones', []))}")
        lines.append("")
        lines.append("⚖️ Güvenlik Notu:")
        lines.append(result.safety_notice)
        return "\n".join(lines)

    def save_json(self) -> None:
        if not self.current_result:
            messagebox.showinfo("Rapor Yok", "Lütfen önce analiz koşturun.")
            return
        path = filedialog.asksaveasfilename(
            title="JSON Raporu Kaydet",
            defaultextension=".json",
            filetypes=[("JSON Dosyası", "*.json")],
            initialfile=f"flame_report_{int(time.time())}.json",
        )
        if path:
            ReportWriter.write_json(self.current_result, path)
            messagebox.showinfo("Başarılı", f"Rapor kaydedildi:\n{path}")

    def save_txt(self) -> None:
        if not self.current_result:
            messagebox.showinfo("Rapor Yok", "Lütfen önce analiz koşturun.")
            return
        path = filedialog.asksaveasfilename(
            title="Metin Raporu Kaydet",
            defaultextension=".txt",
            filetypes=[("Text Dosyası", "*.txt")],
            initialfile=f"flame_report_{int(time.time())}.txt",
        )
        if path:
            ReportWriter.write_txt(self.current_result, path)
            messagebox.showinfo("Başarılı", f"Rapor kaydedildi:\n{path}")

    def save_html(self) -> None:
        if not self.current_result:
            messagebox.showinfo("Rapor Yok", "Lütfen önce analiz koşturun.")
            return
        path = filedialog.asksaveasfilename(
            title="HTML Raporu Kaydet",
            defaultextension=".html",
            filetypes=[("HTML Sayfası", "*.html")],
            initialfile=f"flame_report_{int(time.time())}.html",
        )
        if path:
            ReportWriter.write_html(self.current_result, path)
            messagebox.showinfo("Başarılı", f"Rapor kaydedildi:\n{path}")
