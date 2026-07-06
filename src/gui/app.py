# -*- coding: utf-8 -*-
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Dict, Optional, Tuple

from src.core.models import AnalysisInput, AnalysisResult, APP_NAME, APP_VERSION, CORE_TECH_NAME
from src.core.engine import RiskEngine
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
        self.current_result: Optional[AnalysisResult] = None
        self.worker_queue: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
        
        # C++ Starfall Core durumu
        self.cpp_active = False
        try:
            from src.core.bindings import starfall_similarity
            self.cpp_active = True
        except ImportError:
            pass

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

        # C++ Starfall Core durum etiketi
        status_text = f"Starfall Core C++: Aktif ⚡" if self.cpp_active else "Starfall Core C++: Pasif (Fallback) ⚠️"
        status_style = COLOR_SUCCESS if self.cpp_active else COLOR_WARNING
        
        cpp_status = tk.Label(
            header, 
            text=status_text, 
            font=("Consolas", 9, "bold"), 
            bg=BG_DARK, 
            fg=status_style
        )
        cpp_status.grid(row=0, column=2, sticky="e")

        subtitle = ttk.Label(
            header,
            text=f"Pasif phishing, ilan ve link risk analiz sistemi. Powered by {CORE_TECH_NAME}.",
            style="Muted.TLabel"
        )
        subtitle.grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 0))

        # Sekmeli Defter (Notebook)
        self.notebook = ttk.Notebook(self)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

        self.tab_analyze = ttk.Frame(self.notebook, padding=15)
        self.tab_result = ttk.Frame(self.notebook, padding=15)
        self.tab_help = ttk.Frame(self.notebook, padding=15)

        self.notebook.add(self.tab_analyze, text="Analiz")
        self.notebook.add(self.tab_result, text="Sonuçlar")
        self.notebook.add(self.tab_help, text="Kılavuz & Yardım")

        self._build_analyze_tab()
        self._build_result_tab()
        self._build_help_tab()

    def _build_analyze_tab(self) -> None:
        f = self.tab_analyze
        f.columnconfigure(0, weight=1)
        f.rowconfigure(4, weight=1)

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
        options.columnconfigure(3, weight=1)

        ttk.Label(options, text="Platform:", style="Card.TLabel").grid(row=0, column=0, sticky="w")
        self.platform_var = tk.StringVar(value="sahibinden")
        
        platforms = ["sahibinden", "dolap", "letgo", "trendyol", "hepsiburada", "yemeksepeti", "getir", "n11", "ciceksepeti", "pazarama"]
        platform_box = ttk.Combobox(
            options,
            textvariable=self.platform_var,
            state="readonly",
            values=platforms,
            width=18
        )
        platform_box.grid(row=0, column=1, sticky="w", padx=(8, 20))

        self.fetch_var = tk.BooleanVar(value=False)
        self.fetch_check = ttk.Checkbutton(
            options,
            text="Ağdan pasif sayfa başlığı / SSL sertifikası oku",
            variable=self.fetch_var,
            style="TCheckbutton"
        )
        self.fetch_check.configure(background=BG_CARD) # Kart içine uyum için
        self.fetch_check.grid(row=0, column=2, sticky="w")

        # Metin Girişi
        ttk.Label(f, text="Mesaj İçeriği / İlan Açıklaması / WhatsApp Konuşması", font=("Segoe UI", 10, "bold")).grid(row=3, column=0, sticky="w")
        
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
        self.text_input.grid(row=4, column=0, sticky="nsew", pady=(6, 15))

        # Notlar
        ttk.Label(f, text="Ek Analiz Notları", font=("Segoe UI", 10, "bold")).grid(row=5, column=0, sticky="w")
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
        self.notes_input.grid(row=6, column=0, sticky="ew", pady=(6, 15))

        # Alt Butonlar ve Durum
        btns = ttk.Frame(f)
        btns.grid(row=7, column=0, sticky="ew")
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
Flame & Starfall Akıllı Risk Analiz Sistemi Kılavuzu

Bu araç, şüpheli ilan bağlantılarını, ödeme sayfalarını ve gelen mesaj metinlerini pasif yöntemlerle inceler.
Amacı, kullanıcıyı olası dolandırıcılık ve phishing (oltalama) senaryolarına karşı uyarmaktır.

🛡️ ÖNE ÇIKAN AKILLI YETENEKLER:
--------------------------------------------------
1. Starfall Core C++ Motoru:
   Levenshtein alan adı benzerliği ve kelime arama işlemlerini C++ hızında ve Türkçe karakter destekli gerçekleştirir.
   
2. Gelişmiş SSL & HTTPS Analizi:
   Sadece "https://" protokolünün varlığına güvenmez. Let's Encrypt, ZeroSSL, Cloudflare gibi ücretsiz ve otomatik dağıtılan sertifikaları tespit eder, şüpheli marka taklit alan adlarıyla eşleşiyorsa risk puanını artırır.

3. HTML ve PDF Dosya Analizi:
   Dosya yükleme desteği sayesinde şüpheli fatura, dekont, ekran görüntüsü veya phishing içeren HTML sayfaları yüklenip içindeki metinler ve linkler otomatik ayrıştırılarak taranabilir.

4. SQLite & XOR Şifreli Bellek İhbar Veritabanı:
   Önceki dolandırıcılık vakalarında tespit edilen şüpheli IBAN ve telefon numaraları XOR şifreli olarak C++ belleğinde tutulur ve analizde eşleşirse doğrudan kritik seviyede risk uyarısı verir.

⚠️ KULLANIM TAVSİYELERİ:
--------------------------------------------------
- SMS veya WhatsApp'tan gelen ödeme linklerine asla kart veya kimlik bilgilerinizi girmeyin.
- Ödemeleri ve ilan onay işlemlerini yalnızca platformların kendi resmi mobil uygulamalarından veya tescilli resmi web sitelerinden yapın.
- Şüpheli durumlarda ödeme makbuzunu, dekontu veya linkleri bu araçla taratıp elde ettiğiniz çıktıyı resmi mercilere başvururken kanıt olarak kullanabilirsiniz.
"""
        help_text.insert("1.0", content.strip())
        help_text.configure(state="disabled")

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
        self.url_var.set("https://trendyol-cuzdan-onay.xyz/odeme")
        self.platform_var.set("trendyol")
        self.text_input.delete("1.0", "end")
        self.text_input.insert("1.0", (
            "Trendyol komisyon kesintisi yapmaması için ödemeyi WhatsApp üzerinden iletilen "
            "cüzdan onay linkinden tamamlamanız gerekmektedir. Ödeme tamamlandıktan sonra "
            "dekontu buradan paylaşın. IBAN: TR12 0000 0000 0000 0000 0000 00. Acele edin, "
            "ürün başkasına satılmasın."
        ))
        self.notes_input.delete("1.0", "end")
        self.notes_input.insert("1.0", "Satıcı WhatsApp'a yönlendirdi ve cüzdan onay taklit linki attı.")
        self.status_var.set("Örnek veri dolduruldu.")

    def clear_inputs(self) -> None:
        self.url_var.set("")
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

        self.status_var.set("Analiz başarıyla tamamlandı.")
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.insert("end", self._format_result(result))
        self.result_text.configure(state="disabled")
        self.notebook.select(self.tab_result)

    def _format_result(self, result: AnalysisResult) -> str:
        lines = []
        lines.append(f"{result.verdict} — Risk Puanı: {result.risk_score}/100")
        lines.append("=" * 80)
        lines.append(result.summary)
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
