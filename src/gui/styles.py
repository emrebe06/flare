# -*- coding: utf-8 -*-
from tkinter import ttk

# Flame & Starfall Modern Dark Theme Renk Paleti
BG_DARK = "#121214"         # Ana arka plan
BG_CARD = "#1a1a1e"         # Kartlar ve giriş kutuları arka planı
BG_CARD_ALT = "#222228"     # Alternatif kart rengi
FG_LIGHT = "#f3f3f5"        # Ana metin rengi
FG_MUTED = "#8d8d99"        # İkincil metin rengi
COLOR_ACCENT = "#ff4d4d"    # Flame Alev rengi (Turuncu/Kırmızı)
COLOR_SUCCESS = "#2ecc71"   # Güvenli / Düşük Risk
COLOR_WARNING = "#f1c40f"   # Orta Risk
COLOR_DANGER = "#e74c3c"    # Yüksek Risk
COLOR_BORDER = "#2d2d34"    # Kenarlıklar

def apply_modern_theme(style: ttk.Style) -> None:
    # Arayüz stil temasını temizle ve sıfırla
    style.theme_use("clam")

    # Genel arka plan ve yazı tipleri
    style.configure(".",
        background=BG_DARK,
        foreground=FG_LIGHT,
        font=("Segoe UI", 10),
        bordercolor=COLOR_BORDER,
        lightcolor=COLOR_BORDER,
        darkcolor=COLOR_BORDER
    )

    # Frame Stilleri
    style.configure("TFrame", background=BG_DARK)
    style.configure("Card.TFrame", background=BG_CARD, relief="flat")
    style.configure("CardAlt.TFrame", background=BG_CARD_ALT, relief="flat")

    # Label Stilleri
    style.configure("TLabel", background=BG_DARK, foreground=FG_LIGHT)
    style.configure("Muted.TLabel", background=BG_DARK, foreground=FG_MUTED, font=("Segoe UI", 9))
    style.configure("Card.TLabel", background=BG_CARD, foreground=FG_LIGHT)
    style.configure("CardMuted.TLabel", background=BG_CARD, foreground=FG_MUTED, font=("Segoe UI", 9))
    
    style.configure("Header.TLabel", 
        background=BG_DARK, 
        foreground=COLOR_ACCENT, 
        font=("Segoe UI", 16, "bold")
    )
    style.configure("Tech.TLabel", 
        background=BG_DARK, 
        foreground=FG_MUTED, 
        font=("Consolas", 9)
    )

    # Entry (Giriş) Stilleri
    style.configure("TEntry",
        fieldbackground=BG_CARD,
        foreground=FG_LIGHT,
        bordercolor=COLOR_BORDER,
        lightcolor=COLOR_BORDER,
        darkcolor=COLOR_BORDER,
        insertcolor=FG_LIGHT,
        padding=6
    )
    style.map("TEntry",
        bordercolor=[("focus", COLOR_ACCENT)]
    )

    # Buton Stilleri
    style.configure("TButton",
        background=BG_CARD_ALT,
        foreground=FG_LIGHT,
        bordercolor=COLOR_BORDER,
        font=("Segoe UI", 10, "bold"),
        padding=(12, 6),
        relief="flat"
    )
    style.map("TButton",
        background=[("active", COLOR_ACCENT), ("pressed", COLOR_ACCENT)],
        foreground=[("active", "#ffffff")]
    )

    # Accent (Flame) Buton Stili
    style.configure("Accent.TButton",
        background=COLOR_ACCENT,
        foreground="#ffffff",
        bordercolor=COLOR_ACCENT,
        font=("Segoe UI", 10, "bold"),
        padding=(16, 8),
        relief="flat"
    )
    style.map("Accent.TButton",
        background=[("active", "#ff3333"), ("pressed", "#cc0000")]
    )

    # Combobox Stilleri
    style.configure("TCombobox",
        fieldbackground=BG_CARD,
        background=BG_CARD_ALT,
        foreground=FG_LIGHT,
        bordercolor=COLOR_BORDER,
        arrowcolor=FG_LIGHT,
        padding=5
    )
    style.map("TCombobox",
        fieldbackground=[("readonly", BG_CARD)],
        foreground=[("readonly", FG_LIGHT)]
    )

    # Checkbutton Stilleri
    style.configure("TCheckbutton",
        background=BG_DARK,
        foreground=FG_LIGHT,
        font=("Segoe UI", 9)
    )
    style.map("TCheckbutton",
        background=[("active", BG_DARK)],
        foreground=[("active", FG_LIGHT)]
    )

    # Notebook (Sekme) Stilleri
    style.configure("TNotebook",
        background=BG_DARK,
        bordercolor=COLOR_BORDER,
        tabmargins=[2, 4, 2, 0]
    )
    style.configure("TNotebook.Tab",
        background=BG_CARD,
        foreground=FG_MUTED,
        padding=(15, 6),
        font=("Segoe UI", 9, "bold"),
        bordercolor=COLOR_BORDER
    )
    style.map("TNotebook.Tab",
        background=[("selected", BG_DARK), ("active", BG_CARD_ALT)],
        foreground=[("selected", COLOR_ACCENT), ("active", FG_LIGHT)]
    )
