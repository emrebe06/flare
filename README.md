# Flare

Flare; iş ilanı, ürün ilanı, ödeme linki ve mesaj metinlerini pasif şekilde inceleyen taşınabilir risk analiz aracıdır.

## Ne Söyler?

Flare özellikle iş ilanlarında şu tarz net karar üretir:

- `Başvurulabilir`
- `Dikkatli başvur / önce sor`
- `Doğrula, sonra başvur`
- `Başvurma`
- `Başvurma / önce doğrula`

Ayrıca şunları raporlar:

- Sahte iş ilanı olasılığı
- Gereksiz/spam ilan olasılığı
- İlan kalite puanı
- Aşırı kapsam puanı
- Tek ilanda birden fazla meslek istenip istenmediği
- Maaş, lokasyon, çalışma şekli, görev tanımı ve başvuru kanalı eksikleri
- IBAN, Papara, banka hesabı kullandırma, ön ödeme, evrak/sigorta ücreti ve WhatsApp'a taşıma riskleri
- Çok eski veya okunamayan ilan uyarıları

## Kurulum

Python 3.10 veya üstü gerekir.

Windows:

```bat
cd flare
python bootstrap_flare.py
.venv\Scripts\python.exe run_flare.py
```

Linux/macOS:

```bash
cd flare
python3 bootstrap_flare.py
.venv/bin/python run_flare.py
```

## Hızlı Kullanım

GUI:

```bash
python run_flare.py
```

CLI:

```bash
python run_flare.py --cli "https://www.linkedin.com/jobs/view/123"
python run_flare.py --cli "Evden paketleme işi WhatsApp IBAN Papara hesabı aç"
```

URL'den HTML indirip JSON/TXT rapor üretmek:

```bash
python download_and_scan.py "https://www.eleman.net/is-ilani/ornek" --format json
python download_and_scan.py "https://www.eleman.net/is-ilani/ornek" --format txt
```

## HTML Okunamazsa

Bazı siteler otomatik HTML indirmeyi engelleyebilir. Bu durumda:

1. Linki normal tarayıcıda açın.
2. Sayfayı HTML olarak kaydedin.
3. Flare GUI içinde `Dosyadan Analiz Et (HTML/PDF)` ile yükleyin.

## Güvenlik Notu

Flare pasif analiz yapar. Exploit, brute-force, yetkisiz erişim veya koruma aşma denemesi yapmaz. Sonuçlar kesin hüküm değil, karar vermeye yardımcı risk sinyalidir.
