# Flare

Flare, ilan ve iş ilanı dolandırıcılığına karşı pasif risk analizi yapan temiz paket sürümüdür.

Bu klasör çalıştırılabilir dağıtım içindir. C++ kaynak kodu veya header dosyası içermez. Native çekirdek yalnızca hazır binary olarak gelir:

- `native/libstarfall_core.dll` Windows için
- `native/libstarfall_core.so` Linux için
- `native/libstarfall_core.dylib` macOS için

## Ne Analiz Eder?

Flare şu durumları ayrı ayrı anlamaya çalışır:

- Gerçek sitede kötü niyetli ilan veya ilan sahibi
- Sahte site üzerinden IBAN / ödeme kandırması
- İş ilanı bahanesiyle IBAN, Papara veya banka hesabı kullandırma
- Başvuru, eğitim, evrak veya sigorta ücreti isteyen sahte iş akışları
- Kapora, ön ödeme, rezervasyon veya acele baskısı
- WhatsApp / Telegram / DM gibi platform dışı iletişim
- Kimlik, SMS kodu, doğrulama kodu veya hesap ele geçirme senaryoları
- Kurye, kargo veya sigorta ücreti bahanesi

## İlk Kurulum

Python 3.10 veya üstü önerilir.

Windows PowerShell veya terminalde:

```bash
cd "%USERPROFILE%\Desktop\flare"
python bootstrap_flare.py
```

Bu komut otomatik olarak:

- `.venv` sanal ortamı oluşturur
- `pip` günceller
- `requirements.txt` içindeki paketleri kurar
- native binary dosyalarını kontrol eder
- testleri çalıştırır
- örnek bir CLI analizi yapar

## Hızlı Kullanım

CLI ile örnek analiz:

```bash
python run_flare.py --cli "https://www.sahibinden.com/ilan/vasita-otomobil" "kapora at WhatsApp'tan yaz IBAN veriyorum"
```

GUI açmak için:

```bash
python run_flare.py
```

## Önemli Not

Bu araç kesin hüküm vermez. Pasif risk sinyali üretir. Şüpheli durumda ödeme yapmayın, platform dışına çıkmayın, kanıtları saklayın ve resmi kanallardan doğrulama yapın.
