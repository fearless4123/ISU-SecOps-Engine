# 🛡️ ISU SecOps Engine v0.5.0
### Professional SSL/TLS Security Analyzer & Compliance Auditor

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/audit-High--Fidelity-success)](https://github.com/)

**ISU SecOps Engine**, modern web altyapıları için geliştirilmiş, yüksek performanslı ve asenkron bir SSL/TLS güvenlik denetim motorudur. Basit bir sertifika tarayıcısından öte, kurumsal düzeyde uyumluluk analizi (Compliance), aktif zafiyet taraması ve küresel istihbarat özellikleri sunar.

---

## 🚀 Öne Çıkan Özellikler (Key Features)

- **🔍 Derinlikli Analiz**: RSA/ECDSA anahtar gücü, imza algoritmaları ve SAN kontrolleri.
- **🛡️ Zafiyet Taraması**: Heartbleed, POODLE ve Logjam gibi eksik yapılandırmaları anında tespit eder.
- **🌐 Global Intelligence**: Sunucunun IP tabanlı fiziksel konumu (Geo-IP), ISP bilgisi ve ASN analizi.
- **📋 Uyumluluk (Compliance)**: HSTS, CSP, X-Frame-Options ve DNS CAA kayıtları denetimi.
- **🌳 Trust Chain**: Sertifika güven zincirini (Root -> Intermediate -> Leaf) hiyerarşik olarak görselleştirir.
- **💎 Premium Dashboard**: Glassmorphism arayüzü ile gerçek zamanlı, canlı analiz sonuçları.
- **📄 Raporlama**: CLI üzerinden JSON ve Web üzerinden Print-to-PDF formatında profesyonel çıktılar.

---

## 🛠️ Kurulum (Installation)

Sistemi derlemek için **Rust**, **Visual Studio Build Tools** (Windows) ve **Strawberry Perl** yüklü olmalıdır.

```powershell
# Projeyi klonlayın
git clone https://github.com/isu/secops-engine.git

# Bağımlılıkları yükleyin ve derleyin
cargo build --release
```

---

## 📖 Kullanım Klavuzu (Usage Guide)

### 💻 Command Line Interface (CLI)
Kurumsal denetimler için terminali kullanın:

```powershell
# Tekil bir domaini tüm detaylarıyla tara
./secops.exe pentest ssl-check google.com --grade --ciphers

# Çoklu hedef (Wordlist) kullanarak toplu tarama yap
./secops.exe pentest ssl-check --file targets.txt --json reports/

# Web Arayüzünü başlat
./secops.exe web-ui --port 8080
```

### 🎨 Web Dashboard
Tarayıcınızda `http://localhost:8080` adresine giderek, el sıkışma metriklerinden güven zinciri ağacına kadar her şeyi canlı olarak takip edin.

---

## 📂 Dokümantasyon (Documentation)

Daha detaylı bilgi için `docs/` klasöründeki dosyaları inceleyebilirsiniz:

- [🏗️ **Architecture**](docs/Architecture.md): Sistem tasarımı ve veri akışı.
- [📝 **Changelog**](docs/Changelog.md): Sürüm notları ve 20+ modülün gelişim süreci.
- [🧪 **Testing**](docs/Testing.md): Manuel testler ve zafiyet doğrulama yönergeleri.

---

## ⚖️ Lisans (License)
Bu proje MIT Lisansı altında lisanslanmıştır. Daha fazla bilgi için `LICENSE` dosyasına bakın.

---
**Developed by ISU SecOps Team.**
*"Securing the web, one handshake at a time."*