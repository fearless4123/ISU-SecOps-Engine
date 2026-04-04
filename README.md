# 🛡️ ISU SecOps Engine v0.5.0
### Professional SSL/TLS Security Analyzer & Compliance Auditor

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/audit-High--Fidelity-success)](https://github.com/)

**ISU SecOps Engine**, modern web altyapıları için geliştirilmiş, yüksek performanslı ve asenkron bir SSL/TLS güvenlik denetim motorudur. Basit bir sertifika tarayıcısından öte, kurumsal düzeyde uyumluluk analizi (Compliance), aktif zafiyet taraması ve küresel istihbarat özellikleri sunar.

# 🛡️ ISU SecOps Engine
**Profesyonel SSL/TLS Güvenlik ve Denetim Platformu**

ISU SecOps Engine, Rust dili ile geliştirilmiş, yüksek performanslı, asenkron ve çok katmanlı bir güvenlik analiz aracıdır. Hem terminal tutkunları için gelişmiş bir **CLI** (Komut Satırı Arayüzü) hem de görsel analiz isteyenler için modern bir **Web Dashboard** sunar.

---

## 🚀 Hızlı Başlangıç

Bu proje, herhangi bir `.exe` karmaşasına girmeden doğrudan Rust araç zinciri üzerinden çalıştırılmak üzere optimize edilmiştir.

### 1. İnteraktif Sihirbaz (Wizard) Modu
Komutları ezberlemenize gerek yok! Sadece şunu yazın ve yönergeleri takip edin:
```bash
cargo run -- wizard
```

### 2. Terminal (CLI) Üzerinden Hızlı Tarama
```bash
cargo run -- cli google.com --grade
```
*Sunucu bilgileri, sertifika analitiği ve güvenlik puanı (A-F) anında terminalinizde.*

### 3. Web Dashboard (Görsel Arayüz)
Modern, "Glassmorphism" tasarımlı arayüzü başlatmak için:
```bash
cargo run -- web --port 8080
```
Ardından tarayıcınızda `http://localhost:8080` adresine gidin.

---

## 📊 Ana Özellikler

- **🔍 Derinlikli SSL Analizi:** RSA/ECDSA anahtar güçleri, imza algoritmaları ve sertifika zincir güvenliği kontrolü.
- **🛡️ Zafiyet Taraması:** POODLE ve SSLv3 gibi kritik yapılandırma hatalarının tespiti.
- **🌐 Küresel İstihbarat:** Hedef sunucunun fiziksel konumu (Şehir/Ülke), ISP ve ASN bilgilerinin tespiti.
- **📋 Uyumluluk Kontrolü:** HSTS Politikaları, DNS CAA kayıtları ve Şeffaflık (CT) günlükleri denetimi.
- **💎 Modern Web UI:** Tamamen Türkçe, şık ve gerçek zamanlı analiz portalı.

---

## 🛠️ Gereksinimler

- [Rust & Cargo](https://rust-app.org/learn/get-started) (En son stabil sürüm)
- OpenSSL Geliştirici paketleri

---
*Antigravity Security Team tarafından profesyoneller için geliştirildi.*

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