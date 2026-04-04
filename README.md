# 🛡️ ISU SecOps Engine v0.5.0
### Professional SSL/TLS Security Analyzer & Compliance Auditor

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/audit-High--Fidelity-success)](https://github.com/)

**ISU SecOps Engine**, modern web altyapıları için geliştirilmiş, yüksek performanslı ve asenkron bir SSL/TLS güvenlik denetim motorudur. Basit bir sertifika tarayıcısından öte, kurumsal düzeyde uyumluluk analizi (Compliance), aktif zafiyet taraması ve küresel istihbarat özellikleri sunar.

# 🛡️ ISU SecOps Engine
**Professional SSL/TLS Security Auditor & Pentest Engine**

The ISU SecOps Engine is a high-performance terminal utility written in Rust, designed for deep security auditing of SSL/TLS configurations. It provides instant visibility into certificate health, protocol vulnerabilities (POODLE, SSLv3), and global server intelligence.

---

## 🚀 Speedrun: No-EXE Usage
This tool is designed to be run directly via the Rust toolchain for maximum transparency and performance.

### 1. Audit a Single Host
```bash
cargo run -- google.com --grade
```
*Gives you a full intelligence report, certificate analysis, and a security grade (A-F).*

### 2. Batch Audit (Multiple Hosts)
Prepare a `targets.txt` file with one domain per line, then run:
```bash
cargo run -- --file targets.txt --grade
```

### 3. Enumerate Cipher Suites
To perform an active probe of all supported encryption algorithms:
```bash
cargo run -- google.com --ciphers
```

---

## 📊 Key Features
- **Global Intel:** Detects Server IP, ISP, and ASN physical location.
- **Vulnerability Probing:** Active checks for SSLv3 and deprecated protocols.
- **CT Log Verification:** Checks if certificates are properly logged in Certificate Transparency.
- **Professional Repoting:** Outputs structured, colored tables and optional JSON exports.
- **Grade System:** Industry-standard A+ to F grading based on security posture.

---

## 🛠️ Requirements
- [Rust & Cargo](https://rust-app.org/learn/get-started) (Latest stable)
- OpenSSL Development headers

---
*Developed by Antigravity Security - Optimized for terminal-native workflows.*

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