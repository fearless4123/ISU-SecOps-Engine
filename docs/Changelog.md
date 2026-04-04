# AegisTLS - Değişiklik Kaydı ve Sürüm Notları (Changelog)

Sürüm v0.5.0 itibarıyla tüm modüler gelişim süreci.

---

## [v0.5.0] - "Ultra Intelligence Update" 🚀
### Yeni Özellikler
- **Modül 21 (Certificate Transparency)**: Sertifikanın Google/Apple CT loglarındaki durumu anlık olarak sorgulanıyor.
- **Modül 23 (Global Geo-IP)**: `ip-api.com` entegrasyonu ile sunucunun Şehir, Ülke, ISP ve ASN bilgileri asenkron çekiliyor.
- **Modül 17 (Security Headers Audit)**: `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` başlıkları denetlenmeye başlandı.
- **Modül 18 (Trust Chain Hub)**: Güven zinciri (Root -> Leaf) terminal ve Web'de hiyerarşik ağaç olarak görselleştirildi.
- **Modül 19 (Vuln Probes)**: POODLE (SSLv3) ve Export Ciphers (Logjam) için aktif el sıkışma probları eklendi.
- **Modül 20 (Batch Support)**: `--file` parametresi ile toplu tarama ve otomatik JSON raporlama desteği geldi.

---

## [v0.3.0] - "Web Dashboard & Reporting" 💎
### Yeni Özellikler
- **Modül 9 (Glassmorphism Dashboard)**: Modern, canlı ve asenkron Web arayüzü yayına alındı.
- **Modül 11 (HSTS Check)**: `Strict-Transport-Security` başlığı denetimi eklendi.
- **Modül 14 (DNS CAA Records)**: Sertifika yetkilendirme politikalarının DNS sorgusu ile doğrulanması sağlandı.
- **Modül 15 (OCSP Revocation)**: AIA extension parsing ile sertifika iptal kontrolleri entegre edildi.
- **Modül 16 (PDF Export)**: Web Dashboard üzerinden "Print-to-PDF" butonu ile profesyonel rapor alma imkanı eklendi.

---

## [v0.1.0] - "Core Engine Alpha" ⚙️
### Yeni Özellikler
- **Modül 1-3**: Temel TLS el sıkışma motoru ve X.509 ayrıştırıcı.
- **Modül 4-6**: RSA/ECDSA anahtar güçleri ve imza algoritmaları doğrulaması.
- **Modül 7-8**: Protokol destek matrisi (TLS 1.0 - 1.3) ve Harf tabanlı puanlama sistemi (`A+` - `F`).
- **Modül 12**: Cipher suite enumeration (Şifreleme algoritmaları listeleme) yeteneği.

---
**Gelecek Sürüm (v0.6.0):** Server Intelligence (Banner/Version CVEs) ve Monitoring Mode (CLI Cron).
