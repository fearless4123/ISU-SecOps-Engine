# AegisTLS - Sistem Mimarisi (Architecture)

**AegisTLS**, siber güvenlik araçları için en yüksek performans ve asenkron veri işleme standartlarını (Rust + Tokio) temel alır.

---

## 🏗️ Katmanlı Mimari (Layered Architecture)

Sistem üç ana katmandan oluşur:

### 1. 🛡️ Analysis Engine (Analiz Laboratuvarı)
`src/ssl_check/` dizini altında bulunan ve sunucu üzerindeki aktif denetleri yürüten modüldür.
- **Protokol Denetçisi**: TLS 1.0'dan 1.3'e kadar tüm el sıkışmalarını destekler.
- **Zafiyet Probları**: Sunucu tipine ve cipher suitelere göre özel el sıkışma paketleri üreterek güvenlik açıklarını (Heartbleed, POODLE) tespit eder.
- **Sertifika Ayrıştırıcı**: X.509 DER formatındaki sertifikaları Rust veri yapılarına asenkron olarak çevirir.

### 2. 🌍 Intelligence & Intel (İstihbarat)
Sunucunun sadece SSL yapılandırmasına değil, bulunduğu ekosisteme de bakar.
- **Geo-IP Integration**: `ip-api.com` üzerinden City, Country, ISP ve ASN bilgilerini asenkron olarak çeker.
- **CT Log Auditor**: Sertifikaların şeffaflık loglarında olup olmadığını (Transparency) kontrol eder.

### 3. 🖥️ Presentation Layer (Sunum Katmanı)
- **CLI (Terminal)**: `clap` ile yapılandırılmış ve renklendirilmiş terminal çıktıları sağlar.
- **Web UI (Axum)**: `axum` tabanlı bir API ve `rust-embed` ile binary içine gömülmüş statik dosyalar.

---

## 📡 Veri Akışı Şeması (Data Flow Diagram)

1. **Input**: Kullanıcı Domain/IP bilgisini CLI veya Web üzerinden girer.
2. **DNS Resolver**: Asenkron olarak host çözümlemesi yapılır.
3. **Parallel Scans**: 
    - TLS Handshakes (Farklı versiyon ve cipherlar için).
    - Geo-IP Intelligence Fetching.
    - Security Headers Auditing.
4. **Processing**: Tüm veriler `SslAnalysis` modelinde toplanır.
5. **Grading Engine**: Veriler industry standard (SSL Labs) mantığıyla puanlanır.
6. **Result**: Çıktı terminale basılır, JSON dosyasın yazılır veya Web Dashboard güncellenir.

---
**Teknoloji Yığını:** Rust | OpenSSL | Tokio | Axum | Serde | Reqwest
