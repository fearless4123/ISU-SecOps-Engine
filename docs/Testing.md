# ISU SecOps Engine - Test ve Doğrulama Dokümantasyonu (Testing)

Sistemin siber güvenlik denetim yeteneklerini doğrulamak için yönergeler.

---

## 🧪 Fiziksel ve Ağ Katmanı Testleri

### 1. 🌍 Geo-IP & Intelligence Doğrulaması
Sunucunun fiziksel konumunun ve ISS (ISP) bilgisinin doğru çekildiğini doğrularız.
- **Hedef**: `google.com`
- **Beklenen**: United States / Mountain View (Google LLC).
```powershell
./secops.exe pentest ssl-check google.com
```

### 2. 🌳 Trust Chain (Güven Zinciri) Testi
Eksik "Intermediate" sertifikası olan sunucuların tespit edilip edilmediği kontrol edilir.
- **Hiyerarşi Ağacı**: Terminalde `●*.google.com -> ┗━GTS -> ┗━GlobalSign` şeklinde (veya güncel zincir) göründüğü doğrulanır.

---

## 🛡️ Güvenlik Denetim Testleri (Compliance)

### 1. 🛡️ Security Headers Analizi
Sunucunun güvenlik başlıklarını (`CSP`, `X-Frame`) bypass edip etmediği veya eksik olup olmadığı kontrol edilir.
- **Senaryo**: `bing.com` veya `yahoo.com` gibi farklı yapılandırılmış domainler üzerindeki başlıklar denetlenir.

### 2. ⚠️ Zafiyet Probları (Vuln Probes)
Aktif handshake denemeleriyle eski protokollerin reddedildiği doğrulanır.
- **POODLE**: SSLv3 desteği olan bir test sunucusunda (örneğin `badssl.com` alt domainleri) sistemin **"F"** puanı verdiği kontrol edilir.

---

## 📋 Fonksiyonel Testler (Batch & Monitoring)

### 1. 📂 Toplu Tarama Modeli
`targets.txt` dosyası yardımıyla çoklu tarama ve raporlama test edilir.
```powershell
# Hazırlık
echo "google.com" > targets.txt
echo "bing.com" >> targets.txt

# Çalıştırma
./secops.exe pentest ssl-check --file targets.txt --json reports
```
- **Beklenen**: `reports/` klasörü altında her host için ayrı JSON raporu oluşturulmalıdır.

---

## 🎨 Arayüz ve Sunum Doğrulaması

### 1. 💎 Web Dashboard Canlı Analiz
API'nin dashboard'u engellemeden (`asynchronous`) veri aktardığı gözlemlenir.

### 2. 📄 PDF Rapor Tasarımı
Dashboard üzerindeki "Download PDF" butonuna basıldığında, tarayıcının `@media print` CSS kurallarını kullanarak sadece sonuç kartlarını (ve arama kutusunu gizleyerek) sayfaya döktüğü kontrol edilir.
