use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CipherInfo {
    pub name: String,
    pub strength: String,
    pub recommendation: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertInfo {
    pub common_name: String,
    pub subject_alt_names: Vec<String>,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub is_valid: bool,
    pub key_info: String,
    pub signature_algorithm: String,
    pub cipher_suite: String,
    pub hsts_enabled: bool,
    pub revocation_status: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TlsVersionInfo {
    pub version: String,
    pub supported: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SslAnalysis {
    pub host: String,
    pub certificate: Option<CertInfo>,
    pub tls_versions: Vec<TlsVersionInfo>,
    pub supported_ciphers: Vec<CipherInfo>,
    pub caa_records: Vec<String>,
    pub grade: String,
}
