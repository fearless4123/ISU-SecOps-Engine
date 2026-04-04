use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertInfo {
    pub common_name: String,
    pub subject_alt_names: Vec<String>,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub is_valid: bool,
    pub key_info: String,          // e.g., "RSA 2048 bits"
    pub signature_algorithm: String, // e.g., "sha256WithRSAEncryption"
    pub cipher_suite: String,     // e.g., "TLS_AES_256_GCM_SHA384"
    pub hsts_enabled: bool,
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
    pub grade: String,
}
