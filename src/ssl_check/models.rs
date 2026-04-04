use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CertInfo {
    pub common_name: String,
    pub subject_alt_names: Vec<String>,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub is_valid: bool,
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
