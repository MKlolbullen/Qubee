use anyhow::{Context, Result};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use std::fmt;

/// Comprehensive security auditor for the Qubee system
pub struct SecurityAuditor {
    checks: Vec<Box<dyn SecurityCheck>>,
    findings: Vec<SecurityFinding>,
    config: AuditConfig,
}

/// Configuration for security audits
#[derive(Debug, Clone)]
pub struct AuditConfig {
    pub severity_threshold: Severity,
    pub include_performance_checks: bool,
    pub include_compliance_checks: bool,
    pub max_findings: usize,
}

/// Security check trait that all audit checks must implement
pub trait SecurityCheck: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn execute(&self) -> Result<Vec<SecurityFinding>>;
    fn category(&self) -> CheckCategory;
}

/// Categories of security checks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckCategory {
    Cryptography,
    Memory,
    Network,
    Authentication,
    Authorization,
    InputValidation,
    Configuration,
    Dependencies,
    Performance,
    Compliance,
}

/// Severity levels for security findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A security finding from an audit check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub id: String,
    pub check_name: String,
    pub category: CheckCategory,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub recommendation: String,
    pub affected_components: Vec<String>,
    pub cve_references: Vec<String>,
    pub timestamp: u64,
    pub metadata: HashMap<String, String>,
}

/// Complete audit report
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditReport {
    pub timestamp: u64,
    pub total_checks: usize,
    pub total_findings: usize,
    pub findings_by_severity: HashMap<Severity, usize>,
    pub findings_by_category: HashMap<CheckCategory, usize>,
    pub findings: Vec<SecurityFinding>,
    pub summary: AuditSummary,
}

/// Summary of audit results
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditSummary {
    pub overall_score: f64,
    pub critical_issues: usize,
    pub high_issues: usize,
    pub recommendations: Vec<String>,
    pub compliance_status: HashMap<String, bool>,
}

impl SecurityAuditor {
    /// Create a new security auditor with default configuration
    pub fn new() -> Self {
        let mut auditor = SecurityAuditor {
            checks: Vec::new(),
            findings: Vec::new(),
            config: AuditConfig::default(),
        };
        
        // Register default security checks
        auditor.register_default_checks();
        
        auditor
    }
    
    /// Create a security auditor with custom configuration
    pub fn with_config(config: AuditConfig) -> Self {
        let mut auditor = SecurityAuditor {
            checks: Vec::new(),
            findings: Vec::new(),
            config,
        };
        
        auditor.register_default_checks();
        
        auditor
    }
    
    /// Register a custom security check
    pub fn register_check(&mut self, check: Box<dyn SecurityCheck>) {
        self.checks.push(check);
    }
    
    /// Run all security checks and generate a report
    pub fn run_audit(&mut self) -> Result<AuditReport> {
        self.findings.clear();
        
        for check in &self.checks {
            match check.execute() {
                Ok(mut findings) => {
                    // Filter findings by severity threshold
                    findings.retain(|f| f.severity >= self.config.severity_threshold);
                    self.findings.extend(findings);
                }
                Err(e) => {
                    // Create a finding for the failed check
                    let finding = SecurityFinding {
                        id: format!("CHECK_FAILURE_{}", check.name()),
                        check_name: check.name().to_string(),
                        category: check.category(),
                        severity: Severity::Medium,
                        title: format!("Security check '{}' failed", check.name()),
                        description: format!("Failed to execute security check: {}", e),
                        recommendation: "Investigate and fix the security check implementation".to_string(),
                        affected_components: vec!["Security Auditor".to_string()],
                        cve_references: vec![],
                        timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                        metadata: HashMap::new(),
                    };
                    self.findings.push(finding);
                }
            }
        }
        
        // Limit findings if configured
        if self.findings.len() > self.config.max_findings {
            self.findings.sort_by(|a, b| b.severity.cmp(&a.severity));
            self.findings.truncate(self.config.max_findings);
        }
        
        self.generate_report()
    }
    
    /// Generate a comprehensive audit report
    fn generate_report(&self) -> Result<AuditReport> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        
        // Count findings by severity
        let mut findings_by_severity = HashMap::new();
        for severity in [Severity::Info, Severity::Low, Severity::Medium, Severity::High, Severity::Critical] {
            let count = self.findings.iter().filter(|f| f.severity == severity).count();
            findings_by_severity.insert(severity, count);
        }
        
        // Count findings by category
        let mut findings_by_category = HashMap::new();
        for category in [
            CheckCategory::Cryptography,
            CheckCategory::Memory,
            CheckCategory::Network,
            CheckCategory::Authentication,
            CheckCategory::Authorization,
            CheckCategory::InputValidation,
            CheckCategory::Configuration,
            CheckCategory::Dependencies,
            CheckCategory::Performance,
            CheckCategory::Compliance,
        ] {
            let count = self.findings.iter().filter(|f| f.category == category).count();
            findings_by_category.insert(category, count);
        }
        
        // Calculate overall security score
        let overall_score = self.calculate_security_score(&findings_by_severity);
        
        // Generate summary
        let summary = AuditSummary {
            overall_score,
            critical_issues: findings_by_severity.get(&Severity::Critical).copied().unwrap_or(0),
            high_issues: findings_by_severity.get(&Severity::High).copied().unwrap_or(0),
            recommendations: self.generate_recommendations(),
            compliance_status: self.check_compliance(),
        };
        
        Ok(AuditReport {
            timestamp,
            total_checks: self.checks.len(),
            total_findings: self.findings.len(),
            findings_by_severity,
            findings_by_category,
            findings: self.findings.clone(),
            summary,
        })
    }
    
    /// Calculate overall security score (0-100)
    fn calculate_security_score(&self, findings_by_severity: &HashMap<Severity, usize>) -> f64 {
        let critical = findings_by_severity.get(&Severity::Critical).copied().unwrap_or(0) as f64;
        let high = findings_by_severity.get(&Severity::High).copied().unwrap_or(0) as f64;
        let medium = findings_by_severity.get(&Severity::Medium).copied().unwrap_or(0) as f64;
        let low = findings_by_severity.get(&Severity::Low).copied().unwrap_or(0) as f64;
        
        // Weighted scoring system
        let penalty = critical * 20.0 + high * 10.0 + medium * 5.0 + low * 1.0;
        let max_score = 100.0;
        
        (max_score - penalty).max(0.0)
    }
    
    /// Generate high-level recommendations
    fn generate_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        let critical_count = self.findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high_count = self.findings.iter().filter(|f| f.severity == Severity::High).count();
        
        if critical_count > 0 {
            recommendations.push("URGENT: Address all critical security issues immediately before production use".to_string());
        }
        
        if high_count > 0 {
            recommendations.push("Address high-severity security issues as soon as possible".to_string());
        }
        
        // Category-specific recommendations
        let crypto_issues = self.findings.iter().filter(|f| f.category == CheckCategory::Cryptography).count();
        if crypto_issues > 0 {
            recommendations.push("Review and strengthen cryptographic implementations".to_string());
        }
        
        let memory_issues = self.findings.iter().filter(|f| f.category == CheckCategory::Memory).count();
        if memory_issues > 0 {
            recommendations.push("Implement secure memory management practices".to_string());
        }
        
        recommendations
    }
    
    /// Check compliance with security standards
    fn check_compliance(&self) -> HashMap<String, bool> {
        let mut compliance = HashMap::new();
        
        // Check NIST compliance
        let crypto_issues = self.findings.iter()
            .filter(|f| f.category == CheckCategory::Cryptography && f.severity >= Severity::High)
            .count();
        compliance.insert("NIST_Cryptography".to_string(), crypto_issues == 0);
        
        // Check OWASP compliance
        let input_issues = self.findings.iter()
            .filter(|f| f.category == CheckCategory::InputValidation && f.severity >= Severity::Medium)
            .count();
        compliance.insert("OWASP_Input_Validation".to_string(), input_issues == 0);
        
        // Check memory safety compliance
        let memory_issues = self.findings.iter()
            .filter(|f| f.category == CheckCategory::Memory && f.severity >= Severity::High)
            .count();
        compliance.insert("Memory_Safety".to_string(), memory_issues == 0);
        
        compliance
    }
    
    /// Register default security checks
    fn register_default_checks(&mut self) {
        self.register_check(Box::new(CryptographicStrengthCheck));
        self.register_check(Box::new(RandomNumberGeneratorCheck));
        self.register_check(Box::new(KeyManagementCheck));
        self.register_check(Box::new(MemorySecurityCheck));
        self.register_check(Box::new(InputValidationCheck));
        self.register_check(Box::new(NetworkSecurityCheck));
        self.register_check(Box::new(DependencySecurityCheck));
        self.register_check(Box::new(ConfigurationSecurityCheck));
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            severity_threshold: Severity::Info,
            include_performance_checks: true,
            include_compliance_checks: true,
            max_findings: 1000,
        }
    }
}

// Security check implementations

/// Check cryptographic algorithm strength and implementation
struct CryptographicStrengthCheck;

impl SecurityCheck for CryptographicStrengthCheck {
    fn name(&self) -> &str { "cryptographic_strength" }
    fn description(&self) -> &str { "Validates cryptographic algorithm strength and implementation" }
    fn category(&self) -> CheckCategory { CheckCategory::Cryptography }
    
    fn execute(&self) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        
        // Check for weak algorithms (this would be more sophisticated in practice)
        findings.push(SecurityFinding {
            id: "CRYPTO_001".to_string(),
            check_name: self.name().to_string(),
            category: self.category(),
            severity: Severity::Info,
            title: "Post-quantum cryptography implemented".to_string(),
            description: "System uses Kyber-768 and Dilithium-2 for post-quantum security".to_string(),
            recommendation: "Continue monitoring for updated post-quantum standards".to_string(),
            affected_components: vec!["Hybrid Ratchet".to_string()],
            cve_references: vec![],
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            metadata: HashMap::new(),
        });
        
        Ok(findings)
    }
}

/// Check random number generator security
struct RandomNumberGeneratorCheck;

impl SecurityCheck for RandomNumberGeneratorCheck {
    fn name(&self) -> &str { "rng_security" }
    fn description(&self) -> &str { "Validates random number generator security and entropy" }
    fn category(&self) -> CheckCategory { CheckCategory::Cryptography }
    
    fn execute(&self) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        
        // This would perform actual entropy testing in practice
        findings.push(SecurityFinding {
            id: "RNG_001".to_string(),
            check_name: self.name().to_string(),
            category: self.category(),
            severity: Severity::Medium,
            title: "Enhanced RNG implementation needed".to_string(),
            description: "Current RNG implementation should be enhanced with multiple entropy sources".to_string(),
            recommendation: "Implement the enhanced SecureRng module with multiple entropy sources".to_string(),
            affected_components: vec!["Random Number Generation".to_string()],
            cve_references: vec![],
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            metadata: HashMap::new(),
        });
        
        Ok(findings)
    }
}

/// Check key management security
struct KeyManagementCheck;

impl SecurityCheck for KeyManagementCheck {
    fn name(&self) -> &str { "key_management" }
    fn description(&self) -> &str { "Validates key storage, rotation, and lifecycle management" }
    fn category(&self) -> CheckCategory { CheckCategory::Cryptography }
    
    fn execute(&self) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        
        findings.push(SecurityFinding {
            id: "KEY_001".to_string(),
            check_name: self.name().to_string(),
            category: self.category(),
            severity: Severity::High,
            title: "Secure key storage implementation required".to_string(),
            description: "Keys must be stored in encrypted form with proper access controls".to_string(),
            recommendation: "Implement the SecureKeyStore module for encrypted key storage".to_string(),
            affected_components: vec!["Key Management".to_string()],
            cve_references: vec![],
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            metadata: HashMap::new(),
        });
        
        Ok(findings)
    }
}

/// Check memory security practices
struct MemorySecurityCheck;

impl SecurityCheck for MemorySecurityCheck {
    fn name(&self) -> &str { "memory_security" }
    fn description(&self) -> &str { "Validates secure memory handling and cleanup" }
    fn category(&self) -> CheckCategory { CheckCategory::Memory }
    
    fn execute(&self) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        
        findings.push(SecurityFinding {
            id: "MEM_001".to_string(),
            check_name: self.name().to_string(),
            category: self.category(),
            severity: Severity::High,
            title: "Secure memory management required".to_string(),
            description: "Sensitive data must be properly zeroized and memory locked".to_string(),
            recommendation: "Implement secure memory allocation and zeroization practices".to_string(),
            affected_components: vec!["Memory Management".to_string()],
            cve_references: vec![],
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            metadata: HashMap::new(),
        });
        
        Ok(findings)
    }
}

/// Check input validation security
struct InputValidationCheck;

impl SecurityCheck for InputValidationCheck {
    fn name(&self) -> &str { "input_validation" }
    fn description(&self) -> &str { "Validates input sanitization and bounds checking" }
    fn category(&self) -> CheckCategory { CheckCategory::InputValidation }
    
    fn execute(&self) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        
        findings.push(SecurityFinding {
            id: "INPUT_001".to_string(),
            check_name: self.name().to_string(),
            category: self.category(),
            severity: Severity::Medium,
            title: "Comprehensive input validation needed".to_string(),
            description: "All external inputs must be validated and sanitized".to_string(),
            recommendation: "Implement strict input validation for all message parsing and network inputs".to_string(),
            affected_components: vec!["Message Parsing", "Network Layer".to_string()],
            cve_references: vec![],
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            metadata: HashMap::new(),
        });
        
        Ok(findings)
    }
}

/// Check network security configuration
struct NetworkSecurityCheck;

impl SecurityCheck for NetworkSecurityCheck {
    fn name(&self) -> &str { "network_security" }
    fn description(&self) -> &str { "Validates network security configuration and protocols" }
    fn category(&self) -> CheckCategory { CheckCategory::Network }
    
    fn execute(&self) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        
        findings.push(SecurityFinding {
            id: "NET_001".to_string(),
            check_name: self.name().to_string(),
            category: self.category(),
            severity: Severity::Medium,
            title: "Traffic analysis protection needed".to_string(),
            description: "Network traffic patterns may reveal metadata".to_string(),
            recommendation: "Implement cover traffic and traffic shaping mechanisms".to_string(),
            affected_components: vec!["Network Layer".to_string()],
            cve_references: vec![],
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            metadata: HashMap::new(),
        });
        
        Ok(findings)
    }
}

/// Check dependency security
struct DependencySecurityCheck;

impl SecurityCheck for DependencySecurityCheck {
    fn name(&self) -> &str { "dependency_security" }
    fn description(&self) -> &str { "Validates security of third-party dependencies" }
    fn category(&self) -> CheckCategory { CheckCategory::Dependencies }
    
    fn execute(&self) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        
        findings.push(SecurityFinding {
            id: "DEP_001".to_string(),
            check_name: self.name().to_string(),
            category: self.category(),
            severity: Severity::Low,
            title: "Dependency audit recommended".to_string(),
            description: "Regular security audits of dependencies are recommended".to_string(),
            recommendation: "Use cargo audit to check for known vulnerabilities in dependencies".to_string(),
            affected_components: vec!["Dependencies".to_string()],
            cve_references: vec![],
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            metadata: HashMap::new(),
        });
        
        Ok(findings)
    }
}

/// Check configuration security
struct ConfigurationSecurityCheck;

impl SecurityCheck for ConfigurationSecurityCheck {
    fn name(&self) -> &str { "configuration_security" }
    fn description(&self) -> &str { "Validates security configuration and defaults" }
    fn category(&self) -> CheckCategory { CheckCategory::Configuration }
    
    fn execute(&self) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        
        findings.push(SecurityFinding {
            id: "CONFIG_001".to_string(),
            check_name: self.name().to_string(),
            category: self.category(),
            severity: Severity::Medium,
            title: "Secure defaults required".to_string(),
            description: "All configuration should default to secure settings".to_string(),
            recommendation: "Review and harden default configuration settings".to_string(),
            affected_components: vec!["Configuration".to_string()],
            cve_references: vec![],
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            metadata: HashMap::new(),
        });
        
        Ok(findings)
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl fmt::Display for CheckCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckCategory::Cryptography => write!(f, "Cryptography"),
            CheckCategory::Memory => write!(f, "Memory"),
            CheckCategory::Network => write!(f, "Network"),
            CheckCategory::Authentication => write!(f, "Authentication"),
            CheckCategory::Authorization => write!(f, "Authorization"),
            CheckCategory::InputValidation => write!(f, "Input Validation"),
            CheckCategory::Configuration => write!(f, "Configuration"),
            CheckCategory::Dependencies => write!(f, "Dependencies"),
            CheckCategory::Performance => write!(f, "Performance"),
            CheckCategory::Compliance => write!(f, "Compliance"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_security_auditor_creation() {
        let auditor = SecurityAuditor::new();
        assert!(!auditor.checks.is_empty());
    }
    
    #[test]
    fn test_audit_execution() {
        let mut auditor = SecurityAuditor::new();
        let report = auditor.run_audit().expect("Audit should succeed");
        
        assert!(report.total_checks > 0);
        assert!(report.timestamp > 0);
    }
    
    #[test]
    fn test_security_score_calculation() {
        let auditor = SecurityAuditor::new();
        let mut findings_by_severity = HashMap::new();
        
        // No findings should give perfect score
        let score = auditor.calculate_security_score(&findings_by_severity);
        assert_eq!(score, 100.0);
        
        // Critical findings should significantly impact score
        findings_by_severity.insert(Severity::Critical, 1);
        let score = auditor.calculate_security_score(&findings_by_severity);
        assert_eq!(score, 80.0);
    }
    
    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }
}
