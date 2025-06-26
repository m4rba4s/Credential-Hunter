/**
 * Compliance Reporting Module
 * 
 * Enterprise compliance assessment for SOC2, PCI-DSS, GDPR, HIPAA,
 * and other regulatory frameworks.
 */

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{Finding, SeverityLevel, FrameworkAssessment};

/// Compliance framework types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceFramework {
    /// SOC 2 Type I/II
    SOC2,
    /// PCI Data Security Standard
    PCIDSS,
    /// General Data Protection Regulation
    GDPR,
    /// Health Insurance Portability and Accountability Act
    HIPAA,
    /// ISO 27001
    ISO27001,
    /// NIST Cybersecurity Framework
    NIST,
    /// Custom framework
    Custom(String),
}

/// Compliance assessment engine
pub struct ComplianceEngine;

impl ComplianceEngine {
    /// Generate compliance assessment for multiple frameworks
    pub fn assess_compliance(findings: &[Finding]) -> Result<HashMap<String, FrameworkAssessment>> {
        let mut assessments = HashMap::new();
        
        // SOC2 Assessment
        assessments.insert("SOC2".to_string(), Self::assess_soc2(findings)?);
        
        // PCI-DSS Assessment  
        assessments.insert("PCI-DSS".to_string(), Self::assess_pcidss(findings)?);
        
        // GDPR Assessment
        assessments.insert("GDPR".to_string(), Self::assess_gdpr(findings)?);
        
        // HIPAA Assessment
        assessments.insert("HIPAA".to_string(), Self::assess_hipaa(findings)?);
        
        Ok(assessments)
    }
    
    /// SOC2 compliance assessment
    fn assess_soc2(findings: &[Finding]) -> Result<FrameworkAssessment> {
        let critical_violations = findings.iter()
            .filter(|f| matches!(f.severity, SeverityLevel::Critical))
            .count();
            
        let high_violations = findings.iter()
            .filter(|f| matches!(f.severity, SeverityLevel::High))
            .count();
        
        // SOC2 focuses on security, availability, processing integrity, confidentiality, privacy
        let security_controls = 25;
        let failed_controls = (critical_violations * 2 + high_violations).min(security_controls);
        let passed_controls = security_controls - failed_controls;
        
        let score = passed_controls as f64 / security_controls as f64;
        
        Ok(FrameworkAssessment {
            name: "SOC 2 Type II".to_string(),
            score,
            passed_controls: passed_controls as u32,
            failed_controls: failed_controls as u32,
            total_controls: security_controls as u32,
            critical_findings: findings.iter()
                .filter(|f| matches!(f.severity, SeverityLevel::Critical))
                .map(|f| f.title.clone())
                .collect(),
        })
    }
    
    /// PCI-DSS compliance assessment
    fn assess_pcidss(findings: &[Finding]) -> Result<FrameworkAssessment> {
        let payment_violations = findings.iter()
            .filter(|f| f.tags.iter().any(|tag| 
                tag.to_lowercase().contains("payment") || 
                tag.to_lowercase().contains("card") ||
                tag.to_lowercase().contains("credit")))
            .count();
            
        let data_protection_controls = 12;
        let failed_controls = payment_violations.min(data_protection_controls);
        let passed_controls = data_protection_controls - failed_controls;
        
        let score = passed_controls as f64 / data_protection_controls as f64;
        
        Ok(FrameworkAssessment {
            name: "PCI-DSS v4.0".to_string(),
            score,
            passed_controls: passed_controls as u32,
            failed_controls: failed_controls as u32,
            total_controls: data_protection_controls as u32,
            critical_findings: findings.iter()
                .filter(|f| f.tags.iter().any(|tag| tag.to_lowercase().contains("payment")))
                .map(|f| f.title.clone())
                .collect(),
        })
    }
    
    /// GDPR compliance assessment
    fn assess_gdpr(findings: &[Finding]) -> Result<FrameworkAssessment> {
        let personal_data_violations = findings.iter()
            .filter(|f| f.tags.iter().any(|tag| 
                tag.to_lowercase().contains("personal") || 
                tag.to_lowercase().contains("pii") ||
                tag.to_lowercase().contains("email") ||
                tag.to_lowercase().contains("user")))
            .count();
            
        let privacy_controls = 8;
        let failed_controls = personal_data_violations.min(privacy_controls);
        let passed_controls = privacy_controls - failed_controls;
        
        let score = passed_controls as f64 / privacy_controls as f64;
        
        Ok(FrameworkAssessment {
            name: "GDPR".to_string(),
            score,
            passed_controls: passed_controls as u32,
            failed_controls: failed_controls as u32,
            total_controls: privacy_controls as u32,
            critical_findings: findings.iter()
                .filter(|f| f.tags.iter().any(|tag| tag.to_lowercase().contains("personal")))
                .map(|f| f.title.clone())
                .collect(),
        })
    }
    
    /// HIPAA compliance assessment
    fn assess_hipaa(findings: &[Finding]) -> Result<FrameworkAssessment> {
        let health_data_violations = findings.iter()
            .filter(|f| f.tags.iter().any(|tag| 
                tag.to_lowercase().contains("health") || 
                tag.to_lowercase().contains("medical") ||
                tag.to_lowercase().contains("patient") ||
                tag.to_lowercase().contains("phi")))
            .count();
            
        let health_controls = 15;
        let failed_controls = health_data_violations.min(health_controls);
        let passed_controls = health_controls - failed_controls;
        
        let score = passed_controls as f64 / health_controls as f64;
        
        Ok(FrameworkAssessment {
            name: "HIPAA".to_string(),
            score,
            passed_controls: passed_controls as u32,
            failed_controls: failed_controls as u32,
            total_controls: health_controls as u32,
            critical_findings: findings.iter()
                .filter(|f| f.tags.iter().any(|tag| tag.to_lowercase().contains("health")))
                .map(|f| f.title.clone())
                .collect(),
        })
    }
}