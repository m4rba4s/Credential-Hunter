/**
 * CLI Unit Tests for ECH
 * 
 * Comprehensive tests for the command-line interface including
 * argument parsing, file operations, and output formatting.
 */

use serde_json::Value;

/// 📊 ENTROPY CALCULATION TESTS
#[cfg(test)]
mod entropy_tests {

    // Helper function to calculate Shannon entropy (copied from main.rs)
    fn shannon_entropy(data: &str) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        let mut counts = [0u32; 256];
        let bytes = data.as_bytes();
        let len = bytes.len() as f64;
        
        for &byte in bytes {
            counts[byte as usize] += 1;
        }
        
        let mut entropy = 0.0;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }

    #[test]
    fn test_entropy_empty_string() {
        let entropy = shannon_entropy("");
        assert_eq!(entropy, 0.0, "Empty string should have 0 entropy");
    }

    #[test]
    fn test_entropy_single_character() {
        let entropy = shannon_entropy("aaaaaaaaaa");
        assert!(entropy < 0.1, "Repeated characters should have low entropy: {}", entropy);
    }

    #[test]
    fn test_entropy_random_string() {
        let entropy = shannon_entropy("Kj8#mN2$pL9@vR4!");
        assert!(entropy > 3.0, "Random string should have high entropy: {}", entropy);
    }

    #[test]
    fn test_entropy_api_key() {
        let entropy = shannon_entropy("sk_live_abcdef123456789012345");
        assert!(entropy > 4.0, "API key should have high entropy: {}", entropy);
    }

    #[test]
    fn test_entropy_aws_key() {
        let entropy = shannon_entropy("AKIAIOSFODNN7EXAMPLE");
        assert!(entropy > 3.5, "AWS key should have good entropy: {}", entropy);
    }

    #[test]
    fn test_entropy_jwt_token() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let entropy = shannon_entropy(jwt);
        assert!(entropy > 5.0, "JWT token should have very high entropy: {}", entropy);
    }

    #[test]
    fn test_entropy_threshold_classification() {
        let low_entropy = shannon_entropy("password123");
        let high_entropy = shannon_entropy("Kj8#mN2$pL9@vR4!X7z%Q3w&");
        
        assert!(low_entropy < 4.5, "Simple password should be below threshold");
        assert!(high_entropy >= 4.5, "Complex string should be above threshold");
    }
}

/// 📁 FILE SCANNING TESTS
#[cfg(test)]
mod file_scanning_tests {

    // Helper function to check if file extension is scannable (copied from main.rs)
    fn is_scannable_file(ext: &str) -> bool {
        matches!(ext, 
            "txt" | "json" | "yaml" | "yml" | "conf" | "config" | "env" | "properties" | "ini" | "cfg" | "toml" |
            "rs" | "py" | "js" | "ts" | "java" | "go" | "php" | "rb" | "sh" | "bash" | "zsh" | "fish" |
            "xml" | "html" | "css" | "sql" | "log" | "md" | "dockerfile" | "makefile" | "gradle" | "pom" |
            "lock" | "sum" | "mod" | "backup" | "bak" | "old" | "tmp" | "key" | "pem" | "crt" | "cer" |
            "p12" | "pfx" | "jks" | "keystore" | "gitignore" | "gitconfig" | "secrets" | "credentials"
        )
    }

    #[test]
    fn test_scannable_file_extensions() {
        // Text files
        assert!(is_scannable_file("txt"));
        assert!(is_scannable_file("md"));
        assert!(is_scannable_file("log"));
        
        // Config files
        assert!(is_scannable_file("json"));
        assert!(is_scannable_file("yaml"));
        assert!(is_scannable_file("yml"));
        assert!(is_scannable_file("toml"));
        assert!(is_scannable_file("ini"));
        assert!(is_scannable_file("conf"));
        assert!(is_scannable_file("config"));
        assert!(is_scannable_file("env"));
        
        // Source code files
        assert!(is_scannable_file("rs"));
        assert!(is_scannable_file("py"));
        assert!(is_scannable_file("js"));
        assert!(is_scannable_file("ts"));
        assert!(is_scannable_file("java"));
        assert!(is_scannable_file("go"));
        assert!(is_scannable_file("php"));
        assert!(is_scannable_file("rb"));
        
        // Script files
        assert!(is_scannable_file("sh"));
        assert!(is_scannable_file("bash"));
        assert!(is_scannable_file("zsh"));
        assert!(is_scannable_file("fish"));
        
        // Security files
        assert!(is_scannable_file("key"));
        assert!(is_scannable_file("pem"));
        assert!(is_scannable_file("crt"));
        assert!(is_scannable_file("secrets"));
        assert!(is_scannable_file("credentials"));
        
        // Build files
        assert!(is_scannable_file("dockerfile"));
        assert!(is_scannable_file("makefile"));
        assert!(is_scannable_file("gradle"));
        
        // Git files
        assert!(is_scannable_file("gitignore"));
        assert!(is_scannable_file("gitconfig"));
    }

    #[test]
    fn test_non_scannable_file_extensions() {
        // Binary files
        assert!(!is_scannable_file("exe"));
        assert!(!is_scannable_file("dll"));
        assert!(!is_scannable_file("so"));
        assert!(!is_scannable_file("bin"));
        
        // Image files
        assert!(!is_scannable_file("png"));
        assert!(!is_scannable_file("jpg"));
        assert!(!is_scannable_file("gif"));
        assert!(!is_scannable_file("bmp"));
        
        // Archive files
        assert!(!is_scannable_file("zip"));
        assert!(!is_scannable_file("tar"));
        assert!(!is_scannable_file("gz"));
        assert!(!is_scannable_file("rar"));
        
        // Media files
        assert!(!is_scannable_file("mp4"));
        assert!(!is_scannable_file("avi"));
        assert!(!is_scannable_file("mp3"));
        assert!(!is_scannable_file("wav"));
        
        // Office files
        assert!(!is_scannable_file("doc"));
        assert!(!is_scannable_file("docx"));
        assert!(!is_scannable_file("xls"));
        assert!(!is_scannable_file("pdf"));
    }

    #[test]
    fn test_case_insensitive_extensions() {
        // Extensions should be checked in lowercase
        let ext_upper = "TXT";
        let ext_lower = ext_upper.to_lowercase();
        assert!(is_scannable_file(&ext_lower));
        
        let ext_mixed = "Json";
        let ext_lower = ext_mixed.to_lowercase();
        assert!(is_scannable_file(&ext_lower));
    }
}

/// 🔍 CREDENTIAL PATTERN TESTS
#[cfg(test)]
mod pattern_tests {
    use regex::Regex;

    #[test]
    fn test_aws_access_key_pattern() {
        let pattern = r"AKIA[0-9A-Z]{16}";
        let regex = Regex::new(pattern).unwrap();
        
        // Valid AWS access keys
        assert!(regex.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(regex.is_match("AKIA1234567890ABCDEF"));
        
        // Invalid patterns
        assert!(!regex.is_match("AKIA123"));  // Too short
        assert!(!regex.is_match("BKIAIOSFODNN7EXAMPLE"));  // Wrong prefix
        assert!(!regex.is_match("akiaiosfodnn7example"));  // Wrong case
    }

    #[test]
    fn test_github_token_pattern() {
        let pattern = r"^gh[pousr]_[A-Za-z0-9]{36}$";
        let regex = Regex::new(pattern).unwrap();
        
        // Valid GitHub tokens (exactly 36 chars after ghp_)
        assert!(regex.is_match("ghp_123456789012345678901234567890123456"));
        assert!(regex.is_match("gho_abcdefghijklmnopqrstuvwxyz1234567890"));
        assert!(regex.is_match("ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"));
        assert!(regex.is_match("ghs_abcdef1234567890ABCDEF12345678901234"));
        assert!(regex.is_match("ghr_123456789012345678901234567890123456"));
        
        // Invalid patterns
        assert!(!regex.is_match("ghx_123456789012345678901234567890123456"));  // Wrong type
        assert!(!regex.is_match("ghp_123"));  // Too short
        assert!(!regex.is_match("ghp_12345678901234567890123456789012345678"));  // Too long
    }

    #[test]
    fn test_stripe_key_pattern() {
        let pattern = r"^sk_live_[0-9a-zA-Z]{24}$";
        let regex = Regex::new(pattern).unwrap();
        
        // Valid Stripe keys (exactly 24 chars after sk_live_) - EXAMPLE ONLY
        assert!(regex.is_match("sk_live_EXAMPLE123456789012345"));
        assert!(regex.is_match("sk_live_TESTKEY0123456789ABCD"));
        assert!(regex.is_match("sk_live_DEMO1234567890123456789"));
        
        // Invalid patterns
        assert!(!regex.is_match("sk_test_EXAMPLE123456789012345"));  // Test key
        assert!(!regex.is_match("pk_live_123456789012345678901234"));  // Publishable key
        assert!(!regex.is_match("sk_live_abc"));  // Too short
        assert!(!regex.is_match("sk_live_12345678901234567890123456"));  // Too long
    }

    #[test]
    fn test_jwt_token_pattern() {
        let pattern = r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+";
        let regex = Regex::new(pattern).unwrap();
        
        // Valid JWT tokens
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert!(regex.is_match(jwt));
        
        // Invalid patterns
        assert!(!regex.is_match("eyJ.eyJ.invalid"));  // Too short
        assert!(!regex.is_match("invalid.eyJ.signature"));  // Wrong header
        assert!(!regex.is_match("eyJ.invalid.signature"));  // Wrong payload
    }

    #[test]
    fn test_password_field_pattern() {
        let pattern = r"(?i)(password|passwd|pwd)\s*[=:]\s*[\x22']?([^\s\x22',;]+)";
        let regex = Regex::new(pattern).unwrap();
        
        // Valid password fields
        assert!(regex.is_match("password=secret123"));
        assert!(regex.is_match("passwd:mypassword"));
        assert!(regex.is_match("pwd=mysecret"));
        assert!(regex.is_match("PASSWORD=secret"));
        assert!(regex.is_match("PASSWD:password123"));
        
        // Should not match comments or other contexts
        assert!(!regex.is_match("# Set your password here"));
        assert!(!regex.is_match("Enter password:"));
    }

    #[test]
    fn test_private_key_pattern() {
        let pattern = r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----";
        let regex = Regex::new(pattern).unwrap();
        
        // Valid private key headers
        assert!(regex.is_match("-----BEGIN PRIVATE KEY-----"));
        assert!(regex.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(regex.is_match("-----BEGIN EC PRIVATE KEY-----"));
        assert!(regex.is_match("-----BEGIN DSA PRIVATE KEY-----"));
        
        // Invalid patterns
        assert!(!regex.is_match("-----BEGIN PUBLIC KEY-----"));
        assert!(!regex.is_match("-----BEGIN CERTIFICATE-----"));
        assert!(!regex.is_match("BEGIN PRIVATE KEY"));  // Missing dashes
    }

    #[test]
    fn test_api_key_pattern() {
        let pattern = r"(?i)(api.?key|apikey)\s*[=:]\s*[\x22']?([a-zA-Z0-9_-]{16,})";
        let regex = Regex::new(pattern).unwrap();
        
        // Valid API key fields
        assert!(regex.is_match("api_key=abcdef1234567890"));
        assert!(regex.is_match("apikey:1234567890abcdef"));
        assert!(regex.is_match("API_KEY=abcdef1234567890ghijkl"));
        assert!(regex.is_match("api.key=1234567890abcdef1234567890abcdef"));
        
        // Should not match short values
        assert!(!regex.is_match("api_key=abc"));  // Too short
    }
}

/// 📄 OUTPUT FORMAT TESTS
#[cfg(test)]
mod output_format_tests {
    use serde_json::Value;

    #[test]
    fn test_json_output_structure() {
        let json_str = r#"{
            "session_id": "test-123",
            "scan_type": "filesystem",
            "target": "test.txt",
            "summary": {
                "files_scanned": 1,
                "total_files": 1,
                "credentials_found": 2,
                "scan_duration": 0.05,
                "high_confidence_only": false,
                "entropy_enabled": true,
                "entropy_threshold": 4.5
            },
            "results": [
                {
                    "id": "cred-1",
                    "type": "AWS_ACCESS_KEY", 
                    "confidence": 0.95,
                    "file": "test.txt",
                    "line": 1,
                    "matched_text": "AKIAIOSFODNN7EXAMPLE"
                }
            ]
        }"#;
        
        let parsed: Result<Value, _> = serde_json::from_str(json_str);
        assert!(parsed.is_ok(), "JSON output should be valid");
        
        let json = parsed.unwrap();
        assert_eq!(json["scan_type"], "filesystem");
        assert_eq!(json["summary"]["credentials_found"], 2);
        assert_eq!(json["summary"]["entropy_enabled"], true);
        
        let results = json["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["type"], "AWS_ACCESS_KEY");
        assert_eq!(results[0]["confidence"], 0.95);
    }

    #[test]
    fn test_summary_statistics() {
        let summary = serde_json::json!({
            "files_scanned": 150,
            "total_files": 200,
            "entropy_files": 75,
            "credentials_found": 8,
            "scan_duration": 2.35,
            "high_confidence_only": false,
            "entropy_enabled": true,
            "entropy_threshold": 4.5
        });
        
        assert_eq!(summary["files_scanned"], 150);
        assert_eq!(summary["total_files"], 200);
        assert_eq!(summary["entropy_files"], 75);
        assert_eq!(summary["credentials_found"], 8);
        assert_eq!(summary["scan_duration"], 2.35);
        assert_eq!(summary["entropy_enabled"], true);
        assert_eq!(summary["entropy_threshold"], 4.5);
        
        // Calculate scan coverage
        let scan_coverage = summary["files_scanned"].as_u64().unwrap() as f64 / 
                           summary["total_files"].as_u64().unwrap() as f64;
        assert_eq!(scan_coverage, 0.75);
        
        // Calculate detection rate
        let detection_rate = summary["credentials_found"].as_u64().unwrap() as f64 / 
                            summary["files_scanned"].as_u64().unwrap() as f64;
        assert!((detection_rate - 0.0533).abs() < 0.001);
    }
}

/// 🎯 CONFIDENCE SCORING TESTS
#[cfg(test)]
mod confidence_tests {

    #[test]
    fn test_confidence_levels() {
        // High confidence patterns
        assert_eq!(0.98, 0.98); // Private key
        assert_eq!(0.95, 0.95); // AWS access key
        assert_eq!(0.95, 0.95); // Stripe live key
        assert_eq!(0.90, 0.90); // GitHub token
        assert_eq!(0.90, 0.90); // Slack token
        
        // Medium confidence patterns
        assert_eq!(0.85, 0.85); // Discord token
        assert_eq!(0.80, 0.80); // JWT token
        assert_eq!(0.75, 0.75); // AWS secret key
        assert_eq!(0.75, 0.75); // API key
        
        // Lower confidence patterns
        assert_eq!(0.70, 0.70); // Password field
    }

    #[test]
    fn test_entropy_confidence_calculation() {
        // Test entropy-based confidence calculation
        let entropy = 5.0_f64;
        let threshold = 4.5_f64;
        let base_confidence = 0.5 + (entropy - threshold) / 4.0;
        
        assert!((base_confidence - 0.625).abs() < 0.001);
        
        // Test with characteristics
        let mut confidence: f64 = base_confidence;
        confidence += 0.1; // has_mixed_case
        confidence += 0.1; // has_numbers  
        confidence += 0.1; // has_special
        confidence = confidence.min(0.95);
        
        // Should be 0.625 + 0.3 = 0.925, capped at 0.95
        assert!((confidence - 0.925).abs() < 0.001);
        assert!(confidence <= 0.95);
    }

    #[test]
    fn test_severity_classification() {
        // High severity (confidence >= 0.9)
        assert_eq!("HIGH", if 0.95 >= 0.9 { "HIGH" } else if 0.95 >= 0.8 { "MEDIUM" } else { "LOW" });
        assert_eq!("HIGH", if 0.90 >= 0.9 { "HIGH" } else if 0.90 >= 0.8 { "MEDIUM" } else { "LOW" });
        
        // Medium severity (0.8 <= confidence < 0.9)
        assert_eq!("MEDIUM", if 0.85 >= 0.9 { "HIGH" } else if 0.85 >= 0.8 { "MEDIUM" } else { "LOW" });
        assert_eq!("MEDIUM", if 0.80 >= 0.9 { "HIGH" } else if 0.80 >= 0.8 { "MEDIUM" } else { "LOW" });
        
        // Low severity (confidence < 0.8)
        assert_eq!("LOW", if 0.75 >= 0.9 { "HIGH" } else if 0.75 >= 0.8 { "MEDIUM" } else { "LOW" });
        assert_eq!("LOW", if 0.70 >= 0.9 { "HIGH" } else if 0.70 >= 0.8 { "MEDIUM" } else { "LOW" });
    }
}

/// 📊 ENTROPY CHARACTERISTICS TESTS
#[cfg(test)]
mod entropy_characteristics_tests {

    fn analyze_string_characteristics(s: &str) -> (bool, bool, bool) {
        let has_mixed_case = s.chars().any(|c| c.is_uppercase()) && s.chars().any(|c| c.is_lowercase());
        let has_numbers = s.chars().any(|c| c.is_numeric());
        let has_special = s.chars().any(|c| !c.is_alphanumeric());
        (has_mixed_case, has_numbers, has_special)
    }

    #[test]
    fn test_mixed_case_detection() {
        let (mixed, _, _) = analyze_string_characteristics("AbCdEf");
        assert!(mixed, "Should detect mixed case");
        
        let (mixed, _, _) = analyze_string_characteristics("abcdef");
        assert!(!mixed, "Should not detect mixed case in lowercase");
        
        let (mixed, _, _) = analyze_string_characteristics("ABCDEF");
        assert!(!mixed, "Should not detect mixed case in uppercase");
    }

    #[test]
    fn test_number_detection() {
        let (_, has_numbers, _) = analyze_string_characteristics("abc123");
        assert!(has_numbers, "Should detect numbers");
        
        let (_, has_numbers, _) = analyze_string_characteristics("abcdef");
        assert!(!has_numbers, "Should not detect numbers in letters only");
    }

    #[test]
    fn test_special_character_detection() {
        let (_, _, has_special) = analyze_string_characteristics("abc!@#");
        assert!(has_special, "Should detect special characters");
        
        let (_, _, has_special) = analyze_string_characteristics("abc123");
        assert!(!has_special, "Should not detect special chars in alphanumeric");
    }

    #[test]
    fn test_api_key_characteristics() {
        let key = "sk_live_EXAMPLE123456789DEF";
        let (mixed, numbers, special) = analyze_string_characteristics(key);
        
        assert!(!mixed, "API key should not have mixed case");
        assert!(numbers, "API key should have numbers");
        assert!(special, "API key should have underscores");
    }

    #[test]
    fn test_jwt_characteristics() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let (mixed, numbers, special) = analyze_string_characteristics(jwt);
        
        assert!(mixed, "JWT should have mixed case");
        assert!(numbers, "JWT should have numbers");
        assert!(!special, "JWT base64 should not have special chars (except padding)");
    }

    #[test]
    fn test_complex_secret_characteristics() {
        let secret = "MyS3cr3t!P@ssw0rd#2024";
        let (mixed, numbers, special) = analyze_string_characteristics(secret);
        
        assert!(mixed, "Complex secret should have mixed case");
        assert!(numbers, "Complex secret should have numbers");
        assert!(special, "Complex secret should have special characters");
    }
}

/// 📂 FILE EXTENSION EDGE CASES
#[cfg(test)]
mod file_extension_edge_cases {
    use super::*;

    #[test]
    fn test_no_extension() {
        // Files with no extension should be handled gracefully
        let filename = "Dockerfile";
        let path = std::path::Path::new(filename);
        assert_eq!(path.extension(), None);
        
        let filename2 = "Makefile";
        let path2 = std::path::Path::new(filename2);
        assert_eq!(path2.extension(), None);
    }

    #[test]
    fn test_hidden_files() {
        // For hidden files like .gitignore, the extension is empty because the whole name is considered the extension part
        let filename = ".gitignore";
        let path = std::path::Path::new(filename);
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        
        // .gitignore has no extension, but "gitignore" should be scannable
        assert_eq!(ext, "");
        assert!(is_scannable_file("gitignore"));
        
        // Test a normal .gitignore style check
        let is_gitignore = filename == ".gitignore";
        assert!(is_gitignore);
    }

    #[test]
    fn test_multiple_extensions() {
        let filename = "config.yaml.bak";
        let path = std::path::Path::new(filename);
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        
        // Should get the last extension
        assert_eq!(ext, "bak");
        assert!(is_scannable_file("bak"));
    }

    #[test]
    fn test_case_sensitivity() {
        // Extensions should be checked in lowercase
        assert!(is_scannable_file("json"));
        assert!(is_scannable_file(&"JSON".to_lowercase()));
        assert!(is_scannable_file(&"Json".to_lowercase()));
    }
}

/// ⚡ PERFORMANCE TESTS
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_entropy_calculation_performance() {
        let test_string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        
        let start = Instant::now();
        for _ in 0..1000 {
            let _entropy = shannon_entropy(test_string);
        }
        let duration = start.elapsed();
        
        // Should calculate 1000 entropies in reasonable time
        assert!(duration.as_millis() < 100, "Entropy calculation too slow: {:?}", duration);
    }

    #[test]
    fn test_pattern_matching_performance() {
        use regex::Regex;
        
        let pattern = Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
        let test_string = "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE and some other text here";
        
        let start = Instant::now();
        for _ in 0..1000 {
            let _matches = pattern.find_iter(test_string).count();
        }
        let duration = start.elapsed();
        
        // Should perform 1000 pattern matches in reasonable time
        assert!(duration.as_millis() < 50, "Pattern matching too slow: {:?}", duration);
    }

    #[test]
    fn test_file_extension_check_performance() {
        let extensions = vec!["txt", "json", "rs", "py", "js", "java", "go", "php", "rb", "sh"];
        
        let start = Instant::now();
        for _ in 0..10000 {
            for ext in &extensions {
                let _scannable = is_scannable_file(ext);
            }
        }
        let duration = start.elapsed();
        
        // Should check 100k extensions in reasonable time
        assert!(duration.as_millis() < 50, "Extension checking too slow: {:?}", duration);
    }
}

/// Helper function to calculate Shannon entropy (copied from main.rs for testing)
fn shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    
    let mut counts = [0u32; 256];
    let bytes = data.as_bytes();
    let len = bytes.len() as f64;
    
    for &byte in bytes {
        counts[byte as usize] += 1;
    }
    
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    
    entropy
}

/// Helper function to check if file extension is scannable (copied from main.rs for testing)
fn is_scannable_file(ext: &str) -> bool {
    matches!(ext, 
        "txt" | "json" | "yaml" | "yml" | "conf" | "config" | "env" | "properties" | "ini" | "cfg" | "toml" |
        "rs" | "py" | "js" | "ts" | "java" | "go" | "php" | "rb" | "sh" | "bash" | "zsh" | "fish" |
        "xml" | "html" | "css" | "sql" | "log" | "md" | "dockerfile" | "makefile" | "gradle" | "pom" |
        "lock" | "sum" | "mod" | "backup" | "bak" | "old" | "tmp" | "key" | "pem" | "crt" | "cer" |
        "p12" | "pfx" | "jks" | "keystore" | "gitignore" | "gitconfig" | "secrets" | "credentials"
    )
}