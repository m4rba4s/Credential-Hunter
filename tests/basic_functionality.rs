/**
 * Basic Functionality Tests for ECH
 * 
 * These tests verify core functionality without requiring full compilation
 * of complex modules. Focus on pattern detection and basic operations.
 */

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    
    #[test]
    fn test_basic_pattern_matching() {
        // Test basic regex pattern matching for credentials
        let test_content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let aws_pattern = r"(AKIA[0-9A-Z]{16})";
        
        let regex = regex::Regex::new(aws_pattern).unwrap();
        let captures = regex.captures(test_content);
        
        assert!(captures.is_some());
        let key = captures.unwrap().get(1).unwrap().as_str();
        assert_eq!(key, "AKIAIOSFODNN7EXAMPLE");
    }
    
    #[test]
    fn test_entropy_calculation() {
        // Test Shannon entropy calculation for random strings
        fn calculate_entropy(data: &str) -> f64 {
            let mut freq = HashMap::new();
            let len = data.len() as f64;
            
            for byte in data.bytes() {
                *freq.entry(byte).or_insert(0) += 1;
            }
            
            let mut entropy = 0.0;
            for count in freq.values() {
                let p = *count as f64 / len;
                entropy -= p * p.log2();
            }
            
            entropy
        }
        
        // High entropy string (likely credential)
        let high_entropy = "A7xF9Ks2Bv8Qw1Pr3Gh6Nm4Ct5Yh7Ju9Lp2";
        let entropy = calculate_entropy(high_entropy);
        assert!(entropy > 4.0, "High entropy string should have entropy > 4.0");
        
        // Low entropy string (likely not credential)  
        let low_entropy = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let entropy = calculate_entropy(low_entropy);
        assert!(entropy < 1.0, "Low entropy string should have entropy < 1.0");
    }
    
    #[test]
    fn test_credential_patterns() {
        let test_cases = vec![
            ("GitHub Token", "ghp_1234567890123456789012345678901234567890", r"ghp_[a-zA-Z0-9]{40}"),
            ("Slack Bot Token", "xoxb-XXXXXXXXXXXX-XXXXXXXXXXXX-XXXXXXXXXXXX", r"xoxb-[0-9]{13}-[0-9]{13}-[a-zA-Z0-9]{24}"),
            ("Stripe API Key", "sk_test_1234567890abcdefghijklmnopqrstuvwxyz", r"sk_test_[a-zA-Z0-9]{40}"),
            ("JWT Token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"),
        ];
        
        for (name, test_string, pattern) in test_cases {
            let regex = regex::Regex::new(pattern).unwrap();
            assert!(regex.is_match(test_string), "Pattern {} should match {}", name, test_string);
        }
    }
    
    #[test]
    fn test_false_positive_filtering() {
        // Test that we can filter out obvious test/example credentials
        let test_cases = vec![
            ("test_api_key", "sk_test_example_key_for_testing", true),
            ("demo_token", "demo_token_please_replace", true),
            ("real_looking", "sk_live_TEST_PLACEHOLDER_MASKED", false),
        ];
        
        for (name, credential, should_be_filtered) in test_cases {
            let is_test = credential.to_lowercase().contains("test") 
                || credential.to_lowercase().contains("demo")
                || credential.to_lowercase().contains("example");
                
            assert_eq!(is_test, should_be_filtered, "Test filtering failed for {}", name);
        }
    }
    
    #[test]
    fn test_luhn_algorithm() {
        // Test Luhn algorithm for credit card validation
        fn luhn_checksum(card_number: &str) -> bool {
            let digits: Vec<u32> = card_number
                .chars()
                .filter(|c| c.is_ascii_digit())
                .map(|c| c.to_digit(10).unwrap())
                .collect();
                
            if digits.len() < 13 || digits.len() > 19 {
                return false;
            }
            
            let mut sum = 0;
            let mut alternate = false;
            
            for &digit in digits.iter().rev() {
                let mut n = digit;
                if alternate {
                    n *= 2;
                    if n > 9 {
                        n = n / 10 + n % 10;
                    }
                }
                sum += n;
                alternate = !alternate;
            }
            
            sum % 10 == 0
        }
        
        // Valid credit card numbers
        assert!(luhn_checksum("4532015112830366")); // Visa test card
        assert!(luhn_checksum("5555555555554444")); // Mastercard test card
        
        // Invalid credit card numbers
        assert!(!luhn_checksum("4532015112830367")); // Wrong checksum
        assert!(!luhn_checksum("1234567890123456")); // Sequential numbers
    }
    
    #[test]
    fn test_base64_detection() {
        // Test detection of base64 encoded data (often used for keys)
        fn is_base64(data: &str) -> bool {
            if data.len() % 4 != 0 {
                return false;
            }
            
            let base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
            data.chars().all(|c| base64_chars.contains(c))
        }
        
        // Valid base64
        assert!(is_base64("SGVsbG8gV29ybGQ="));
        assert!(is_base64("dGVzdCBzdHJpbmcgZm9yIGJhc2U2NA=="));
        
        // Invalid base64
        assert!(!is_base64("Hello World!"));
        assert!(!is_base64("not-base64-@#$"));
    }
}