/**
 * Standalone ECH Tests
 * 
 * These tests verify core credential detection algorithms without
 * requiring the main library to compile. This allows testing of
 * core functionality during development.
 */

use std::collections::HashMap;
use regex::Regex;

#[cfg(test)]
mod credential_detection_tests {
    use super::*;

    #[test]
    fn test_aws_credential_patterns() {
        let test_cases = vec![
            ("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
            ("export AWS_ACCESS_KEY=AKIAI44QH8DHBEXAMPLE", "AKIAI44QH8DHBEXAMPLE"),
            ("access_key_id: AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        ];
        
        let aws_pattern = Regex::new(r"(AKIA[0-9A-Z]{16})").unwrap();
        
        for (input, expected) in test_cases {
            let captures = aws_pattern.captures(input);
            assert!(captures.is_some(), "Failed to match AWS key in: {}", input);
            
            let matched_key = captures.unwrap().get(1).unwrap().as_str();
            assert_eq!(matched_key, expected, "Extracted key doesn't match expected");
        }
    }

    #[test] 
    fn test_github_token_patterns() {
        let test_cases = vec![
            ("GITHUB_TOKEN=ghp_1234567890123456789012345678901234567890", true),
            ("token: github_pat_1234567890123456789012_123456789012345678901234567890123456789012345678901234567890123456", true),
            ("not_a_token=random_string_here", false),
        ];
        
        let patterns = vec![
            Regex::new(r"ghp_[a-zA-Z0-9]{36}").unwrap(),
            Regex::new(r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}").unwrap(),
        ];
        
        for (input, should_match) in test_cases {
            let found = patterns.iter().any(|pattern| pattern.is_match(input));
            assert_eq!(found, should_match, "GitHub token pattern test failed for: {}", input);
        }
    }

    #[test]
    fn test_entropy_analysis() {
        fn shannon_entropy(data: &str) -> f64 {
            let mut frequency = HashMap::new();
            let length = data.len() as f64;
            
            // Count frequency of each character
            for ch in data.chars() {
                *frequency.entry(ch).or_insert(0) += 1;
            }
            
            // Calculate Shannon entropy
            let mut entropy = 0.0;
            for count in frequency.values() {
                let probability = *count as f64 / length;
                entropy -= probability * probability.log2();
            }
            
            entropy
        }
        
        let test_cases = vec![
            ("password123", false), // Low entropy - common pattern
            ("aaaaaaaaaaaaa", false), // Very low entropy - repeated chars
            ("A7xF9Ks2Bv8Qw1Pr3Gh6Nm4Ct5Yh7Ju9Lp2", true), // High entropy - likely credential
            ("sk_test_AbCdEf1234567890GhIjKlMnOpQrStUvWxYz", true), // API key format
        ];
        
        for (input, should_be_high_entropy) in test_cases {
            let entropy = shannon_entropy(input);
            let is_high_entropy = entropy > 4.0; // Threshold for suspicious entropy
            
            assert_eq!(is_high_entropy, should_be_high_entropy, 
                "Entropy test failed for '{}'. Entropy: {:.2}", input, entropy);
        }
    }

    #[test]
    fn test_jwt_token_detection() {
        let valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let invalid_jwt = "not.a.jwt.token";
        
        let jwt_pattern = Regex::new(r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*").unwrap();
        
        assert!(jwt_pattern.is_match(valid_jwt), "Valid JWT should match pattern");
        assert!(!jwt_pattern.is_match(invalid_jwt), "Invalid JWT should not match pattern");
        
        // Additional validation - JWT should have exactly 3 parts
        let parts: Vec<&str> = valid_jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "Valid JWT should have exactly 3 parts");
        
        let invalid_parts: Vec<&str> = invalid_jwt.split('.').collect();
        assert_ne!(invalid_parts.len(), 3, "Invalid JWT should not have exactly 3 parts");
    }

    #[test]
    fn test_api_key_patterns() {
        let test_patterns = vec![
            // Stripe API keys
            ("sk_test_1234567890abcdefghijklmnopqrstuvwxyz", r"sk_test_[a-zA-Z0-9]{40}"),
            ("pk_live_1234567890abcdefghijklmnopqrstuvwxyz", r"pk_live_[a-zA-Z0-9]{40}"),
            
            // Slack tokens
            ("xoxb-XXXXXXXXXXXX-XXXXXXXXXXXX-XXXXXXXXXXXX", r"xoxb-[0-9]{13}-[0-9]{13}-[a-zA-Z0-9]{24}"),
            
            // SendGrid API keys
            ("SG.XXXXXXXXXXXXXXXXXXXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"),
        ];
        
        for (test_key, pattern_str) in test_patterns {
            let pattern = Regex::new(pattern_str).unwrap();
            assert!(pattern.is_match(test_key), 
                "API key '{}' should match pattern '{}'", test_key, pattern_str);
        }
    }

    #[test]
    fn test_false_positive_filtering() {
        let test_credentials = vec![
            ("sk_test_example_key_for_testing", true), // Should be filtered (test)
            ("demo_api_key_placeholder", true), // Should be filtered (demo)
            ("sample_secret_replace_me", true), // Should be filtered (sample)
            ("sk_live_TEST_PLACEHOLDER_MASKED", false), // Real-looking key
            ("prod_key_a1b2c3d4e5f6789012345678", false), // Production key
        ];
        
        for (credential, should_be_filtered) in test_credentials {
            let is_test_credential = credential.to_lowercase().contains("test")
                || credential.to_lowercase().contains("demo")
                || credential.to_lowercase().contains("example")
                || credential.to_lowercase().contains("sample")
                || credential.to_lowercase().contains("placeholder");
                
            assert_eq!(is_test_credential, should_be_filtered,
                "False positive filtering failed for '{}'", credential);
        }
    }

    #[test]
    fn test_credit_card_luhn_validation() {
        fn luhn_check(card_number: &str) -> bool {
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
                        n = (n / 10) + (n % 10);
                    }
                }
                sum += n;
                alternate = !alternate;
            }
            
            sum % 10 == 0
        }
        
        let test_cases = vec![
            ("4532015112830366", true),  // Valid Visa test card
            ("5555555555554444", true),  // Valid Mastercard test card
            ("378282246310005", true),   // Valid Amex test card
            ("4532015112830367", false), // Invalid checksum
            ("1234567890123456", false), // Sequential numbers
            ("not_a_card_number", false), // Not a number
        ];
        
        for (card_number, expected_valid) in test_cases {
            let is_valid = luhn_check(card_number);
            assert_eq!(is_valid, expected_valid,
                "Luhn validation failed for card number '{}'", card_number);
        }
    }

    #[test]
    fn test_context_based_confidence() {
        fn calculate_context_confidence(text: &str, base_confidence: f64) -> f64 {
            let mut confidence = base_confidence;
            let text_lower = text.to_lowercase();
            
            // Positive context indicators
            let positive_keywords = ["api", "secret", "key", "token", "password", "auth"];
            for keyword in &positive_keywords {
                if text_lower.contains(keyword) {
                    confidence += 0.1;
                }
            }
            
            // Negative context indicators
            let negative_keywords = ["test", "example", "demo", "sample", "fake", "mock"];
            for keyword in &negative_keywords {
                if text_lower.contains(keyword) {
                    confidence -= 0.3;
                }
            }
            
            confidence.max(0.0).min(1.0)
        }
        
        let test_cases = vec![
            ("API_SECRET=sk_live_TEST_PLACEHOLDER_MASKED", 0.9, true),  // High confidence
            ("test_api_key=sk_test_example_key", 0.9, false),    // Reduced by test context
            ("demo_password=fake_secret_123", 0.8, false),       // Multiple negative indicators
            ("production_auth_token=real_token_here", 0.7, true), // Production context
        ];
        
        for (text, base_conf, should_be_high) in test_cases {
            let final_confidence = calculate_context_confidence(text, base_conf);
            let is_high_confidence = final_confidence > 0.6;
            
            assert_eq!(is_high_confidence, should_be_high,
                "Context confidence test failed for '{}'. Final confidence: {:.2}", 
                text, final_confidence);
        }
    }

    #[test] 
    fn test_base64_detection() {
        fn is_likely_base64(data: &str) -> bool {
            // Must be at least 4 characters and multiple of 4 (with padding)
            if data.len() < 4 {
                return false;
            }
            
            // Check for base64 character set
            let base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
            if !data.chars().all(|c| base64_chars.contains(c)) {
                return false;
            }
            
            // Check padding rules
            let padding_count = data.chars().rev().take_while(|&c| c == '=').count();
            if padding_count > 2 {
                return false;
            }
            
            // Length should be multiple of 4
            data.len() % 4 == 0
        }
        
        let test_cases = vec![
            ("SGVsbG8gV29ybGQ=", true),           // "Hello World" in base64
            ("dGVzdCBzdHJpbmc=", true),           // "test string" in base64
            ("YWJjZGVmZ2hpams=", true),           // "abcdefghijk" in base64
            ("not_base64_data!", false),          // Invalid characters
            ("SGVsbG8=X", false),                 // Invalid padding
            ("abc", false),                       // Too short
            ("Hello World", false),               // Plain text
        ];
        
        for (input, expected) in test_cases {
            let result = is_likely_base64(input);
            assert_eq!(result, expected, 
                "Base64 detection failed for '{}'", input);
        }
    }
}

#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_pattern_matching_performance() {
        let patterns = vec![
            Regex::new(r"(AKIA[0-9A-Z]{16})").unwrap(),
            Regex::new(r"ghp_[a-zA-Z0-9]{36}").unwrap(),
            Regex::new(r"sk_test_[a-zA-Z0-9]{40}").unwrap(),
            Regex::new(r"xoxb-[0-9]{13}-[0-9]{13}-[a-zA-Z0-9]{24}").unwrap(),
        ];
        
        let test_content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        GITHUB_TOKEN=ghp_1234567890123456789012345678901234567890
        STRIPE_KEY=sk_test_1234567890abcdefghijklmnopqrstuvwxyz
        SLACK_TOKEN=xoxb-XXXXXXXXXXXX-XXXXXXXXXXXX-XXXXXXXXXXXX
        Regular text that should not match any patterns.
        More text to make the content larger for performance testing.";
        
        let start = Instant::now();
        let mut matches = 0;
        
        // Run pattern matching 1000 times
        for _ in 0..1000 {
            for pattern in &patterns {
                if pattern.is_match(test_content) {
                    matches += 1;
                }
            }
        }
        
        let duration = start.elapsed();
        println!("Pattern matching took: {:?} for {} matches", duration, matches);
        
        // Should complete reasonably quickly (under 1 second for 1000 iterations)
        assert!(duration.as_secs() < 1, "Pattern matching took too long: {:?}", duration);
        assert_eq!(matches, 4000, "Should find 4 matches per iteration");
    }

    #[test]
    fn test_entropy_calculation_performance() {
        let test_strings = vec![
            "password123",
            "A7xF9Ks2Bv8Qw1Pr3Gh6Nm4Ct5Yh7Ju9Lp2",
            "sk_test_AbCdEf1234567890GhIjKlMnOpQrStUvWxYz",
            "very_long_string_that_might_be_a_credential_or_maybe_not_who_knows",
        ];
        
        let start = Instant::now();
        
        // Calculate entropy 10000 times
        for _ in 0..10000 {
            for test_string in &test_strings {
                let mut frequency = HashMap::new();
                let length = test_string.len() as f64;
                
                for ch in test_string.chars() {
                    *frequency.entry(ch).or_insert(0) += 1;
                }
                
                let mut _entropy = 0.0;
                for count in frequency.values() {
                    let probability = *count as f64 / length;
                    _entropy -= probability * probability.log2();
                }
            }
        }
        
        let duration = start.elapsed();
        println!("Entropy calculation took: {:?}", duration);
        
        // Should complete reasonably quickly
        assert!(duration.as_secs() < 2, "Entropy calculation took too long: {:?}", duration);
    }
}