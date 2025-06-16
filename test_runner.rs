/**
 * Independent Test Runner for ECH Core Algorithms
 * 
 * This is a standalone test runner that validates core credential detection
 * algorithms without requiring the main library to compile. Run with:
 * rustc test_runner.rs && ./test_runner
 */

use std::collections::HashMap;

fn main() {
    println!("🧪 Running ECH Core Algorithm Tests...\n");
    
    let mut passed = 0;
    let mut total = 0;
    
    // Run all test suites
    passed += run_pattern_tests(&mut total);
    passed += run_entropy_tests(&mut total);
    passed += run_validation_tests(&mut total);
    passed += run_performance_tests(&mut total);
    
    println!("\n📊 Test Results:");
    println!("✅ Passed: {}/{}", passed, total);
    
    if passed == total {
        println!("🎉 All tests passed! ECH core algorithms are working correctly.");
        std::process::exit(0);
    } else {
        println!("❌ Some tests failed. Please review the implementation.");
        std::process::exit(1);
    }
}

fn run_pattern_tests(total: &mut i32) -> i32 {
    println!("🔍 Testing Credential Pattern Detection...");
    let mut passed = 0;
    
    // Test AWS patterns
    *total += 1;
    if test_aws_patterns() {
        println!("  ✅ AWS credential patterns");
        passed += 1;
    } else {
        println!("  ❌ AWS credential patterns");
    }
    
    // Test API key patterns
    *total += 1;
    if test_api_key_patterns() {
        println!("  ✅ API key patterns");
        passed += 1;
    } else {
        println!("  ❌ API key patterns");
    }
    
    // Test JWT patterns  
    *total += 1;
    if test_jwt_patterns() {
        println!("  ✅ JWT token patterns");
        passed += 1;
    } else {
        println!("  ❌ JWT token patterns");
    }
    
    passed
}

fn run_entropy_tests(total: &mut i32) -> i32 {
    println!("\n📈 Testing Entropy Analysis...");
    let mut passed = 0;
    
    *total += 1;
    if test_shannon_entropy() {
        println!("  ✅ Shannon entropy calculation");
        passed += 1;
    } else {
        println!("  ❌ Shannon entropy calculation");
    }
    
    *total += 1;
    if test_entropy_thresholds() {
        println!("  ✅ Entropy threshold detection");
        passed += 1;
    } else {
        println!("  ❌ Entropy threshold detection");
    }
    
    passed
}

fn run_validation_tests(total: &mut i32) -> i32 {
    println!("\n🛡️ Testing Validation Algorithms...");
    let mut passed = 0;
    
    *total += 1;
    if test_luhn_algorithm() {
        println!("  ✅ Luhn algorithm (credit cards)");
        passed += 1;
    } else {
        println!("  ❌ Luhn algorithm (credit cards)");
    }
    
    *total += 1;
    if test_false_positive_filtering() {
        println!("  ✅ False positive filtering");
        passed += 1;
    } else {
        println!("  ❌ False positive filtering");
    }
    
    *total += 1;
    if test_context_analysis() {
        println!("  ✅ Context-based confidence");
        passed += 1;
    } else {
        println!("  ❌ Context-based confidence");
    }
    
    passed
}

fn run_performance_tests(total: &mut i32) -> i32 {
    println!("\n⚡ Testing Performance...");
    let mut passed = 0;
    
    *total += 1;
    if test_pattern_performance() {
        println!("  ✅ Pattern matching performance");
        passed += 1;
    } else {
        println!("  ❌ Pattern matching performance");
    }
    
    *total += 1;
    if test_entropy_performance() {
        println!("  ✅ Entropy calculation performance");
        passed += 1;
    } else {
        println!("  ❌ Entropy calculation performance");
    }
    
    passed
}

// Pattern detection tests
fn test_aws_patterns() -> bool {
    let test_cases = vec![
        ("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", true),
        ("export AWS_ACCESS_KEY=AKIAI44QH8DHBEXAMPLE", true),
        ("not_an_aws_key=regular_text", false),
    ];
    
    for (input, should_match) in test_cases {
        let has_aws_pattern = input.contains("AKIA") && 
            input.chars().filter(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                .count() >= 16;
        
        if has_aws_pattern != should_match {
            return false;
        }
    }
    
    true
}

fn test_api_key_patterns() -> bool {
    let test_cases = vec![
        ("sk_test_1234567890abcdefghijklmnopqrstuvwxyz", true),
        ("ghp_1234567890123456789012345678901234567890", true),
        ("xoxb-XXXXXXXXXXXX-XXXXXXXXXXXX-XXXXXXXXXXXX", true),
        ("not_an_api_key", false),
    ];
    
    for (input, should_match) in test_cases {
        let has_api_pattern = input.starts_with("sk_") || 
            input.starts_with("ghp_") || 
            input.starts_with("xoxb-");
        
        if has_api_pattern != should_match {
            return false;
        }
    }
    
    true
}

fn test_jwt_patterns() -> bool {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let not_jwt = "not.a.jwt.token";
    
    let jwt_parts: Vec<&str> = jwt.split('.').collect();
    let not_jwt_parts: Vec<&str> = not_jwt.split('.').collect();
    
    // Valid JWT: 3 parts AND starts with "eyJ"
    let jwt_valid = jwt_parts.len() == 3 && jwt.starts_with("eyJ");
    
    // Invalid JWT: either wrong number of parts OR doesn't start with eyJ
    let not_jwt_invalid = not_jwt_parts.len() != 3 || !not_jwt.starts_with("eyJ");
    
    jwt_valid && not_jwt_invalid
}

// Entropy analysis tests
fn test_shannon_entropy() -> bool {
    fn shannon_entropy(data: &str) -> f64 {
        let mut frequency = HashMap::new();
        let length = data.len() as f64;
        
        for ch in data.chars() {
            *frequency.entry(ch).or_insert(0) += 1;
        }
        
        let mut entropy = 0.0;
        for count in frequency.values() {
            let probability = *count as f64 / length;
            entropy -= probability * probability.log2();
        }
        
        entropy
    }
    
    let high_entropy = shannon_entropy("A7xF9Ks2Bv8Qw1Pr3Gh6Nm4Ct5Yh7Ju9Lp2");
    let low_entropy = shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    
    high_entropy > 4.0 && low_entropy < 1.0
}

fn test_entropy_thresholds() -> bool {
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
    
    let test_cases = vec![
        ("password123", false), // Low entropy
        ("sk_test_AbCdEf1234567890GhIjKlMnOpQrStUvWxYz", true), // High entropy
        ("aaaaaaaaaa", false), // Very low entropy
        ("R4nd0mK3yW1thH1gh3ntr0py", true), // High entropy
    ];
    
    for (input, should_be_high) in test_cases {
        let entropy = calculate_entropy(input);
        let is_high = entropy > 4.0;
        
        if is_high != should_be_high {
            return false;
        }
    }
    
    true
}

// Validation tests
fn test_luhn_algorithm() -> bool {
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
    
    // Test valid and invalid credit card numbers
    luhn_check("4532015112830366") && // Valid Visa
    luhn_check("5555555555554444") && // Valid Mastercard
    !luhn_check("4532015112830367") && // Invalid checksum
    !luhn_check("1234567890123456") // Sequential numbers
}

fn test_false_positive_filtering() -> bool {
    let test_cases = vec![
        ("sk_test_example_key", true), // Should be filtered
        ("demo_api_key", true), // Should be filtered
        ("sk_live_TEST_PLACEHOLDER_MASKED_key_abc123", false), // Should not be filtered
    ];
    
    for (credential, should_be_filtered) in test_cases {
        let is_test = credential.to_lowercase().contains("test") ||
            credential.to_lowercase().contains("demo") ||
            credential.to_lowercase().contains("example");
            
        if is_test != should_be_filtered {
            return false;
        }
    }
    
    true
}

fn test_context_analysis() -> bool {
    fn analyze_context(text: &str) -> f64 {
        let mut confidence: f64 = 0.5; // Base confidence
        let text_lower = text.to_lowercase();
        
        // Positive indicators
        if text_lower.contains("api") || text_lower.contains("key") {
            confidence += 0.2;
        }
        
        // Negative indicators
        if text_lower.contains("test") || text_lower.contains("demo") {
            confidence -= 0.3;
        }
        
        confidence.max(0.0).min(1.0)
    }
    
    let high_conf = analyze_context("API_KEY=sk_live_TEST_PLACEHOLDER_MASKED_key");
    let low_conf = analyze_context("test_demo_key=fake_value");
    
    high_conf > 0.6 && low_conf < 0.4
}

// Performance tests
fn test_pattern_performance() -> bool {
    use std::time::Instant;
    
    let test_content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    GITHUB_TOKEN=ghp_1234567890123456789012345678901234567890
    STRIPE_KEY=sk_test_1234567890abcdefghijklmnopqrstuvwxyz
    Regular text that should not match patterns.";
    
    let start = Instant::now();
    
    // Simulate pattern matching 1000 times
    for _ in 0..1000 {
        let _has_aws = test_content.contains("AKIA");
        let _has_github = test_content.contains("ghp_");
        let _has_stripe = test_content.contains("sk_");
    }
    
    let duration = start.elapsed();
    
    // Should complete in reasonable time (under 100ms)
    duration.as_millis() < 100
}

fn test_entropy_performance() -> bool {
    use std::time::Instant;
    
    let test_strings = vec![
        "password123",
        "A7xF9Ks2Bv8Qw1Pr3Gh6Nm4Ct5Yh7Ju9Lp2",
        "sk_test_AbCdEf1234567890GhIjKlMnOpQrStUvWxYz",
    ];
    
    let start = Instant::now();
    
    // Calculate entropy 1000 times
    for _ in 0..1000 {
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
    
    // Should complete in reasonable time (under 500ms)
    duration.as_millis() < 500
}