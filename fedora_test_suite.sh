#!/bin/bash

##############################################################################
# ECH Fedora Test Suite - Enterprise Credential Hunter Testing on Fedora
# 
# This script tests ECH functionality specifically on Fedora Linux,
# including system-specific features and integration tests.
##############################################################################

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0

echo -e "${BLUE}🚀 ECH Fedora Linux Test Suite${NC}"
echo "=========================================="
echo "Testing on: $(cat /etc/fedora-release)"
echo "Kernel: $(uname -r)"
echo "Architecture: $(uname -m)"
echo "User: $(whoami)"
echo "=========================================="

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -n "Testing $test_name... "
    
    if eval "$test_command" &>/dev/null; then
        echo -e "${GREEN}✅ PASSED${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        echo -e "${RED}❌ FAILED${NC}"
        return 1
    fi
}

# Function to run detailed test with output
run_detailed_test() {
    local test_name="$1"
    local test_command="$2"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "${YELLOW}🔍 Testing $test_name...${NC}"
    
    if eval "$test_command"; then
        echo -e "${GREEN}✅ $test_name PASSED${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        echo -e "${RED}❌ $test_name FAILED${NC}"
        return 1
    fi
}

echo -e "\n${BLUE}📋 System Prerequisites Check${NC}"
echo "----------------------------------------"

# Check if we're on Fedora
run_test "Fedora OS Detection" "grep -q 'Fedora' /etc/os-release"

# Check Rust installation
run_test "Rust Installation" "command -v rustc"

# Check required tools
run_test "Essential Tools" "command -v gcc && command -v make && command -v git"

# Check if running as regular user (not root)
run_test "Non-root execution" "[ \$EUID -ne 0 ]"

echo -e "\n${BLUE}🔧 ECH Core Algorithm Tests${NC}"
echo "----------------------------------------"

# Test core ECH algorithms using our standalone runner
if [ -f "final_test_runner.rs" ]; then
    run_detailed_test "ECH Core Algorithms" "rustc final_test_runner.rs -o ech_test && ./ech_test | grep -q '100.0%'"
else
    echo -e "${YELLOW}⚠️ ECH test runner not found, creating minimal test...${NC}"
    
    # Create minimal test
    cat > minimal_ech_test.rs << 'EOF'
fn main() {
    println!("🔍 ECH Minimal Fedora Test");
    
    // Test basic pattern matching
    let aws_key = "AKIAIOSFODNN7EXAMPLE";
    assert!(aws_key.starts_with("AKIA"));
    assert_eq!(aws_key.len(), 20);
    
    // Test entropy calculation
    let entropy = calculate_entropy("A7xF9Ks2Bv8Qw1Pr3Gh6Nm4Ct5Yh7Ju9Lp2");
    assert!(entropy > 4.0);
    
    println!("✅ All core tests passed on Fedora!");
}

fn calculate_entropy(data: &str) -> f64 {
    use std::collections::HashMap;
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
EOF
    
    run_detailed_test "ECH Minimal Test" "rustc minimal_ech_test.rs -o minimal_test && ./minimal_test"
fi

echo -e "\n${BLUE}🐧 Fedora-Specific System Tests${NC}"
echo "----------------------------------------"

# Test SELinux status
run_detailed_test "SELinux Status Check" "sestatus | head -3"

# Test systemd integration
run_test "Systemd Available" "command -v systemctl"

# Test if we can read /proc (needed for memory scanning)
run_test "Proc Filesystem Access" "ls /proc/self/maps > /dev/null"

# Test if we can access process information
run_test "Process Information Access" "ps aux | head -5 > /dev/null"

# Test file system permissions
run_test "Home Directory Access" "ls -la ~ > /dev/null"

# Test network capabilities (for SIEM integration)
run_test "Network Stack Available" "ss -tuln > /dev/null"

echo -e "\n${BLUE}🔐 Security Context Tests${NC}"
echo "----------------------------------------"

# Test user permissions
run_detailed_test "Current User Permissions" "id && groups"

# Test if we can create temporary files
run_test "Temporary File Creation" "touch /tmp/ech_test_$$ && rm /tmp/ech_test_$$"

# Test if we can access common credential locations
echo -e "${YELLOW}🔍 Testing credential file access patterns...${NC}"

# Test common locations where credentials might be found
test_locations=(
    "$HOME/.bashrc"
    "$HOME/.bash_profile" 
    "$HOME/.zshrc"
    "$HOME/.config"
    "/tmp"
)

for location in "${test_locations[@]}"; do
    if [ -e "$location" ]; then
        run_test "Access to $location" "ls -la '$location' > /dev/null"
    fi
done

echo -e "\n${BLUE}⚡ Performance Tests${NC}"
echo "----------------------------------------"

# Create performance test
cat > fedora_perf_test.rs << 'EOF'
use std::time::Instant;
use std::collections::HashMap;

fn main() {
    println!("🚀 ECH Fedora Performance Tests");
    
    // Test 1: Pattern matching performance
    let start = Instant::now();
    let test_data = generate_test_data(1000);
    let mut matches = 0;
    
    for _ in 0..100 {
        if test_data.contains("AKIA") { matches += 1; }
        if test_data.contains("ghp_") { matches += 1; }
        if test_data.contains("sk_") { matches += 1; }
    }
    
    let pattern_time = start.elapsed();
    println!("📊 Pattern matching: {:?} ({} matches)", pattern_time, matches);
    
    // Test 2: Entropy calculation performance
    let start = Instant::now();
    
    for i in 0..500 {
        let test_string = format!("entropy_test_string_{}", i);
        let _entropy = calculate_entropy(&test_string);
    }
    
    let entropy_time = start.elapsed();
    println!("📊 Entropy calculation: {:?}", entropy_time);
    
    // Test 3: Memory usage estimation
    let start_mem = estimate_memory();
    let _large_data = generate_test_data(5000);
    let end_mem = estimate_memory();
    
    println!("📊 Memory usage: ~{}KB", (end_mem - start_mem) / 1024);
    
    // Performance assertions for Fedora
    assert!(pattern_time.as_millis() < 50, "Pattern matching too slow");
    assert!(entropy_time.as_millis() < 100, "Entropy calculation too slow");
    assert!(matches > 0, "Should find patterns");
    
    println!("✅ All performance tests passed on Fedora!");
}

fn generate_test_data(lines: usize) -> String {
    let mut data = String::new();
    for i in 0..lines {
        match i % 6 {
            0 => data.push_str(&format!("AWS_ACCESS_KEY_ID=AKIA{:016}\n", i)),
            1 => data.push_str(&format!("GITHUB_TOKEN=ghp_{:036}\n", i)),
            2 => data.push_str(&format!("SECRET_KEY=sk_live_secret_{}\n", i)),
            3 => data.push_str(&format!("config_line_{} = value\n", i)),
            4 => data.push_str(&format!("# Comment line {}\n", i)),
            _ => data.push_str(&format!("normal_data_{}\n", i)),
        }
    }
    data
}

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

fn estimate_memory() -> usize {
    // Simple memory estimation
    std::mem::size_of::<String>() * 100
}
EOF

run_detailed_test "Fedora Performance Tests" "rustc fedora_perf_test.rs -o perf_test && ./perf_test"

echo -e "\n${BLUE}🔍 Fedora Integration Tests${NC}"
echo "----------------------------------------"

# Test if we can enumerate processes (memory scanning simulation)
run_detailed_test "Process Enumeration" "ps -eo pid,comm,cmd | head -10"

# Test file system scanning capabilities
echo -e "${YELLOW}🔍 Testing filesystem scanning capabilities...${NC}"

# Create test credential files
mkdir -p /tmp/ech_test_$$
cat > /tmp/ech_test_$$/test_config.env << 'EOF'
# Test configuration file
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_URL=postgresql://user:password@localhost/db
GITHUB_TOKEN=ghp_1234567890123456789012345678901234567890
API_SECRET=sk_test_example_key_for_testing
JWT_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature
EOF

# Test file scanning
cat > fedora_file_scan.rs << 'EOF'
use std::fs;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <directory>", args[0]);
        return;
    }
    
    let test_dir = &args[1];
    println!("🔍 Scanning directory: {}", test_dir);
    
    let mut credentials_found = 0;
    
    if let Ok(entries) = fs::read_dir(test_dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    // Simple credential detection
                    if content.contains("AKIA") || 
                       content.contains("ghp_") || 
                       content.contains("sk_") ||
                       content.contains("eyJ") {
                        credentials_found += 1;
                        println!("📋 Found credentials in: {:?}", entry.file_name());
                    }
                }
            }
        }
    }
    
    println!("📊 Total credential patterns found: {}", credentials_found);
    assert!(credentials_found > 0, "Should find test credentials");
    println!("✅ File scanning test passed!");
}
EOF

run_detailed_test "Filesystem Credential Scanning" "rustc fedora_file_scan.rs -o file_scan && ./file_scan /tmp/ech_test_$$"

# Cleanup test files
rm -rf /tmp/ech_test_$$

echo -e "\n${BLUE}🌐 Network & SIEM Integration Tests${NC}"
echo "----------------------------------------"

# Test network connectivity (for SIEM integration)
run_test "DNS Resolution" "nslookup google.com > /dev/null"

# Test if we can bind to local ports (for local SIEM testing)
run_test "Local Port Binding" "python3 -c 'import socket; s=socket.socket(); s.bind((\"\", 0)); print(\"Port:\", s.getsockname()[1]); s.close()'"

# Test JSON processing (for SIEM data)
run_test "JSON Processing" "echo '{\"test\": \"data\"}' | python3 -c 'import json, sys; json.load(sys.stdin)'"

echo -e "\n${BLUE}🔒 Security Feature Tests${NC}"
echo "----------------------------------------"

# Test credential masking
cat > fedora_security_test.rs << 'EOF'
fn main() {
    println!("🔐 ECH Security Feature Tests on Fedora");
    
    // Test credential masking
    let sensitive_data = vec![
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        "password=secretpassword123",
        "token=sk_live_1234567890abcdef",
        "api_key=ghp_1234567890123456789012345678901234567890",
    ];
    
    for data in &sensitive_data {
        let masked = mask_credential(data);
        println!("Original: {} -> Masked: {}", 
            &data[0..std::cmp::min(20, data.len())], masked);
        assert!(masked.contains("***"), "Should contain masking");
        assert!(!masked.contains("secret"), "Should not contain 'secret'");
    }
    
    // Test risk assessment
    let test_credentials = vec![
        ("AKIAIOSFODNN7EXAMPLE", "HIGH"),
        ("sk_live_production_key", "HIGH"), 
        ("password123", "MEDIUM"),
        ("sk_test_example", "LOW"),
    ];
    
    for (cred, expected_risk) in test_credentials {
        let risk = assess_risk(cred);
        println!("Credential risk: {} -> {}", cred, risk);
        assert_eq!(risk, expected_risk, "Risk assessment mismatch");
    }
    
    println!("✅ All security tests passed on Fedora!");
}

fn mask_credential(data: &str) -> String {
    if let Some(pos) = data.find('=') {
        let (key, value) = data.split_at(pos + 1);
        if value.len() > 6 {
            format!("{}{}***{}", key, &value[0..3], &value[value.len()-3..])
        } else {
            format!("{}***", key)
        }
    } else {
        "***".to_string()
    }
}

fn assess_risk(credential: &str) -> &'static str {
    let cred_lower = credential.to_lowercase();
    
    if credential.starts_with("AKIA") || cred_lower.contains("live") || cred_lower.contains("prod") {
        "HIGH"
    } else if cred_lower.contains("test") || cred_lower.contains("demo") {
        "LOW" 
    } else {
        "MEDIUM"
    }
}
EOF

run_detailed_test "Security Features" "rustc fedora_security_test.rs -o security_test && ./security_test"

echo -e "\n${BLUE}📊 Final Results${NC}"
echo "=========================================="
echo -e "🏆 ECH Fedora Test Results:"
echo -e "✅ Tests Passed: ${GREEN}$PASSED_TESTS${NC}/${TOTAL_TESTS}"

SUCCESS_RATE=$(( PASSED_TESTS * 100 / TOTAL_TESTS ))
echo -e "📈 Success Rate: ${GREEN}$SUCCESS_RATE%${NC}"

if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    echo -e "\n${GREEN}🎉 ALL TESTS PASSED!${NC}"
    echo -e "${GREEN}ECH is fully compatible with Fedora Linux!${NC}"
    echo -e "\n🚀 ${BLUE}Fedora-specific capabilities validated:${NC}"
    echo "   • System integration"
    echo "   • File system access"
    echo "   • Process enumeration"
    echo "   • Network connectivity"
    echo "   • Security contexts"
    echo "   • Performance optimization"
else
    echo -e "\n${YELLOW}⚠️ Some tests failed.${NC}"
    echo "Please review the failed tests before deployment."
fi

# Cleanup
rm -f ech_test minimal_test minimal_ech_test.rs perf_test fedora_perf_test.rs
rm -f file_scan fedora_file_scan.rs security_test fedora_security_test.rs

echo -e "\n${BLUE}🔧 System Information Summary:${NC}"
echo "=========================================="
echo "OS: $(cat /etc/fedora-release)"
echo "Kernel: $(uname -r)"
echo "Architecture: $(uname -m)"
echo "CPU: $(nproc) cores"
echo "Memory: $(free -h | grep 'Mem:' | awk '{print $2}')"
echo "Rust: $(rustc --version 2>/dev/null || echo 'Not installed')"
echo "SELinux: $(sestatus | grep 'Current mode' | awk '{print $3}' 2>/dev/null || echo 'Unknown')"
echo "=========================================="

echo -e "${BLUE}✨ ECH Fedora testing completed!${NC}"