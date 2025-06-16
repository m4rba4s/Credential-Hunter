/**
 * Dynamic Auto-Tuning for SIMD Operations
 * 
 * Runtime performance optimization with adaptive parameter tuning.
 * Monitors system load, CPU performance, and adjusts SIMD parameters on-the-fly.
 */

use super::{SimdStrategy, SimdCapabilities, get_simd_capabilities};
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::collections::VecDeque;

/// Dynamic performance tuning engine
pub struct SimdAutoTuner {
    capabilities: &'static SimdCapabilities,
    current_config: Arc<Mutex<TuningConfig>>,
    performance_history: Arc<Mutex<PerformanceHistory>>,
    benchmarks: BenchmarkSuite,
    tuning_enabled: AtomicBool,
    last_tune_time: Arc<Mutex<Instant>>,
}

#[derive(Debug, Clone)]
pub struct TuningConfig {
    pub chunk_size: usize,
    pub thread_count: usize,
    pub simd_strategy: SimdStrategy,
    pub use_parallel: bool,
    pub entropy_threshold: f64,
    pub memory_scan_window: usize,
    pub pattern_batch_size: usize,
}

#[derive(Debug)]
struct PerformanceHistory {
    measurements: VecDeque<PerformanceMeasurement>,
    max_history: usize,
}

#[derive(Debug, Clone)]
struct PerformanceMeasurement {
    timestamp: Instant,
    config: TuningConfig,
    operation_type: String,
    throughput_mbps: f64,
    latency_ms: f64,
    cpu_usage: f64,
    memory_usage: f64,
    cache_efficiency: f64,
}

#[derive(Debug)]
pub struct BenchmarkSuite {
    entropy_benchmarks: Vec<BenchmarkResult>,
    pattern_benchmarks: Vec<BenchmarkResult>,
    memory_benchmarks: Vec<BenchmarkResult>,
}

#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub config: TuningConfig,
    pub throughput_mbps: f64,
    pub latency_ms: f64,
    pub efficiency_score: f64,
}

impl Default for TuningConfig {
    fn default() -> Self {
        let caps = get_simd_capabilities();
        Self {
            chunk_size: caps.cache_line_size * 4,
            thread_count: num_cpus::get(),
            simd_strategy: caps.best_strategy(),
            use_parallel: true,
            entropy_threshold: 6.0,
            memory_scan_window: 4096,
            pattern_batch_size: 1000,
        }
    }
}

impl PerformanceHistory {
    fn new() -> Self {
        Self {
            measurements: VecDeque::new(),
            max_history: 1000,
        }
    }
    
    fn add_measurement(&mut self, measurement: PerformanceMeasurement) {
        if self.measurements.len() >= self.max_history {
            self.measurements.pop_front();
        }
        self.measurements.push_back(measurement);
    }
    
    fn get_recent_average(&self, operation_type: &str, window: usize) -> Option<f64> {
        let recent: Vec<_> = self.measurements.iter()
            .rev()
            .take(window)
            .filter(|m| m.operation_type == operation_type)
            .collect();
        
        if recent.is_empty() {
            return None;
        }
        
        let avg_throughput = recent.iter()
            .map(|m| m.throughput_mbps)
            .sum::<f64>() / recent.len() as f64;
        
        Some(avg_throughput)
    }
    
    fn get_best_config(&self, operation_type: &str) -> Option<TuningConfig> {
        self.measurements.iter()
            .filter(|m| m.operation_type == operation_type)
            .max_by(|a, b| a.throughput_mbps.partial_cmp(&b.throughput_mbps).unwrap_or(std::cmp::Ordering::Equal))
            .map(|m| m.config.clone())
    }
}

impl SimdAutoTuner {
    pub fn new() -> Self {
        Self {
            capabilities: get_simd_capabilities(),
            current_config: Arc::new(Mutex::new(TuningConfig::default())),
            performance_history: Arc::new(Mutex::new(PerformanceHistory::new())),
            benchmarks: BenchmarkSuite::new(),
            tuning_enabled: AtomicBool::new(true),
            last_tune_time: Arc::new(Mutex::new(Instant::now())),
        }
    }
    
    /// Initialize with comprehensive benchmarking
    pub async fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🔧 Initializing SIMD Auto-Tuner...");
        
        // Run initial benchmarks
        self.benchmarks = self.run_comprehensive_benchmarks().await?;
        
        // Set optimal initial configuration
        let optimal_config = self.determine_optimal_config();
        *self.current_config.lock().unwrap() = optimal_config;
        
        println!("✅ Auto-tuner initialized with optimal configuration");
        Ok(())
    }
    
    /// Get current tuning configuration
    pub fn get_current_config(&self) -> TuningConfig {
        self.current_config.lock().unwrap().clone()
    }
    
    /// Record performance measurement and potentially retune
    pub async fn record_performance(&self, operation_type: &str, data_size: usize, 
                                   elapsed: Duration) -> Result<(), Box<dyn std::error::Error>> {
        let throughput_mbps = (data_size as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64();
        let latency_ms = elapsed.as_millis() as f64;
        
        let measurement = PerformanceMeasurement {
            timestamp: Instant::now(),
            config: self.get_current_config(),
            operation_type: operation_type.to_string(),
            throughput_mbps,
            latency_ms,
            cpu_usage: self.get_cpu_usage(),
            memory_usage: self.get_memory_usage(),
            cache_efficiency: self.estimate_cache_efficiency(data_size, elapsed),
        };
        
        self.performance_history.lock().unwrap().add_measurement(measurement);
        
        // Check if we should retune
        if self.should_retune() {
            self.adaptive_retune(operation_type).await?;
        }
        
        Ok(())
    }
    
    /// Adaptive retuning based on current performance
    async fn adaptive_retune(&self, operation_type: &str) -> Result<(), Box<dyn std::error::Error>> {
        if !self.tuning_enabled.load(Ordering::Relaxed) {
            return Ok(());
        }
        
        println!("🔄 Adaptive retuning for operation: {}", operation_type);
        
        let current_config = self.get_current_config();
        let history = self.performance_history.lock().unwrap();
        
        // Analyze recent performance trends
        let recent_avg = history.get_recent_average(operation_type, 10);
        let best_config = history.get_best_config(operation_type);
        
        drop(history);
        
        // Determine if current performance is suboptimal
        if let (Some(recent), Some(best)) = (recent_avg, best_config) {
            let performance_ratio = recent / self.get_baseline_throughput(operation_type);
            
            if performance_ratio < 0.8 {
                println!("  📉 Performance degraded ({:.1}%), applying best known config", 
                        (1.0 - performance_ratio) * 100.0);
                *self.current_config.lock().unwrap() = best;
            } else if performance_ratio > 1.2 {
                println!("  📈 Performance improved, exploring nearby configurations");
                let optimized = self.explore_nearby_configs(current_config, operation_type).await?;
                *self.current_config.lock().unwrap() = optimized;
            }
        }
        
        // Update last tune time
        *self.last_tune_time.lock().unwrap() = Instant::now();
        
        Ok(())
    }
    
    /// Explore configurations near the current one for potential improvements
    async fn explore_nearby_configs(&self, base_config: TuningConfig, operation_type: &str) 
                                   -> Result<TuningConfig, Box<dyn std::error::Error>> {
        let variations = vec![
            // Chunk size variations
            TuningConfig { chunk_size: base_config.chunk_size * 2, ..base_config.clone() },
            TuningConfig { chunk_size: base_config.chunk_size / 2, ..base_config.clone() },
            // Thread count variations
            TuningConfig { thread_count: (base_config.thread_count * 3 / 2).max(1), ..base_config.clone() },
            TuningConfig { thread_count: (base_config.thread_count / 2).max(1), ..base_config.clone() },
            // Batch size variations
            TuningConfig { pattern_batch_size: base_config.pattern_batch_size * 2, ..base_config.clone() },
            TuningConfig { pattern_batch_size: base_config.pattern_batch_size / 2, ..base_config.clone() },
        ];
        
        let mut best_config = base_config.clone();
        let mut best_performance = 0.0;
        
        for config in variations {
            if let Some(performance) = self.quick_benchmark_config(&config, operation_type).await {
                if performance > best_performance {
                    best_performance = performance;
                    best_config = config;
                }
            }
        }
        
        Ok(best_config)
    }
    
    /// Quick benchmark of a specific configuration
    async fn quick_benchmark_config(&self, config: &TuningConfig, operation_type: &str) -> Option<f64> {
        // Temporarily apply config and run quick benchmark
        let original_config = self.get_current_config();
        *self.current_config.lock().unwrap() = config.clone();
        
        let result = match operation_type {
            "entropy_calculation" => self.benchmark_entropy_quick().await,
            "pattern_matching" => self.benchmark_patterns_quick().await,
            "memory_scanning" => self.benchmark_memory_quick().await,
            _ => None,
        };
        
        // Restore original config
        *self.current_config.lock().unwrap() = original_config;
        
        result
    }
    
    /// Should we retune based on time and performance criteria?
    fn should_retune(&self) -> bool {
        let last_tune = *self.last_tune_time.lock().unwrap();
        let time_since_tune = last_tune.elapsed();
        
        // Retune every 5 minutes or if significant performance change detected
        time_since_tune > Duration::from_secs(300) || self.significant_performance_change()
    }
    
    /// Detect significant performance changes
    fn significant_performance_change(&self) -> bool {
        let history = self.performance_history.lock().unwrap();
        
        if history.measurements.len() < 10 {
            return false;
        }
        
        let recent: Vec<_> = history.measurements.iter().rev().take(5).collect();
        let older: Vec<_> = history.measurements.iter().rev().skip(5).take(5).collect();
        
        if recent.len() < 5 || older.len() < 5 {
            return false;
        }
        
        let recent_avg = recent.iter().map(|m| m.throughput_mbps).sum::<f64>() / recent.len() as f64;
        let older_avg = older.iter().map(|m| m.throughput_mbps).sum::<f64>() / older.len() as f64;
        
        let change_ratio = (recent_avg - older_avg).abs() / older_avg;
        change_ratio > 0.2 // 20% change threshold
    }
    
    /// Run comprehensive benchmarks for all operation types
    async fn run_comprehensive_benchmarks(&self) -> Result<BenchmarkSuite, Box<dyn std::error::Error>> {
        println!("  🧪 Running comprehensive SIMD benchmarks...");
        
        let entropy_benchmarks = self.benchmark_entropy_configs().await;
        let pattern_benchmarks = self.benchmark_pattern_configs().await;
        let memory_benchmarks = self.benchmark_memory_configs().await;
        
        Ok(BenchmarkSuite {
            entropy_benchmarks,
            pattern_benchmarks, 
            memory_benchmarks,
        })
    }
    
    /// Benchmark different configurations for entropy calculation
    async fn benchmark_entropy_configs(&self) -> Vec<BenchmarkResult> {
        let mut results = Vec::new();
        
        let test_configs = self.generate_test_configs();
        let test_data = self.generate_entropy_test_data();
        
        for config in test_configs {
            if let Some(result) = self.benchmark_single_entropy_config(&config, &test_data).await {
                results.push(result);
            }
        }
        
        results.sort_by(|a, b| b.efficiency_score.partial_cmp(&a.efficiency_score).unwrap_or(std::cmp::Ordering::Equal));
        results
    }
    
    /// Benchmark different configurations for pattern matching
    async fn benchmark_pattern_configs(&self) -> Vec<BenchmarkResult> {
        let mut results = Vec::new();
        
        let test_configs = self.generate_test_configs();
        let test_data = self.generate_pattern_test_data();
        
        for config in test_configs {
            if let Some(result) = self.benchmark_single_pattern_config(&config, &test_data).await {
                results.push(result);
            }
        }
        
        results.sort_by(|a, b| b.efficiency_score.partial_cmp(&a.efficiency_score).unwrap_or(std::cmp::Ordering::Equal));
        results
    }
    
    /// Benchmark different configurations for memory scanning
    async fn benchmark_memory_configs(&self) -> Vec<BenchmarkResult> {
        let mut results = Vec::new();
        
        let test_configs = self.generate_test_configs();
        let test_data = self.generate_memory_test_data();
        
        for config in test_configs {
            if let Some(result) = self.benchmark_single_memory_config(&config, &test_data).await {
                results.push(result);
            }
        }
        
        results.sort_by(|a, b| b.efficiency_score.partial_cmp(&a.efficiency_score).unwrap_or(std::cmp::Ordering::Equal));
        results
    }
    
    /// Generate test configurations for benchmarking
    fn generate_test_configs(&self) -> Vec<TuningConfig> {
        let base = TuningConfig::default();
        let cache_line = self.capabilities.cache_line_size;
        
        vec![
            // Different chunk sizes
            TuningConfig { chunk_size: cache_line, ..base.clone() },
            TuningConfig { chunk_size: cache_line * 2, ..base.clone() },
            TuningConfig { chunk_size: cache_line * 4, ..base.clone() },
            TuningConfig { chunk_size: cache_line * 8, ..base.clone() },
            TuningConfig { chunk_size: cache_line * 16, ..base.clone() },
            
            // Different thread counts
            TuningConfig { thread_count: 1, ..base.clone() },
            TuningConfig { thread_count: num_cpus::get() / 2, ..base.clone() },
            TuningConfig { thread_count: num_cpus::get(), ..base.clone() },
            TuningConfig { thread_count: num_cpus::get() * 2, ..base.clone() },
            
            // Different batch sizes
            TuningConfig { pattern_batch_size: 100, ..base.clone() },
            TuningConfig { pattern_batch_size: 500, ..base.clone() },
            TuningConfig { pattern_batch_size: 1000, ..base.clone() },
            TuningConfig { pattern_batch_size: 5000, ..base.clone() },
        ]
    }
    
    /// Determine optimal configuration from benchmark results
    fn determine_optimal_config(&self) -> TuningConfig {
        let mut optimal = TuningConfig::default();
        
        // Use best entropy config for chunk size
        if let Some(best_entropy) = self.benchmarks.entropy_benchmarks.first() {
            optimal.chunk_size = best_entropy.config.chunk_size;
        }
        
        // Use best pattern config for thread count
        if let Some(best_pattern) = self.benchmarks.pattern_benchmarks.first() {
            optimal.thread_count = best_pattern.config.thread_count;
            optimal.pattern_batch_size = best_pattern.config.pattern_batch_size;
        }
        
        // Use best memory config for memory parameters
        if let Some(best_memory) = self.benchmarks.memory_benchmarks.first() {
            optimal.memory_scan_window = best_memory.config.memory_scan_window;
        }
        
        optimal
    }
    
    // Mock implementations for benchmarking (would use real modules in practice)
    async fn benchmark_single_entropy_config(&self, config: &TuningConfig, test_data: &[String]) -> Option<BenchmarkResult> {
        let start = Instant::now();
        
        // Simulate entropy calculation with this config
        for data in test_data {
            // Would use actual entropy calculator here
            let _entropy = self.mock_entropy_calculation(data, config);
        }
        
        let duration = start.elapsed();
        let data_size = test_data.iter().map(|s| s.len()).sum::<usize>();
        let throughput = (data_size as f64 / 1024.0 / 1024.0) / duration.as_secs_f64();
        
        Some(BenchmarkResult {
            config: config.clone(),
            throughput_mbps: throughput,
            latency_ms: duration.as_millis() as f64,
            efficiency_score: throughput / (config.thread_count as f64).sqrt(),
        })
    }
    
    async fn benchmark_single_pattern_config(&self, config: &TuningConfig, test_data: &[String]) -> Option<BenchmarkResult> {
        let start = Instant::now();
        
        for data in test_data {
            let _matches = self.mock_pattern_matching(data, config);
        }
        
        let duration = start.elapsed();
        let data_size = test_data.iter().map(|s| s.len()).sum::<usize>();
        let throughput = (data_size as f64 / 1024.0 / 1024.0) / duration.as_secs_f64();
        
        Some(BenchmarkResult {
            config: config.clone(),
            throughput_mbps: throughput,
            latency_ms: duration.as_millis() as f64,
            efficiency_score: throughput / (config.thread_count as f64).sqrt(),
        })
    }
    
    async fn benchmark_single_memory_config(&self, config: &TuningConfig, test_data: &[Vec<u8>]) -> Option<BenchmarkResult> {
        let start = Instant::now();
        
        for data in test_data {
            let _matches = self.mock_memory_scanning(data, config);
        }
        
        let duration = start.elapsed();
        let data_size = test_data.iter().map(|v| v.len()).sum::<usize>();
        let throughput = (data_size as f64 / 1024.0 / 1024.0) / duration.as_secs_f64();
        
        Some(BenchmarkResult {
            config: config.clone(),
            throughput_mbps: throughput,
            latency_ms: duration.as_millis() as f64,
            efficiency_score: throughput / (config.thread_count as f64).sqrt(),
        })
    }
    
    // Quick benchmark implementations
    async fn benchmark_entropy_quick(&self) -> Option<f64> {
        let test_data = vec!["AKIAIOSFODNN7EXAMPLE".to_string(); 100];
        let config = self.get_current_config();
        
        let start = Instant::now();
        for data in &test_data {
            let _entropy = self.mock_entropy_calculation(data, &config);
        }
        let duration = start.elapsed();
        
        let data_size = test_data.iter().map(|s| s.len()).sum::<usize>();
        Some((data_size as f64 / 1024.0 / 1024.0) / duration.as_secs_f64())
    }
    
    async fn benchmark_patterns_quick(&self) -> Option<f64> {
        let test_data = vec!["AKIAIOSFODNN7EXAMPLE test data".to_string(); 100];
        let config = self.get_current_config();
        
        let start = Instant::now();
        for data in &test_data {
            let _matches = self.mock_pattern_matching(data, &config);
        }
        let duration = start.elapsed();
        
        let data_size = test_data.iter().map(|s| s.len()).sum::<usize>();
        Some((data_size as f64 / 1024.0 / 1024.0) / duration.as_secs_f64())
    }
    
    async fn benchmark_memory_quick(&self) -> Option<f64> {
        let test_data = vec![vec![0x41u8; 1024]; 100];
        let config = self.get_current_config();
        
        let start = Instant::now();
        for data in &test_data {
            let _matches = self.mock_memory_scanning(data, &config);
        }
        let duration = start.elapsed();
        
        let data_size = test_data.iter().map(|v| v.len()).sum::<usize>();
        Some((data_size as f64 / 1024.0 / 1024.0) / duration.as_secs_f64())
    }
    
    // Test data generators
    fn generate_entropy_test_data(&self) -> Vec<String> {
        vec![
            "AKIAIOSFODNN7EXAMPLE".to_string(),
            "ghp_1234567890123456789012345678901234567890".to_string(),
            "sk_live_TEST_PLACEHOLDER_MASKED".to_string(),
            "password123".to_string(),
            "high_entropy_A7xF9Ks2Bv8Qw1Pr6Zn4Jm3Lp9Rt5Xy".to_string(),
        ]
    }
    
    fn generate_pattern_test_data(&self) -> Vec<String> {
        let mut data = Vec::new();
        for i in 0..1000 {
            data.push(format!("log entry {} with AKIAIOSFODNN7EXAMPLE credential", i));
            data.push(format!("github token ghp_{:040}", i));
            data.push(format!("normal log entry {}", i));
        }
        data
    }
    
    fn generate_memory_test_data(&self) -> Vec<Vec<u8>> {
        let mut data = Vec::new();
        for i in 0..100 {
            let mut region = vec![0u8; 4096];
            if i % 10 == 0 {
                region[100..120].copy_from_slice(b"AKIAIOSFODNN7EXAMPLE");
            }
            data.push(region);
        }
        data
    }
    
    // Mock implementations (would be replaced with actual SIMD operations)
    fn mock_entropy_calculation(&self, data: &str, _config: &TuningConfig) -> f64 {
        // Simple entropy calculation mock
        use std::collections::HashMap;
        let mut freq = HashMap::new();
        for ch in data.chars() {
            *freq.entry(ch).or_insert(0) += 1;
        }
        let len = data.len() as f64;
        freq.values().map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        }).sum()
    }
    
    fn mock_pattern_matching(&self, data: &str, _config: &TuningConfig) -> usize {
        // Simple pattern matching mock
        let patterns = ["AKIA", "ghp_", "sk_live_", "password"];
        patterns.iter().map(|pattern| {
            data.matches(pattern).count()
        }).sum()
    }
    
    fn mock_memory_scanning(&self, data: &[u8], _config: &TuningConfig) -> usize {
        // Simple memory scanning mock
        let patterns = [b"AKIA", b"ghp_", b"sk_live_"];
        patterns.iter().map(|pattern| {
            data.windows(pattern.len()).filter(|window| window == *pattern).count()
        }).sum()
    }
    
    // System monitoring functions
    fn get_cpu_usage(&self) -> f64 {
        // Mock CPU usage - would use system APIs
        50.0
    }
    
    fn get_memory_usage(&self) -> f64 {
        // Mock memory usage - would use system APIs
        1024.0 * 1024.0 * 100.0 // 100MB
    }
    
    fn estimate_cache_efficiency(&self, data_size: usize, duration: Duration) -> f64 {
        // Simple cache efficiency estimation
        let expected_time = (data_size as f64 / self.capabilities.cache_line_size as f64) * 0.001;
        expected_time / duration.as_secs_f64()
    }
    
    fn get_baseline_throughput(&self, operation_type: &str) -> f64 {
        // Baseline throughput expectations (MB/s)
        match operation_type {
            "entropy_calculation" => 100.0,
            "pattern_matching" => 200.0,
            "memory_scanning" => 500.0,
            _ => 50.0,
        }
    }
    
    /// Enable/disable automatic tuning
    pub fn set_tuning_enabled(&self, enabled: bool) {
        self.tuning_enabled.store(enabled, Ordering::Relaxed);
    }
    
    /// Get tuning statistics
    pub fn get_tuning_stats(&self) -> TuningStats {
        let history = self.performance_history.lock().unwrap();
        
        TuningStats {
            measurements_count: history.measurements.len(),
            entropy_benchmarks: self.benchmarks.entropy_benchmarks.len(),
            pattern_benchmarks: self.benchmarks.pattern_benchmarks.len(),
            memory_benchmarks: self.benchmarks.memory_benchmarks.len(),
            current_config: self.get_current_config(),
            tuning_enabled: self.tuning_enabled.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
pub struct TuningStats {
    pub measurements_count: usize,
    pub entropy_benchmarks: usize,
    pub pattern_benchmarks: usize,
    pub memory_benchmarks: usize,
    pub current_config: TuningConfig,
    pub tuning_enabled: bool,
}

impl BenchmarkSuite {
    fn new() -> Self {
        Self {
            entropy_benchmarks: Vec::new(),
            pattern_benchmarks: Vec::new(),
            memory_benchmarks: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_auto_tuner_creation() {
        let tuner = SimdAutoTuner::new();
        let config = tuner.get_current_config();
        println!("Auto-tuner created with config: {:?}", config);
        assert!(config.chunk_size > 0);
        assert!(config.thread_count > 0);
    }
    
    #[tokio::test]
    async fn test_auto_tuner_initialization() {
        let mut tuner = SimdAutoTuner::new();
        let result = tuner.initialize().await;
        assert!(result.is_ok());
        
        let stats = tuner.get_tuning_stats();
        println!("Tuner stats after initialization: {:?}", stats);
        assert!(stats.entropy_benchmarks > 0);
        assert!(stats.pattern_benchmarks > 0);
        assert!(stats.memory_benchmarks > 0);
    }
    
    #[tokio::test]
    async fn test_performance_recording() {
        let tuner = SimdAutoTuner::new();
        
        // Record some performance measurements
        let result = tuner.record_performance("entropy_calculation", 1024*1024, Duration::from_millis(10)).await;
        assert!(result.is_ok());
        
        let result = tuner.record_performance("pattern_matching", 2048*1024, Duration::from_millis(20)).await;
        assert!(result.is_ok());
        
        let stats = tuner.get_tuning_stats();
        assert!(stats.measurements_count >= 2);
    }
    
    #[tokio::test]
    async fn test_configuration_exploration() {
        let tuner = SimdAutoTuner::new();
        let base_config = tuner.get_current_config();
        
        let optimized = tuner.explore_nearby_configs(base_config.clone(), "entropy_calculation").await;
        assert!(optimized.is_ok());
        
        println!("Base config: {:?}", base_config);
        println!("Optimized config: {:?}", optimized.unwrap());
    }
    
    #[tokio::test]
    async fn test_adaptive_retuning() {
        let tuner = SimdAutoTuner::new();
        
        // Simulate poor performance to trigger retuning
        for _ in 0..15 {
            let _ = tuner.record_performance("entropy_calculation", 1024, Duration::from_millis(100)).await;
        }
        
        let stats = tuner.get_tuning_stats();
        println!("Stats after retuning simulation: {:?}", stats);
        assert!(stats.measurements_count >= 15);
    }
    
    #[test]
    fn test_performance_history() {
        let mut history = PerformanceHistory::new();
        
        let measurement = PerformanceMeasurement {
            timestamp: Instant::now(),
            config: TuningConfig::default(),
            operation_type: "test".to_string(),
            throughput_mbps: 100.0,
            latency_ms: 10.0,
            cpu_usage: 50.0,
            memory_usage: 1024.0,
            cache_efficiency: 0.9,
        };
        
        history.add_measurement(measurement);
        assert_eq!(history.measurements.len(), 1);
        
        let avg = history.get_recent_average("test", 5);
        assert_eq!(avg, Some(100.0));
    }
}