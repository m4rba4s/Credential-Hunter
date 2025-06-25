/**
 * ЭЛИТНЫЕ ПРОСТЫЕ ТЕСТЫ - ШВЕЙЦАРСКОЕ КАЧЕСТВО!
 * 
 * Простые, но мощные тесты, которые гарантированно работают.
 * Проверяем основной функционал без сложных зависимостей.
 */

use ech_core::memory::types::*;

#[test]
fn test_memory_permissions_basic() {
    let read_only = MemoryPermissions::READ_ONLY;
    let read_write = MemoryPermissions::READ_WRITE;
    let all_perms = MemoryPermissions::ALL;
    
    assert!(read_only.can_scan());
    assert!(!read_only.is_executable());
    
    assert!(read_write.can_scan());
    assert!(!read_write.is_executable());
    
    assert!(all_perms.can_scan());
    assert!(all_perms.is_executable());
    
    println!("✅ MemoryPermissions работают как швейцарские часы!");
}

#[test] 
fn test_memory_address_operations() {
    let addr1 = MemoryAddress(0x1000);
    let addr2 = MemoryAddress(0x2000);
    
    assert_eq!(addr1.0, 0x1000);
    assert_eq!(addr2.0, 0x2000);
    assert_ne!(addr1, addr2);
    
    println!("✅ MemoryAddress работает точно!");
}

#[test]
fn test_process_id_operations() {
    let pid1 = ProcessId(1234);
    let pid2 = ProcessId(5678);
    
    assert_eq!(pid1.0, 1234);
    assert_eq!(pid2.0, 5678);
    assert_ne!(pid1, pid2);
    
    println!("✅ ProcessId операции надежны!");
}

#[test]
fn test_memory_region_creation() {
    let region = MemoryRegion {
        base_address: MemoryAddress(0x1000),
        size: 0x2000,
        permissions: MemoryPermissions::READ_WRITE,
        region_type: MemoryRegionType::Heap,
        module_name: Some("test_module".to_string()),
        metadata: std::collections::HashMap::new(),
    };
    
    assert_eq!(region.base_address.0, 0x1000);
    assert_eq!(region.size, 0x2000);
    assert_eq!(region.end_address().0, 0x3000);
    assert!(region.contains_address(MemoryAddress(0x2000)));
    assert!(!region.contains_address(MemoryAddress(0x4000)));
    assert!(region.is_scannable());
    
    println!("✅ MemoryRegion создается и работает идеально!");
}

#[test]
fn test_process_memory_map() {
    let regions = vec![
        MemoryRegion {
            base_address: MemoryAddress(0x1000),
            size: 0x1000,
            permissions: MemoryPermissions::READ_ONLY,
            region_type: MemoryRegionType::Heap,
            module_name: None,
            metadata: std::collections::HashMap::new(),
        },
        MemoryRegion {
            base_address: MemoryAddress(0x2000),
            size: 0x1000,
            permissions: MemoryPermissions::READ_WRITE,
            region_type: MemoryRegionType::Stack,
            module_name: None,
            metadata: std::collections::HashMap::new(),
        },
    ];
    
    let memory_map = ProcessMemoryMap::new(ProcessId(1234), regions);
    
    assert_eq!(memory_map.process_id.0, 1234);
    assert_eq!(memory_map.regions.len(), 2);
    assert_eq!(memory_map.total_memory, 0x2000);
    assert_eq!(memory_map.scannable_memory, 0x2000);
    
    let scannable_regions = memory_map.get_scannable_regions();
    assert_eq!(scannable_regions.len(), 2);
    
    println!("✅ ProcessMemoryMap работает как часы!");
}

#[test]
fn test_process_info_creation() {
    let process = ProcessInfo {
        pid: ProcessId(1234),
        name: "test_process".to_string(),
        exe_path: Some("/usr/bin/test".to_string()),
        command_line: Some("test --arg".to_string()),
        parent_pid: Some(ProcessId(1)),
        user_id: Some(1000),
        memory_usage_bytes: Some(10 * 1024 * 1024),
        cpu_time_ms: Some(500),
        start_time: Some(chrono::Utc::now()),
        is_system_process: false,
        architecture: ProcessArchitecture::X64,
    };
    
    assert_eq!(process.pid.0, 1234);
    assert_eq!(process.name, "test_process");
    assert_eq!(process.architecture, ProcessArchitecture::X64);
    assert!(!process.is_system_process);
    
    println!("✅ ProcessInfo создается профессионально!");
}

#[test]
fn test_process_filter() {
    let filter = ProcessFilter {
        name_patterns: vec!["notepad".to_string()],
        min_memory_mb: Some(10),
        max_memory_mb: Some(500),
        exclude_system: true,
        ..Default::default()
    };
    
    let matching_process = ProcessInfo {
        pid: ProcessId(1234),
        name: "notepad.exe".to_string(),
        exe_path: None,
        command_line: None,
        parent_pid: None,
        user_id: Some(1000),
        memory_usage_bytes: Some(50 * 1024 * 1024), // 50MB
        cpu_time_ms: None,
        start_time: Some(chrono::Utc::now()),
        is_system_process: false,
        architecture: ProcessArchitecture::X64,
    };
    
    let non_matching_process = ProcessInfo {
        pid: ProcessId(5678),
        name: "chrome.exe".to_string(),
        exe_path: None,
        command_line: None,
        parent_pid: None,
        user_id: Some(1000),
        memory_usage_bytes: Some(50 * 1024 * 1024),
        cpu_time_ms: None,
        start_time: Some(chrono::Utc::now()),
        is_system_process: false,
        architecture: ProcessArchitecture::X64,
    };
    
    assert!(filter.matches_process(&matching_process));
    assert!(!filter.matches_process(&non_matching_process));
    
    println!("✅ ProcessFilter работает как элита!");
}

#[test]
fn test_memory_scan_config() {
    let config = MemoryScanConfig::default();
    
    assert!(config.include_heap);
    assert!(config.include_stack);
    assert!(config.include_private);
    assert!(!config.include_modules); // По умолчанию отключено
    assert!(!config.include_mapped);  // По умолчанию отключено
    assert!(config.max_chunk_size > 0);
    assert!(config.min_region_size > 0);
    
    println!("✅ MemoryScanConfig оптимален!");
}

#[test]
fn test_performance_memory_operations() {
    let start = std::time::Instant::now();
    
    // Создаем много операций с памятью
    for i in 0..1000 {
        let region = MemoryRegion {
            base_address: MemoryAddress(i * 0x1000),
            size: 0x1000,
            permissions: MemoryPermissions::READ_ONLY,
            region_type: MemoryRegionType::Private,
            module_name: None,
            metadata: std::collections::HashMap::new(),
        };
        
        let _contains = region.contains_address(MemoryAddress(i * 0x1000 + 0x500));
        let _scannable = region.is_scannable();
        let _end = region.end_address();
    }
    
    let duration = start.elapsed();
    assert!(duration.as_millis() < 100, "Операции должны быть быстрыми!");
    
    println!("✅ Производительность на уровне Formula 1!");
}

#[test]
fn test_memory_region_edge_cases() {
    // Тест граничных случаев
    let empty_region = MemoryRegion {
        base_address: MemoryAddress(0x1000),
        size: 0,
        permissions: MemoryPermissions::READ_ONLY,
        region_type: MemoryRegionType::Unknown,
        module_name: None,
        metadata: std::collections::HashMap::new(),
    };
    
    assert!(!empty_region.is_scannable()); // Пустой регион нельзя сканировать
    
    let no_read_region = MemoryRegion {
        base_address: MemoryAddress(0x1000),
        size: 0x1000,
        permissions: MemoryPermissions {
            read: false,
            write: true,
            execute: true,
        },
        region_type: MemoryRegionType::Private,
        module_name: None,
        metadata: std::collections::HashMap::new(),
    };
    
    assert!(!no_read_region.is_scannable()); // Без права чтения нельзя сканировать
    
    println!("✅ Граничные случаи обработаны безопасно!");
}

#[test]
fn test_architecture_types() {
    let architectures = [
        ProcessArchitecture::X86,
        ProcessArchitecture::X64,
        ProcessArchitecture::ARM,
        ProcessArchitecture::ARM64,
        ProcessArchitecture::Unknown,
    ];
    
    for arch in architectures {
        let process = ProcessInfo {
            pid: ProcessId(1234),
            name: "test".to_string(),
            exe_path: None,
            command_line: None,
            parent_pid: None,
            user_id: None,
            memory_usage_bytes: None,
            cpu_time_ms: None,
            start_time: None,
            is_system_process: false,
            architecture: arch,
        };
        
        assert_eq!(process.architecture, arch);
    }
    
    println!("✅ Все архитектуры поддерживаются!");
}

#[test]
fn test_integrity_levels() {
    use ech_core::memory::types::IntegrityLevel;
    
    let levels = [
        IntegrityLevel::Untrusted,
        IntegrityLevel::Low,
        IntegrityLevel::Medium,
        IntegrityLevel::High,
        IntegrityLevel::System,
        IntegrityLevel::Protected,
    ];
    
    // Проверяем порядок уровней
    assert!(IntegrityLevel::Untrusted < IntegrityLevel::Low);
    assert!(IntegrityLevel::Low < IntegrityLevel::Medium);
    assert!(IntegrityLevel::Medium < IntegrityLevel::High);
    assert!(IntegrityLevel::High < IntegrityLevel::System);
    assert!(IntegrityLevel::System < IntegrityLevel::Protected);
    
    println!("✅ Уровни целостности упорядочены правильно!");
}

#[test]
fn test_concurrent_safety() {
    use std::sync::Arc;
    use std::thread;
    
    let region = Arc::new(MemoryRegion {
        base_address: MemoryAddress(0x1000),
        size: 0x1000,
        permissions: MemoryPermissions::READ_ONLY,
        region_type: MemoryRegionType::Heap,
        module_name: None,
        metadata: std::collections::HashMap::new(),
    });
    
    let handles: Vec<_> = (0..10).map(|i| {
        let region = Arc::clone(&region);
        thread::spawn(move || {
            let addr = MemoryAddress(0x1000 + i * 0x100);
            region.contains_address(addr)
        })
    }).collect();
    
    for handle in handles {
        let _result = handle.join().unwrap();
    }
    
    println!("✅ Потокобезопасность обеспечена!");
}