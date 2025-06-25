/**
 * ECH CLI ELITE TESTS - КОМАНДНАЯ СТРОКА КАК ШВЕЙЦАРСКИЙ НОЖ!
 * 
 * Тестируем CLI интерфейс как элитные инженеры:
 * - Каждая команда работает безупречно
 * - Все параметры валидируются
 * - Вывод форматируется идеально
 * - Ошибки обрабатываются профессионально
 */

use anyhow::Result;
use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Тесты базовых команд CLI - каждая должна работать как часы!
#[cfg(test)]
mod cli_basic_tests {
    use super::*;

    #[test]
    fn test_cli_help_professional() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.arg("--help")
           .assert()
           .success()
           .stdout(predicate::str::contains("Enterprise Credential Hunter"))
           .stdout(predicate::str::contains("Professional-grade credential hunting"));
        
        println!("✅ CLI help работает профессионально!");
    }

    #[test]
    fn test_cli_version_display() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.arg("--version")
           .assert()
           .success()
           .stdout(predicate::str::contains("ech"))
           .stdout(predicate::str::is_match(r"\d+\.\d+\.\d+").unwrap());
        
        println!("✅ Версия отображается корректно!");
    }

    #[test]
    fn test_memory_command_help() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["memory", "--help"])
           .assert()
           .success()
           .stdout(predicate::str::contains("Memory credential hunting"))
           .stdout(predicate::str::contains("--pid"))
           .stdout(predicate::str::contains("--all"));
        
        println!("✅ Memory команда документирована отлично!");
    }

    #[test] 
    fn test_cloud_command_help() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["cloud", "--help"])
           .assert()
           .success()
           .stdout(predicate::str::contains("Cloud IMDS exploitation"))
           .stdout(predicate::str::contains("--provider"))
           .stdout(predicate::str::contains("--ebpf"));
        
        println!("✅ Cloud команда готова к бою!");
    }

    #[test]
    fn test_webauthn_command_help() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["web-authn", "--help"])
           .assert()
           .success()
           .stdout(predicate::str::contains("WebAuthn credential extraction"))
           .stdout(predicate::str::contains("--browser"))
           .stdout(predicate::str::contains("--all"));
        
        println!("✅ WebAuthn команда настроена идеально!");
    }

    #[test]
    fn test_lsa_command_help() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["lsa", "--help"])
           .assert()
           .success()
           .stdout(predicate::str::contains("LSA bypass"))
           .stdout(predicate::str::contains("--method"))
           .stdout(predicate::str::contains("--ppl-bypass"));
        
        println!("✅ LSA команда готова к взлому!");
    }

    #[test]
    fn test_dump_command_help() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["dump", "--help"])
           .assert()
           .success()
           .stdout(predicate::str::contains("memory dump"))
           .stdout(predicate::str::contains("--file"))
           .stdout(predicate::str::contains("--dump-type"));
        
        println!("✅ Dump команда работает как мимикац!");
    }

    #[test]
    fn test_stealth_command_help() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["stealth", "--help"])
           .assert()
           .success()
           .stdout(predicate::str::contains("Stealth and evasion"))
           .stdout(predicate::str::contains("--test"))
           .stdout(predicate::str::contains("--status"));
        
        println!("✅ Stealth команда невидима как ниндзя!");
    }
}

/// Тесты валидации параметров - никаких дыр в защите!
#[cfg(test)]
mod cli_validation_tests {
    use super::*;

    #[test]
    fn test_memory_command_requires_target() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["memory"])
           .assert()
           .failure()
           .stderr(predicate::str::contains("Must specify"));
        
        println!("✅ Memory команда правильно требует цель!");
    }

    #[test]
    fn test_dump_command_requires_file() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["dump"])
           .assert()
           .failure()
           .stderr(predicate::str::contains("required"));
        
        println!("✅ Dump команда требует файл как положено!");
    }

    #[test]
    fn test_invalid_output_format_rejected() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["memory", "--all", "--output", "invalid_format"])
           .assert()
           .failure();
        
        println!("✅ Неверные форматы отклоняются!");
    }

    #[test]
    fn test_invalid_cloud_provider_rejected() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["cloud", "--provider", "invalid_provider"])
           .assert()
           .failure();
        
        println!("✅ Неверные провайдеры отклоняются!");
    }

    #[test]
    fn test_negative_timeout_rejected() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["cloud", "--timeout", "0"])
           .assert()
           .failure();
        
        println!("✅ Неверные таймауты отклоняются!");
    }
}

/// Тесты форматов вывода - каждый байт на своем месте!
#[cfg(test)]
mod cli_output_tests {
    use super::*;

    #[test]
    fn test_json_output_format() {
        let temp_dir = TempDir::new().unwrap();
        let output_file = temp_dir.path().join("output.json");
        
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&[
            "memory", "--all", 
            "--output", "json",
            "--output-file", output_file.to_str().unwrap()
        ])
        .assert()
        .success();
        
        // Проверяем что файл создан и содержит валидный JSON
        assert!(output_file.exists(), "Выходной файл должен быть создан!");
        
        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("{"), "Должен быть валидный JSON!");
        assert!(content.contains("session_id"), "Должен содержать session_id!");
        
        println!("✅ JSON вывод работает идеально!");
    }

    #[test]
    fn test_table_output_format() {
        let temp_dir = TempDir::new().unwrap();
        let output_file = temp_dir.path().join("output.txt");
        
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&[
            "stealth", "--status",
            "--output", "table", 
            "--output-file", output_file.to_str().unwrap()
        ])
        .assert()
        .success();
        
        // Проверяем табличный формат
        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("┌") || content.contains("|"), "Должна быть таблица!");
        
        println!("✅ Табличный вывод красив как швейцарские часы!");
    }

    #[test]
    fn test_csv_output_format() {
        let temp_dir = TempDir::new().unwrap();
        let output_file = temp_dir.path().join("output.csv");
        
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&[
            "config", "--show",
            "--output", "csv",
            "--output-file", output_file.to_str().unwrap()
        ])
        .assert()
        .success();
        
        // Проверяем CSV формат
        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains(","), "Должен быть CSV формат!");
        
        println!("✅ CSV вывод структурирован отлично!");
    }
}

/// Тесты конфигурации - настройки как у Formula 1!
#[cfg(test)]
mod cli_config_tests {
    use super::*;

    #[test]
    fn test_config_show_command() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["config", "--show"])
           .assert()
           .success()
           .stdout(predicate::str::contains("operation"))
           .stdout(predicate::str::contains("config"));
        
        println!("✅ Показ конфигурации работает!");
    }

    #[test]
    fn test_config_with_custom_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("test_config.json");
        
        // Создаем тестовый конфиг файл
        fs::write(&config_file, r#"{"test": "config"}"#).unwrap();
        
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&[
            "--config", config_file.to_str().unwrap(),
            "config", "--show"
        ])
        .assert()
        .success();
        
        println!("✅ Пользовательские конфиги загружаются!");
    }

    #[test] 
    fn test_verbose_logging() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["--verbose", "config", "--show"])
           .assert()
           .success();
        
        println!("✅ Verbose режим активируется!");
    }

    #[test]
    fn test_stealth_level_setting() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["--stealth", "high", "stealth", "--status"])
           .assert()
           .success();
        
        println!("✅ Уровни стелс устанавливаются!");
    }
}

/// Тесты функциональности - каждая функция работает!
#[cfg(test)]
mod cli_functionality_tests {
    use super::*;

    #[test]
    fn test_memory_scan_simulation() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["memory", "--all", "--include-system"])
           .assert()
           .success()
           .stdout(predicate::str::contains("scan_type"))
           .stdout(predicate::str::contains("memory"));
        
        println!("✅ Симуляция сканирования памяти работает!");
    }

    #[test]
    fn test_cloud_scan_simulation() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["cloud", "--provider", "aws", "--timeout", "30"])
           .assert()
           .success()
           .stdout(predicate::str::contains("cloud_imds"));
        
        println!("✅ Симуляция облачного сканирования работает!");
    }

    #[test]
    fn test_webauthn_scan_simulation() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["web-authn", "--all"])
           .assert()
           .success()
           .stdout(predicate::str::contains("webauthn"));
        
        println!("✅ Симуляция WebAuthn сканирования работает!");
    }

    #[test]
    fn test_lsa_bypass_simulation() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["lsa", "--method", "auto", "--ppl-bypass"])
           .assert()
           .success()
           .stdout(predicate::str::contains("lsa_bypass"));
        
        println!("✅ Симуляция LSA bypass работает!");
    }

    #[test]
    fn test_dump_analysis_simulation() {
        let temp_dir = TempDir::new().unwrap();
        let dump_file = temp_dir.path().join("test.dmp");
        
        // Создаем фиктивный dump файл
        fs::write(&dump_file, b"fake dump content").unwrap();
        
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&[
            "dump", 
            "--file", dump_file.to_str().unwrap(),
            "--dump-type", "lsass"
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("dump_analysis"));
        
        println!("✅ Симуляция анализа дампов работает!");
    }

    #[test]
    fn test_stealth_operations() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["stealth", "--test", "--status", "--apply"])
           .assert()
           .success()
           .stdout(predicate::str::contains("stealth"));
        
        println!("✅ Стелс операции выполняются!");
    }
}

/// Тесты обработки ошибок - каждая ошибка под контролем!
#[cfg(test)]
mod cli_error_handling_tests {
    use super::*;

    #[test]
    fn test_nonexistent_file_error() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["dump", "--file", "/nonexistent/file.dmp"])
           .assert()
           .failure()
           .stderr(predicate::str::contains("Operation failed"));
        
        println!("✅ Ошибки несуществующих файлов обрабатываются!");
    }

    #[test]
    fn test_invalid_pid_error() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["memory", "--pid", "99999999"])
           .assert()
           .failure();
        
        println!("✅ Неверные PID обрабатываются!");
    }

    #[test]
    fn test_permission_error_handling() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["memory", "--pid", "1"]) // Обычно требует root
           .assert()
           .failure();
        
        println!("✅ Ошибки прав доступа обрабатываются!");
    }

    #[test]
    fn test_conflicting_options_error() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["web-authn", "--all", "--browser", "chrome"])
           .assert()
           .failure()
           .stderr(predicate::str::contains("Must specify"));
        
        println!("✅ Конфликтующие опции отклоняются!");
    }
}

/// Тесты производительности CLI - скорость как молния!
#[cfg(test)]
mod cli_performance_tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn test_help_command_speed() {
        let start = Instant::now();
        
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.arg("--help")
           .assert()
           .success();
        
        let duration = start.elapsed();
        assert!(duration < Duration::from_secs(2), "Help должен быть быстрым: {:?}", duration);
        
        println!("✅ Help команда быстрая как молния!");
    }

    #[test]
    fn test_config_show_speed() {
        let start = Instant::now();
        
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["config", "--show"])
           .assert()
           .success();
        
        let duration = start.elapsed();
        assert!(duration < Duration::from_secs(5), "Config show должен быть быстрым: {:?}", duration);
        
        println!("✅ Config команды работают быстро!");
    }

    #[test]
    fn test_stealth_status_speed() {
        let start = Instant::now();
        
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["stealth", "--status"])
           .assert()
           .success();
        
        let duration = start.elapsed();
        assert!(duration < Duration::from_secs(3), "Stealth status должен быть быстрым: {:?}", duration);
        
        println!("✅ Stealth команды молниеносны!");
    }
}

/// Интеграционные тесты CLI - все работает как единое целое!
#[cfg(test)]
mod cli_integration_tests {
    use super::*;

    #[test]
    fn test_full_workflow_simulation() {
        let temp_dir = TempDir::new().unwrap();
        
        // 1. Показываем конфиг
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&["config", "--show"])
           .assert()
           .success();
        
        // 2. Проверяем стелс статус
        let mut cmd = Command::cargo_bin("ech").unwrap(); 
        cmd.args(&["stealth", "--status"])
           .assert()
           .success();
        
        // 3. Симулируем сканирование памяти
        let output_file = temp_dir.path().join("memory_results.json");
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&[
            "memory", "--all",
            "--output", "json",
            "--output-file", output_file.to_str().unwrap()
        ])
        .assert()
        .success();
        
        // 4. Проверяем результаты
        assert!(output_file.exists(), "Файл результатов должен быть создан!");
        let content = fs::read_to_string(&output_file).unwrap();
        assert!(content.contains("session_id"), "Результаты должны содержать session_id!");
        
        println!("✅ Полный workflow работает как симфония!");
    }

    #[test]
    fn test_multiple_output_formats() {
        let temp_dir = TempDir::new().unwrap();
        let formats = vec!["json", "table", "csv"];
        
        for format in formats {
            let output_file = temp_dir.path().join(format!("test.{}", format));
            
            let mut cmd = Command::cargo_bin("ech").unwrap();
            cmd.args(&[
                "config", "--show",
                "--output", format,
                "--output-file", output_file.to_str().unwrap()
            ])
            .assert()
            .success();
            
            assert!(output_file.exists(), "Файл для формата {} должен быть создан!", format);
        }
        
        println!("✅ Все форматы вывода работают идеально!");
    }

    #[test]
    fn test_verbose_mode_integration() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&[
            "--verbose",
            "stealth", "--test"
        ])
        .assert()
        .success();
        
        println!("✅ Verbose режим интегрирован идеально!");
    }

    #[test]
    fn test_stealth_mode_integration() {
        let mut cmd = Command::cargo_bin("ech").unwrap();
        cmd.args(&[
            "--stealth", "maximum",
            "memory", "--all"
        ])
        .assert()
        .success();
        
        println!("✅ Стелс режим интегрирован безупречно!");
    }
}