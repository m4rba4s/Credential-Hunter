//! Filesystem include/exclude filtering helpers.

use super::FilesystemConfig;
use anyhow::{Context, Result};
use glob::Pattern;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use tracing::debug;

/// Applies include/exclude patterns and size/hidden checks to filesystem entries.
pub struct FileFilter {
    include_patterns: Vec<Pattern>,
    exclude_patterns: Vec<Pattern>,
    exclude_directories: Vec<PathBuf>,
    exclude_directory_names: Vec<String>,
    max_file_size: u64,
    scan_hidden: bool,
    scan_binary: bool,
    sample_bytes: usize,
}

impl FileFilter {
    /// Build a filter based on the filesystem configuration.
    pub fn new(config: &FilesystemConfig) -> Result<Self> {
        Ok(Self {
            include_patterns: compile_patterns(&config.include_patterns)?,
            exclude_patterns: compile_patterns(&config.exclude_patterns)?,
            exclude_directories: config
                .exclude_directories
                .iter()
                .map(PathBuf::from)
                .collect(),
            exclude_directory_names: config
                .exclude_directories
                .iter()
                .filter_map(|dir| Path::new(dir).file_name())
                .filter_map(|name| name.to_str())
                .map(|s| s.to_string())
                .collect(),
            max_file_size: config.max_file_size,
            scan_hidden: config.scan_hidden,
            scan_binary: config.scan_binary,
            sample_bytes: config.buffer_size.min(4096),
        })
    }

    /// Determine whether a directory should be excluded from scanning.
    pub fn should_exclude_directory(&self, path: &Path) -> bool {
        if !self.scan_hidden && is_hidden(path) {
            return true;
        }

        if self
            .exclude_directories
            .iter()
            .any(|blocked| !blocked.as_os_str().is_empty() && path.starts_with(blocked))
        {
            return true;
        }

        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if self
                .exclude_directory_names
                .iter()
                .any(|blocked| blocked == name)
            {
                return true;
            }
        }

        false
    }

    /// Determine whether a file should be scanned based on rules and heuristics.
    pub fn should_scan_file(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        let explicitly_included =
            !self.include_patterns.is_empty() && matches_any(&self.include_patterns, &path_str);

        if matches_any(&self.exclude_patterns, &path_str) {
            return false;
        }

        if !self.include_patterns.is_empty() && !explicitly_included {
            return false;
        }

        if !explicitly_included {
            if let Some(parent) = path.parent() {
                if self.should_exclude_directory(parent) {
                    return false;
                }
            }

            if !self.scan_hidden && is_hidden(path) {
                return false;
            }
        }

        if self.max_file_size > 0 {
            match std::fs::metadata(path) {
                Ok(metadata) => {
                    if metadata.len() > self.max_file_size {
                        return false;
                    }
                }
                Err(e) => {
                    debug!("metadata check failed for {}: {}", path.display(), e);
                    return false;
                }
            }
        }

        if !explicitly_included && !self.scan_binary && file_looks_binary(path, self.sample_bytes) {
            return false;
        }

        true
    }
}

fn compile_patterns(patterns: &[String]) -> Result<Vec<Pattern>> {
    patterns
        .iter()
        .map(|pattern| {
            Pattern::new(pattern).with_context(|| format!("invalid glob pattern: {}", pattern))
        })
        .collect()
}

fn matches_any(patterns: &[Pattern], target: &str) -> bool {
    patterns.iter().any(|pattern| pattern.matches(target))
}

fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.starts_with('.'))
        .unwrap_or(false)
}

fn file_looks_binary(path: &Path, sample_bytes: usize) -> bool {
    if sample_bytes == 0 {
        return false;
    }

    match read_prefix(path, sample_bytes) {
        Ok(buffer) => {
            if buffer.is_empty() {
                return false;
            }

            let non_text = buffer
                .iter()
                .filter(|byte| !byte.is_ascii_graphic() && !byte.is_ascii_whitespace())
                .count();

            non_text as f64 / buffer.len() as f64 > 0.3
        }
        Err(e) => {
            debug!("binary sniff failed for {}: {}", path.display(), e);
            false
        }
    }
}

fn read_prefix(path: &Path, sample_bytes: usize) -> Result<Vec<u8>> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut buffer = vec![0u8; sample_bytes];
    let bytes_read = file
        .read(&mut buffer)
        .with_context(|| format!("failed to read {}", path.display()))?;
    buffer.truncate(bytes_read);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn respects_include_and_exclude_patterns() {
        let mut config = FilesystemConfig::default();
        config.include_patterns = vec!["*.env".into()];
        config.exclude_patterns = vec!["*.secret.env".into()];

        let filter = FileFilter::new(&config).expect("filter");

        let dir = tempdir().unwrap();
        let env_path = dir.path().join("prod.env");
        std::fs::write(&env_path, b"KEY=value").unwrap();
        let secret_path = dir.path().join("prod.secret.env");
        std::fs::write(&secret_path, b"KEY=value").unwrap();

        assert!(filter.should_scan_file(&env_path));
        assert!(!filter.should_scan_file(&secret_path));
    }
}
