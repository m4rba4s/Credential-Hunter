use super::FilesystemConfig;
/**
 * ECH Filesystem Analyzers Module
 */
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use tokio::task;

/// Performs lightweight static inspection of files before scanning.
pub struct FileAnalyzer {
    preview_bytes: usize,
}

/// Summary of the on-disk file characteristics.
#[derive(Debug, Clone)]
pub struct FileAnalysis {
    /// Absolute path to the analyzed file.
    pub path: PathBuf,
    /// File size in bytes.
    pub size: u64,
    /// Last modification timestamp if available.
    pub modified: Option<DateTime<Utc>>,
    /// Last access timestamp if available.
    pub accessed: Option<DateTime<Utc>>,
    /// Lightweight content analysis summary.
    pub content: ContentAnalysis,
}

/// Summary of the sampled file contents.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ContentAnalysis {
    /// UTF-8 preview of the beginning of the file.
    pub preview: String,
    /// Shannon entropy estimate for the sampled bytes.
    pub entropy: f64,
    /// Number of newline-delimited lines captured in the preview.
    pub line_count: usize,
    /// Whether the preview contains binary data.
    pub is_binary: bool,
}

impl FileAnalyzer {
    /// Construct a new analyzer based on the filesystem configuration.
    pub fn new(config: &FilesystemConfig) -> Result<Self> {
        Ok(Self {
            preview_bytes: config.buffer_size.min(128 * 1024),
        })
    }

    /// Perform a blocking analysis of the provided file path.
    pub async fn analyze_file(&self, path: &Path) -> Result<FileAnalysis> {
        let path = path.to_path_buf();
        let preview_bytes = self.preview_bytes;
        task::spawn_blocking(move || analyze_blocking(&path, preview_bytes))
            .await
            .context("file analysis task failed")?
    }
}

fn analyze_blocking(path: &Path, preview_bytes: usize) -> Result<FileAnalysis> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to read metadata for {}", path.display()))?;
    let mut file = File::open(path)
        .with_context(|| format!("failed to open {} for analysis", path.display()))?;

    let mut buffer = vec![0u8; preview_bytes];
    let bytes_read = file
        .read(&mut buffer)
        .with_context(|| format!("failed to read {}", path.display()))?;
    buffer.truncate(bytes_read);

    let is_binary = buffer.iter().any(|b| *b == 0);
    let preview = if let Ok(text) = String::from_utf8(buffer.clone()) {
        text
    } else {
        String::new()
    };
    let line_count = preview.lines().count();
    let entropy = calculate_entropy(&buffer);

    let modified = metadata.modified().ok().map(DateTime::<Utc>::from);
    let accessed = metadata.accessed().ok().map(DateTime::<Utc>::from);

    Ok(FileAnalysis {
        path: path.to_path_buf(),
        size: metadata.len(),
        modified,
        accessed,
        content: ContentAnalysis {
            preview,
            entropy,
            line_count,
            is_binary,
        },
    })
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for byte in data {
        counts[*byte as usize] += 1;
    }

    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn analyzes_basic_file() {
        let config = FilesystemConfig::default();
        let analyzer = FileAnalyzer::new(&config).unwrap();
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("sample.txt");
        std::fs::write(&file_path, "LINE1\nLINE2\n").unwrap();

        let analysis = analyzer.analyze_file(&file_path).await.unwrap();
        assert_eq!(analysis.content.line_count, 2);
        assert!(analysis.content.entropy > 0.0);
    }
}
