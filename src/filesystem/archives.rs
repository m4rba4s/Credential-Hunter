use super::FilesystemConfig;
use crate::detection::engine::CredentialLocation;
use crate::detection::{DetectionEngine, DetectionResult};
/**
 * ECH Filesystem Archives Module
 */
use anyhow::{anyhow, Context, Result};
use std::io::Read;
use std::path::Path;
use tokio::task;
use tracing::{debug, warn};

/// Extracts and scans supported archive formats.
pub struct ArchiveScanner {
    max_entry_size: u64,
    enabled: bool,
}

/// Supported archive formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveType {
    /// ZIP archive.
    Zip,
    /// TAR archive.
    Tar,
    /// TAR.GZ archive.
    TarGz,
    /// Single-file gzip payload.
    Gzip,
}

/// Result of scanning a single archive entry.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    /// Logical path within the archive.
    pub entry_path: String,
    /// Entry size in bytes.
    pub size: u64,
    /// Detections produced while scanning the entry.
    pub detections: Vec<DetectionResult>,
}

impl ArchiveScanner {
    /// Construct an archive scanner using the filesystem configuration.
    pub fn new(config: &FilesystemConfig) -> Result<Self> {
        Ok(Self {
            max_entry_size: config.max_file_size.max(1),
            enabled: config.scan_archives,
        })
    }

    /// Determine whether the provided path appears to be an archive.
    pub async fn is_archive(&self, path: &Path) -> bool {
        if !self.enabled {
            return false;
        }

        self.detect_type(path).await.ok().flatten().is_some()
    }

    /// Identify the archive type for the provided path.
    pub async fn detect_archive_type(&self, path: &Path) -> Result<ArchiveType> {
        if !self.enabled {
            return Err(anyhow!("archive scanning disabled"));
        }

        self.detect_type(path)
            .await?
            .ok_or_else(|| anyhow!("unsupported archive format: {}", path.display()))
    }

    /// Extract the archive and scan each entry for credentials.
    pub async fn extract_and_scan(
        &self,
        path: &Path,
        detection_engine: &DetectionEngine,
    ) -> Result<Vec<ArchiveEntry>> {
        let archive_type = self.detect_archive_type(path).await?;
        let payloads = self.read_archive_payloads(path, archive_type).await?;
        let mut entries = Vec::with_capacity(payloads.len());
        let archive_name = path.display().to_string();

        for payload in payloads {
            let location = CredentialLocation {
                source_type: "archive".to_string(),
                path: format!("{}!{}", archive_name, payload.entry_name),
                line_number: None,
                column: None,
                memory_address: None,
                process_id: None,
                container_id: None,
            };

            let detections = if let Ok(text) = std::str::from_utf8(&payload.data) {
                detection_engine
                    .detect_in_text(text, location.clone())
                    .await?
            } else {
                detection_engine
                    .detect_in_binary(&payload.data, location.clone())
                    .await?
            };

            entries.push(ArchiveEntry {
                entry_path: location.path,
                size: payload.data.len() as u64,
                detections,
            });
        }

        Ok(entries)
    }

    async fn detect_type(&self, path: &Path) -> Result<Option<ArchiveType>> {
        let path = path.to_path_buf();
        task::spawn_blocking(move || sniff_archive_type(&path)).await?
    }

    async fn read_archive_payloads(
        &self,
        path: &Path,
        archive_type: ArchiveType,
    ) -> Result<Vec<ArchivePayload>> {
        let path = path.to_path_buf();
        let max_entry_size = self.max_entry_size;
        task::spawn_blocking(move || match archive_type {
            ArchiveType::Zip => read_zip_entries(&path, max_entry_size),
            ArchiveType::Tar => read_tar_entries(&path, None, max_entry_size),
            ArchiveType::TarGz => read_tar_entries(&path, Some(Compression::Gzip), max_entry_size),
            ArchiveType::Gzip => read_gzip_entry(&path, max_entry_size),
        })
        .await?
    }
}

#[derive(Debug)]
struct ArchivePayload {
    entry_name: String,
    data: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
enum Compression {
    /// Single-file gzip payload.
    Gzip,
}

fn sniff_archive_type(path: &Path) -> Result<Option<ArchiveType>> {
    let lower_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_lowercase())
        .unwrap_or_default();

    if lower_name.ends_with(".tar.gz") || lower_name.ends_with(".tgz") {
        return Ok(Some(ArchiveType::TarGz));
    }
    if lower_name.ends_with(".tar") {
        return Ok(Some(ArchiveType::Tar));
    }
    if lower_name.ends_with(".zip") {
        return Ok(Some(ArchiveType::Zip));
    }
    if lower_name.ends_with(".gz") {
        return Ok(Some(ArchiveType::Gzip));
    }

    let mut magic = [0u8; 4];
    let read = std::fs::File::open(path)
        .and_then(|mut file| file.read(&mut magic))
        .unwrap_or(0);

    if read >= 4 && &magic[..4] == b"PK\x03\x04" {
        return Ok(Some(ArchiveType::Zip));
    }
    if read >= 2 && magic[0] == 0x1F && magic[1] == 0x8B {
        return Ok(Some(ArchiveType::Gzip));
    }

    Ok(None)
}

fn read_zip_entries(path: &Path, max_entry_size: u64) -> Result<Vec<ArchivePayload>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open archive {}", path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| format!("invalid zip archive {}", path.display()))?;
    let mut payloads = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if entry.is_dir() {
            continue;
        }
        if entry.size() > max_entry_size {
            warn!("skipping large archive entry {}", entry.name());
            continue;
        }

        let mut data = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut data)
            .with_context(|| format!("failed to read entry {}", entry.name()))?;
        payloads.push(ArchivePayload {
            entry_name: entry.name().to_string(),
            data,
        });
    }

    Ok(payloads)
}

fn read_tar_entries(
    path: &Path,
    compression: Option<Compression>,
    max_entry_size: u64,
) -> Result<Vec<ArchivePayload>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open archive {}", path.display()))?;
    let reader: Box<dyn Read> = match compression {
        Some(Compression::Gzip) => Box::new(flate2::read::GzDecoder::new(file)),
        None => Box::new(file),
    };

    let mut archive = tar::Archive::new(reader);
    let mut payloads = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let size = entry.size();
        if size > max_entry_size {
            if let Ok(path) = entry.path() {
                warn!("skipping large tar entry {}", path.display());
            }
            continue;
        }

        let mut data = Vec::with_capacity(size as usize);
        entry.read_to_end(&mut data)?;
        let name = entry
            .path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".into());
        payloads.push(ArchivePayload {
            entry_name: name,
            data,
        });
    }

    Ok(payloads)
}

fn read_gzip_entry(path: &Path, max_entry_size: u64) -> Result<Vec<ArchivePayload>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open archive {}", path.display()))?;
    let mut decoder = flate2::read::GzDecoder::new(file);
    let mut data = Vec::new();
    decoder.read_to_end(&mut data)?;
    if data.len() as u64 > max_entry_size {
        debug!("skipping gzip entry {} due to size", path.display());
        return Ok(Vec::new());
    }

    let entry_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.trim_end_matches(".gz").to_string())
        .unwrap_or_else(|| "<gzip>".into());

    Ok(vec![ArchivePayload { entry_name, data }])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::engine::{DetectionConfig, DetectionEngine};
    use std::io::Write;
    use tempfile::tempdir;

    async fn detection_engine() -> DetectionEngine {
        DetectionEngine::new(DetectionConfig::default())
            .await
            .expect("engine")
    }

    #[tokio::test]
    async fn scans_zip_archive_for_secrets() {
        let config = FilesystemConfig::default();
        let scanner = ArchiveScanner::new(&config).unwrap();

        let dir = tempdir().unwrap();
        let zip_path = dir.path().join("test.zip");

        {
            let file = std::fs::File::create(&zip_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::FileOptions::default();
            zip.start_file("secret.txt", options).unwrap();
            zip.write_all(b"AWS_ACCESS_KEY_ID=AKIA1234567890ABCD12")
                .unwrap();
            zip.finish().unwrap();
        }

        assert!(scanner.is_archive(&zip_path).await);
        let engine = detection_engine().await;
        let entries = scanner.extract_and_scan(&zip_path, &engine).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].entry_path.contains("secret.txt"));
        assert!(entries[0].size > 0);
    }
}
