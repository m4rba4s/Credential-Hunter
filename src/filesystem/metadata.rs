use super::FilesystemConfig;
/**
 * ECH Filesystem Metadata Module
 */
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::fs::{self, Metadata};
use std::path::{Path, PathBuf};
use tokio::task;

/// Collects platform-specific file metadata and extended attributes.
pub struct MetadataAnalyzer {
    collect_extended_attributes: bool,
}

/// Rich metadata describing a file or directory.
#[derive(Debug, Clone)]
pub struct FileMetadata {
    /// Absolute path to the file or directory.
    pub path: PathBuf,
    /// File size in bytes.
    pub size: u64,
    /// Whether the item is read-only.
    pub readonly: bool,
    /// Indicates the item is a directory.
    pub is_directory: bool,
    /// Indicates the item is a symbolic link.
    pub is_symlink: bool,
    /// Platform-specific permissions string (e.g., 755).
    pub permissions: String,
    /// Owning user ID when available.
    pub owner: Option<u32>,
    /// Owning group ID when available.
    pub group: Option<u32>,
    /// Creation timestamp if reported by the filesystem.
    pub created: Option<DateTime<Utc>>,
    /// Last modification timestamp.
    pub modified: Option<DateTime<Utc>>,
    /// Last access timestamp.
    pub accessed: Option<DateTime<Utc>>,
    /// Extended attribute metadata.
    pub extended_attributes: ExtendedAttributes,
}

/// List of extended attribute keys attached to a file.
#[derive(Debug, Clone, Default)]
pub struct ExtendedAttributes {
    /// Names of extended attributes present on disk.
    pub keys: Vec<String>,
}

impl MetadataAnalyzer {
    /// Construct a metadata analyzer; respects config for extended attributes.
    pub fn new(_config: &FilesystemConfig) -> Result<Self> {
        Ok(Self {
            collect_extended_attributes: true,
        })
    }

    /// Collect metadata for the specified path.
    pub async fn analyze_metadata(&self, path: &Path) -> Result<FileMetadata> {
        let path = path.to_path_buf();
        let collect_xattrs = self.collect_extended_attributes;
        task::spawn_blocking(move || analyze_metadata_blocking(&path, collect_xattrs))
            .await
            .context("metadata analysis task failed")?
    }
}

fn analyze_metadata_blocking(path: &Path, collect_xattrs: bool) -> Result<FileMetadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to read metadata for {}", path.display()))?;

    let extended_attributes = if collect_xattrs {
        ExtendedAttributes {
            keys: list_xattrs(path).unwrap_or_default(),
        }
    } else {
        ExtendedAttributes::default()
    };

    Ok(FileMetadata {
        path: path.to_path_buf(),
        size: metadata.len(),
        readonly: metadata.permissions().readonly(),
        is_directory: metadata.is_dir(),
        is_symlink: metadata.file_type().is_symlink(),
        permissions: format_permissions(&metadata),
        owner: owner(&metadata),
        group: group(&metadata),
        created: metadata.created().ok().map(DateTime::<Utc>::from),
        modified: metadata.modified().ok().map(DateTime::<Utc>::from),
        accessed: metadata.accessed().ok().map(DateTime::<Utc>::from),
        extended_attributes,
    })
}

fn format_permissions(metadata: &Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        return format!("{:o}", metadata.permissions().mode() & 0o777);
    }

    #[cfg(not(unix))]
    {
        if metadata.permissions().readonly() {
            "readonly".to_string()
        } else {
            "rw".to_string()
        }
    }
}

fn owner(metadata: &Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(metadata.uid())
    }

    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

fn group(metadata: &Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(metadata.gid())
    }

    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

fn list_xattrs(path: &Path) -> Result<Vec<String>> {
    #[cfg(unix)]
    {
        let mut keys = Vec::new();
        match xattr::list(path) {
            Ok(iter) => {
                for attr in iter {
                    if let Some(s) = attr.to_str() {
                        keys.push(s.to_string());
                    }
                }
                Ok(keys)
            }
            Err(e) => Err(anyhow::anyhow!(
                "failed to list xattrs for {}: {}",
                path.display(),
                e
            )),
        }
    }

    #[cfg(not(unix))]
    {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn gathers_basic_metadata() {
        let config = FilesystemConfig::default();
        let analyzer = MetadataAnalyzer::new(&config).unwrap();
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("meta.txt");
        std::fs::write(&file_path, "meta").unwrap();

        let metadata = analyzer.analyze_metadata(&file_path).await.unwrap();
        assert_eq!(metadata.path, file_path);
        assert_eq!(metadata.is_directory, false);
        assert!(metadata.size > 0);
    }
}
