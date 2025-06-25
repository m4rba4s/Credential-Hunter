/**
 * ECH Filesystem Metadata Module
 */

use anyhow::Result;
use std::path::Path;
use super::FilesystemConfig;

pub struct MetadataAnalyzer;

#[derive(Debug, Clone)]
pub struct FileMetadata;

#[derive(Debug)]
pub struct ExtendedAttributes;

impl MetadataAnalyzer {
    pub async fn new(_config: &FilesystemConfig) -> Result<Self> {
        Ok(Self)
    }
    
    pub async fn analyze_metadata(&self, _path: &Path) -> Result<FileMetadata> {
        Ok(FileMetadata)
    }
}