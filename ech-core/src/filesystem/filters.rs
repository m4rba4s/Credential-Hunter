/**
 * ECH Filesystem Filters Module
 */

use anyhow::Result;
use std::path::Path;
use super::FilesystemConfig;

pub struct FileFilter;
pub struct FilterCriteria;
pub struct FilterRule;

impl FileFilter {
    pub async fn new(_config: &FilesystemConfig) -> Result<Self> {
        Ok(Self)
    }
    
    pub async fn should_exclude_directory(&self, _path: &Path) -> bool {
        false
    }
    
    pub async fn should_scan_file(&self, _path: &Path) -> bool {
        true
    }
}