/**
 * ECH Memory Regions Module
 */

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start_address: u64,
    pub size: usize,
    pub permissions: RegionPermissions,
    pub region_type: RegionType,
    pub module_name: Option<String>,
    pub protection: String,
}

#[derive(Debug, Clone)]
pub struct RegionPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Debug, Clone)]
pub enum RegionType {
    Heap,
    Stack,
    Module,
    Private,
    Mapped,
    Unknown,
}

#[derive(Debug)]
pub struct MemoryMap {
    pub pid: u32,
    pub regions: Vec<MemoryRegion>,
}