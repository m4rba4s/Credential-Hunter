//! Region metadata definitions shared by the memory scanner and analyzer.

/// Description of a contiguous virtual memory segment.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Starting virtual address for the region.
    pub start_address: u64,
    /// Size of the region in bytes.
    pub size: usize,
    /// Access permissions derived from `/proc/<pid>/maps` or equivalent APIs.
    pub permissions: RegionPermissions,
    /// High-level classification (heap, stack, module, etc.).
    pub region_type: RegionType,
    /// Module or backing file name when available.
    pub module_name: Option<String>,
    /// String representation of the OS protection mask.
    pub protection: String,
}

/// Fine-grained permission flags for a region.
#[derive(Debug, Clone)]
pub struct RegionPermissions {
    /// Region is readable.
    pub read: bool,
    /// Region is writable.
    pub write: bool,
    /// Region is executable.
    pub execute: bool,
}

/// Coarse classification used for reporting and filtering.
#[derive(Debug, Clone)]
pub enum RegionType {
    /// Heap-allocated memory.
    Heap,
    /// Thread stack.
    Stack,
    /// Shared library or module range.
    Module,
    /// Private/anonymous mapping.
    Private,
    /// File-backed or shared mapping.
    Mapped,
    /// Unable to classify.
    Unknown,
}

/// Complete memory map for a process, including all regions.
#[derive(Debug)]
pub struct MemoryMap {
    /// Process identifier owning this map.
    pub pid: u32,
    /// Regions discovered for the process.
    pub regions: Vec<MemoryRegion>,
}
