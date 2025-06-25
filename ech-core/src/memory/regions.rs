/**
 * ECH Memory Regions Module - Clean Architecture
 * 
 * This module provides compatibility layer and re-exports from the
 * centralized types module. Maintains backward compatibility while
 * ensuring consistent type definitions across the entire codebase.
 */

// Re-export all memory-related types from the central types module
pub use super::types::{
    MemoryPermissions as RegionPermissions,
    MemoryRegionType as RegionType, 
    MemoryRegion,
    ProcessMemoryMap as MemoryMap,
    ProcessMemoryMap,
};
pub use crate::types::{MemoryAddress, ProcessId};

// Legacy compatibility - these will be phased out
pub type MemoryRegionVec = Vec<MemoryRegion>;

/// Helper functions for memory region operations
impl MemoryRegion {
    /// Create a new memory region with basic information
    pub fn new(
        start_address: u64,
        size: u64,
        permissions: RegionPermissions,
        region_type: RegionType,
    ) -> Self {
        Self {
            base_address: super::types::MemoryAddress(start_address),
            size,
            permissions,
            region_type,
            module_name: None,
            metadata: std::collections::HashMap::new(),
        }
    }
    
    /// Get start address as u64 for compatibility
    pub fn start_address(&self) -> u64 {
        self.base_address.0
    }
    
    /// Check if region is readable
    pub fn is_readable(&self) -> bool {
        self.permissions.read
    }
    
    /// Check if region is writable
    pub fn is_writable(&self) -> bool {
        self.permissions.write
    }
    
    /// Check if region is executable
    pub fn is_executable(&self) -> bool {
        self.permissions.execute
    }
}

/// Helper functions for memory maps
impl ProcessMemoryMap {
    /// Get process ID as u32 for compatibility
    pub fn pid(&self) -> u32 {
        self.process_id.0
    }
    
    /// Get all regions
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }
    
    /// Get regions by type
    pub fn regions_by_type(&self, region_type: RegionType) -> Vec<&MemoryRegion> {
        self.regions.iter()
            .filter(|r| r.region_type == region_type)
            .collect()
    }
    
    /// Get readable regions only
    pub fn readable_regions(&self) -> Vec<&MemoryRegion> {
        self.regions.iter()
            .filter(|r| r.is_readable())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ProcessId;
    
    #[test]
    fn test_memory_region_creation() {
        let region = MemoryRegion::new(
            0x1000,
            0x1000,
            RegionPermissions::READ_ONLY,
            RegionType::Heap,
        );
        
        assert_eq!(region.start_address(), 0x1000);
        assert!(region.is_readable());
        assert!(!region.is_writable());
        assert!(!region.is_executable());
    }
    
    #[test]
    fn test_memory_map_operations() {
        let regions = vec![
            MemoryRegion::new(0x1000, 0x1000, RegionPermissions::READ_ONLY, RegionType::Heap),
            MemoryRegion::new(0x2000, 0x1000, RegionPermissions::READ_WRITE, RegionType::Stack),
        ];
        
        let memory_map = ProcessMemoryMap::new(crate::memory::types::ProcessId(1234), regions);
        
        assert_eq!(memory_map.pid(), 1234);
        assert_eq!(memory_map.regions().len(), 2);
        assert_eq!(memory_map.readable_regions().len(), 2);
        assert_eq!(memory_map.regions_by_type(RegionType::Heap).len(), 1);
    }
}