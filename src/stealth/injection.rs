/**
 * ECH Stealth Injection Module
 */

use anyhow::Result;
use super::StealthSystemConfig;

pub struct ProcessInjector;
pub struct InjectionMethod;
pub struct InjectionTarget;

impl ProcessInjector {
    pub async fn new(_config: &StealthSystemConfig) -> Result<Self> { Ok(Self) }
    pub async fn prepare_injection_target(&self) -> Result<()> { Ok(()) }
}