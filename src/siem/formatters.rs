/**
 * ECH SIEM Formatters Module
 */

use anyhow::Result;
use super::{events::SiemEvent, integration::SiemPlatform};

pub struct EventFormatter;
pub struct FormatType;
pub struct FormattedEvent;

impl EventFormatter {
    pub async fn new(_platform: &SiemPlatform) -> Result<Self> {
        Ok(Self)
    }
    
    pub async fn format_events(&self, _events: &[SiemEvent]) -> Result<Vec<FormattedEvent>> {
        Ok(Vec::new())
    }
}