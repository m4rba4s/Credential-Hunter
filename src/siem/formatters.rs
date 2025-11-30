use super::{events::SiemEvent, integration::SiemPlatform};
/**
 * ECH SIEM Formatters Module
 */
use anyhow::Result;

#[derive(Debug, Clone, Copy)]
pub enum FormatType {
    Json,
}

#[derive(Debug, Clone)]
pub struct FormattedEvent {
    pub format: FormatType,
    pub payload: String,
}

pub struct EventFormatter {
    platform: SiemPlatform,
}

impl EventFormatter {
    pub async fn new(platform: &SiemPlatform) -> Result<Self> {
        Ok(Self {
            platform: platform.clone(),
        })
    }

    pub async fn format_events(&self, events: &[SiemEvent]) -> Result<Vec<FormattedEvent>> {
        let mut formatted = Vec::with_capacity(events.len());
        for event in events {
            let payload = serde_json::to_string(event)?;
            formatted.push(FormattedEvent {
                format: match self.platform {
                    SiemPlatform::ArcSight | SiemPlatform::QRadar => FormatType::Json,
                    _ => FormatType::Json,
                },
                payload,
            });
        }
        Ok(formatted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::siem::events::{EventMetadata, EventSeverity, EventType, SiemEvent};
    use chrono::Utc;
    use uuid::Uuid;

    #[tokio::test]
    async fn formats_event_to_json() {
        let formatter = EventFormatter::new(&SiemPlatform::Generic).await.unwrap();
        let event = SiemEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: EventType::HighThreat,
            severity: EventSeverity::High,
            source: "ech".into(),
            title: "Test".into(),
            description: "desc".into(),
            host: "localhost".into(),
            user: "tester".into(),
            process: "ech".into(),
            tags: vec!["t".into()],
            custom_fields: Default::default(),
            metadata: EventMetadata {
                session_id: Uuid::new_v4(),
                correlation_id: None,
                tenant_id: None,
                organization: None,
                environment: None,
                version: "1.0.0".into(),
            },
        };

        let formatted = formatter.format_events(&[event]).await.unwrap();
        assert_eq!(formatted.len(), 1);
        assert_eq!(formatted[0].format, FormatType::Json);
        assert!(formatted[0].payload.contains("\"title\":"));
    }
}
