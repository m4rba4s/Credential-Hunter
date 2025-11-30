//! Filesystem watcher utilities for monitor mode.

use super::FilesystemConfig;
use anyhow::{Context, Result};
use notify::{
    event::ModifyKind, Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode,
    Watcher,
};
use std::path::PathBuf;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;
use tracing::{info, warn};

/// High-level watcher event kinds consumed by monitoring logic
/// High-level watcher event kinds consumed by monitoring logic
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemEventKind {
    /// A filesystem entry was created.
    Created,
    /// A filesystem entry was modified.
    Modified,
    /// A filesystem entry was removed.
    Removed,
    /// A filesystem entry was accessed.
    Accessed,
    /// Any other event coming from `notify`.
    Other,
}

/// Structured filesystem event emitted to subscribers
/// Structured filesystem event emitted to subscribers
#[derive(Debug, Clone)]
pub struct FilesystemMonitorEvent {
    /// Path associated with the event.
    pub path: PathBuf,
    /// Event kind.
    pub kind: FilesystemEventKind,
}

#[derive(Debug)]
struct WatcherState {
    shutdown: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

/// Thin wrapper around the OS watcher implementation.
pub struct FilesystemWatcher {
    config: FilesystemConfig,
    state: Mutex<Option<WatcherState>>,
}

impl FilesystemWatcher {
    /// Construct a filesystem watcher.
    pub async fn new(config: &FilesystemConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            state: Mutex::new(None),
        })
    }

    /// Begin monitoring the supplied paths.
    pub async fn start_monitoring(
        &self,
        paths: Vec<PathBuf>,
        event_tx: mpsc::UnboundedSender<FilesystemMonitorEvent>,
    ) -> Result<()> {
        if paths.is_empty() {
            warn!("No paths supplied for filesystem monitoring");
            return Ok(());
        }

        let mut state = self.state.lock().await;
        if state.is_some() {
            warn!("Filesystem watcher already running; ignoring duplicate start");
            return Ok(());
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let config = self.config.clone();
        let handle = tokio::spawn(async move {
            if let Err(err) = run_watcher(paths, config, shutdown_rx, event_tx).await {
                warn!("Filesystem watcher exited with error: {}", err);
            }
        });

        *state = Some(WatcherState {
            shutdown: shutdown_tx,
            handle,
        });

        Ok(())
    }

    /// Stop monitoring and shutdown the watcher task.
    pub async fn stop_monitoring(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        if let Some(state) = state.take() {
            let _ = state.shutdown.send(true);
            if let Err(err) = state.handle.await {
                warn!("Watcher task join failed: {}", err);
            }
        }
        Ok(())
    }
}

async fn run_watcher(
    paths: Vec<PathBuf>,
    config: FilesystemConfig,
    mut shutdown_rx: watch::Receiver<bool>,
    monitor_tx: mpsc::UnboundedSender<FilesystemMonitorEvent>,
) -> Result<()> {
    let (notify_tx, mut notify_rx) = mpsc::unbounded_channel();

    let mut watcher = RecommendedWatcher::new(
        move |res| {
            if notify_tx.send(res).is_err() {
                warn!("Filesystem watcher receiver dropped; stopping callbacks");
            }
        },
        NotifyConfig::default(),
    )
    .context("failed to initialize filesystem watcher")?;

    for path in &paths {
        watcher
            .watch(path, RecursiveMode::Recursive)
            .with_context(|| format!("failed to watch {}", path.display()))?;
        info!("Watching {} for changes", path.display());
    }

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                info!("Filesystem watcher stopping");
                break;
            }
            Some(event) = notify_rx.recv() => match event {
                Ok(event) => handle_event(&config, &event, &monitor_tx),
                Err(err) => warn!("Filesystem watcher error: {}", err),
            }
        }
    }

    drop(watcher);
    Ok(())
}

fn handle_event(
    config: &FilesystemConfig,
    event: &Event,
    monitor_tx: &mpsc::UnboundedSender<FilesystemMonitorEvent>,
) {
    if !config.scan_hidden {
        if event.paths.iter().any(|path| {
            path.file_name()
                .map(|n| n.to_string_lossy().starts_with('.'))
                .unwrap_or(false)
        }) {
            return;
        }
    }

    let event_kind = map_event_kind(&event.kind);

    for path in &event.paths {
        info!("Filesystem {:?}: {}", event_kind, path.display());

        let monitor_event = FilesystemMonitorEvent {
            path: path.clone(),
            kind: event_kind,
        };

        if monitor_tx.send(monitor_event).is_err() {
            warn!("Filesystem monitor channel closed; stopping event emission");
            break;
        }
    }
}

fn map_event_kind(kind: &EventKind) -> FilesystemEventKind {
    match kind {
        EventKind::Create(_) => FilesystemEventKind::Created,
        EventKind::Modify(modify_kind) => match modify_kind {
            ModifyKind::Data(_) | ModifyKind::Metadata(_) | ModifyKind::Any => {
                FilesystemEventKind::Modified
            }
            _ => FilesystemEventKind::Other,
        },
        EventKind::Remove(_) => FilesystemEventKind::Removed,
        EventKind::Access(_) => FilesystemEventKind::Accessed,
        _ => FilesystemEventKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn start_and_stop_watcher() {
        let config = FilesystemConfig::default();
        let watcher = FilesystemWatcher::new(&config).await.unwrap();
        let dir = tempdir().unwrap();
        let (tx, _rx) = mpsc::unbounded_channel();
        watcher
            .start_monitoring(vec![dir.path().to_path_buf()], tx)
            .await
            .unwrap();
        watcher.stop_monitoring().await.unwrap();
    }
}
