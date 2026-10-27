//! On-disk state: small JSON files, written atomically and durably (BR-951):
//! a temp file is written and fsynced, renamed over the record, and the
//! directory is fsynced, so after a crash or a power cut a record is either
//! the old one or the new one, never empty or half written. A guardian must
//! never sign a sequence twice with different bodies, so what it signed is on
//! disk before its cursor moves past it.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};

use crate::sources::Cursor;

#[derive(Clone)]
pub struct Store {
    root: PathBuf,
}

/// fsync a directory, so the renames into it survive a power cut.
fn sync_dir(dir: &Path) -> Result<()> {
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("syncing directory {}", dir.display()))
}

impl Store {
    pub fn open(root: &Path) -> Result<Store> {
        std::fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
        Ok(Store {
            root: root.to_path_buf(),
        })
    }

    fn path(&self, parts: &[&str]) -> PathBuf {
        parts.iter().fold(self.root.clone(), |p, part| p.join(part))
    }

    pub fn read<T: DeserializeOwned>(&self, parts: &[&str]) -> Result<Option<T>> {
        let path = self.path(parts);
        match std::fs::read(&path) {
            Ok(bytes) if bytes.is_empty() => Err(anyhow::anyhow!(
                "{} is empty (a write cut short before records were synced?)",
                path.display()
            )),
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes)
                    .with_context(|| format!("parsing {}", path.display()))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn write<T: Serialize>(&self, parts: &[&str], value: &T) -> Result<()> {
        let path = self.path(parts);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let tmp = path.with_extension("tmp");
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&tmp)
                .with_context(|| format!("creating {}", tmp.display()))?;
            file.write_all(&serde_json::to_vec_pretty(value)?)
                .with_context(|| format!("writing {}", tmp.display()))?;
            file.sync_all()
                .with_context(|| format!("syncing {}", tmp.display()))?;
        }
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("renaming into {}", path.display()))?;
        if let Some(dir) = path.parent() {
            // The rename is durable once the directory entry is; a directory
            // just created needs its own entry in its parent synced too.
            sync_dir(dir)?;
            if let Some(up) = dir.parent().filter(|up| up.starts_with(&self.root)) {
                sync_dir(up)?;
            }
        }
        Ok(())
    }

    pub fn cursor(&self, source: &str) -> Result<Option<Cursor>> {
        self.read(&["cursors", &format!("{source}.json")])
    }

    pub fn set_cursor(&self, source: &str, cursor: &Cursor) -> Result<()> {
        self.write(&["cursors", &format!("{source}.json")], cursor)
    }

    /// The file a message lives in: `<kind>/<chain>/<sequence>.json`.
    pub fn message_parts(kind: &str, chain: u16, sequence: u64) -> [String; 3] {
        [
            kind.to_string(),
            chain.to_string(),
            format!("{sequence:020}.json"),
        ]
    }

    pub fn read_message<T: DeserializeOwned>(
        &self,
        kind: &str,
        chain: u16,
        sequence: u64,
    ) -> Result<Option<T>> {
        let parts = Self::message_parts(kind, chain, sequence);
        self.read(&[&parts[0], &parts[1], &parts[2]])
    }

    pub fn write_message<T: Serialize>(
        &self,
        kind: &str,
        chain: u16,
        sequence: u64,
        value: &T,
    ) -> Result<()> {
        let parts = Self::message_parts(kind, chain, sequence);
        self.write(&[&parts[0], &parts[1], &parts[2]], value)
    }

    /// Every sequence stored under `<kind>/<chain>`, ascending.
    pub fn sequences(&self, kind: &str, chain: u16) -> Result<Vec<u64>> {
        let dir = self.path(&[kind, &chain.to_string()]);
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e).with_context(|| format!("listing {}", dir.display())),
        };
        for entry in entries {
            let name = entry?.file_name();
            if let Some(seq) = name
                .to_str()
                .and_then(|n| n.strip_suffix(".json"))
                .and_then(|n| n.parse().ok())
            {
                out.push(seq);
            }
        }
        out.sort_unstable();
        Ok(out)
    }
}
