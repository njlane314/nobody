use anyhow::Result;
use serde_json::{Value, json};
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Trace {
    file: File,
}

impl Trace {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            create_dir_all(parent)?;
        }

        let file = OpenOptions::new().create(true).append(true).open(path)?;

        Ok(Self { file })
    }

    pub fn event(&mut self, kind: &str, data: Value) -> Result<()> {
        let ts_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();

        let line = json!({
            "ts_ms": ts_ms,
            "kind": kind,
            "data": data,
        });

        serde_json::to_writer(&mut self.file, &line)?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;

        Ok(())
    }
}
