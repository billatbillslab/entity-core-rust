//! Atomic-write SHOULD per DOMAIN-LOCAL-FILES v1.3 §4.3 / §5.3.
//!
//! Pattern: sibling temp file in the same directory → fsync(file) →
//! close → rename → **fsync(parent_dir)** on POSIX. On POSIX `rename(2)`
//! within the same directory is atomic for the namespace mutation, but
//! the directory-entry update lives in the page cache until the parent
//! inode is flushed. Without the parent fsync, a power loss within the
//! kernel writeback window can drop the rename even though the temp
//! file is durable (see v1.3 spec §4.3 + LWN Articles/457667/).
//!
//! ext4 with `data=ordered` makes a partial implicit ordering guarantee
//! for rename-over-existing-file (closes the post-2009 zero-length-file
//! fiasco) — but only for that subcase, and only on ext4. xfs/btrfs/zfs
//! make no such guarantee. The parent fsync is portable.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Write `data` to `target` via sibling-temp + fsync + rename + parent fsync.
pub fn atomic_write(target: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = target.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "target has no parent")
    })?;
    let basename = target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("tmp");

    // Pick a unique sibling name; uniqueness is best-effort via pid+counter.
    // Collisions retry once.
    let mut tmp_path = dir.join(format!(".{basename}.{}.tmp", random_suffix()));
    let file_result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path);
    let mut file = match file_result {
        Ok(f) => f,
        Err(_) => {
            tmp_path = dir.join(format!(".{basename}.{}.tmp", random_suffix()));
            OpenOptions::new().write(true).create_new(true).open(&tmp_path)?
        }
    };

    let write_result = (|| -> std::io::Result<()> {
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        drop(file);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    drop(file);

    if let Err(e) = std::fs::rename(&tmp_path, target) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    // POSIX: fsync the parent directory so the rename's directory-entry
    // update is durable, not merely queued. Windows MoveFileEx provides
    // equivalent semantics without this step — `File::open(dir).sync_all`
    // on Windows is a no-op for directories (handled by the OS), so this
    // is portable to call uniformly. Best-effort: a failure to open the
    // parent is logged-via-error-return but does not invalidate the
    // already-successful rename.
    fsync_parent(dir)?;
    Ok(())
}

#[cfg(unix)]
fn fsync_parent(dir: &Path) -> std::io::Result<()> {
    let f = File::open(dir)?;
    f.sync_all()
}

#[cfg(not(unix))]
fn fsync_parent(_dir: &Path) -> std::io::Result<()> {
    // Windows: MoveFileEx (under std::fs::rename on Windows) handles
    // directory-entry durability without an explicit parent fsync step.
    // Other targets (WASI etc.): conservative no-op.
    Ok(())
}

/// Streaming atomic write — for payloads that don't fit comfortably in
/// memory. `fill` is a closure that writes the content into the temp
/// file (called once). The atomic + fsync + rename + parent-fsync
/// sequence is identical to `atomic_write`; only the body-write phase
/// differs (closure vs &[u8]).
///
/// Used by the L4 streaming reverse-write path and content-mode write
/// for blobs above the 64 MiB threshold.
pub fn atomic_write_stream<F>(target: &Path, fill: F) -> std::io::Result<()>
where
    F: FnOnce(&mut std::fs::File) -> std::io::Result<()>,
{
    let dir = target.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "target has no parent")
    })?;
    let basename = target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("tmp");

    let mut tmp_path = dir.join(format!(".{basename}.{}.tmp", random_suffix()));
    let file_result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path);
    let mut file = match file_result {
        Ok(f) => f,
        Err(_) => {
            tmp_path = dir.join(format!(".{basename}.{}.tmp", random_suffix()));
            OpenOptions::new().write(true).create_new(true).open(&tmp_path)?
        }
    };

    let write_result = (|| -> std::io::Result<()> {
        fill(&mut file)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        drop(file);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    drop(file);

    if let Err(e) = std::fs::rename(&tmp_path, target) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    fsync_parent(dir)?;
    Ok(())
}

fn random_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // Mix in pid to reduce collision risk across processes.
    nanos ^ (std::process::id() as u64)
}

