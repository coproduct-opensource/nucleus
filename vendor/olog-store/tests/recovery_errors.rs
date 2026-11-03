//! Regression tests for fallible reads and WAL recovery.
use std::error::Error;
type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[test]
fn segment_read_failure_never_becomes_an_old_or_partial_answer() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut store = olog_store::Store::open(dir.path())?;
    for value in [b"old", b"new"] {
        let mut batch = olog_store::Batch::new();
        batch.put(b"key", value);
        store.commit(batch)?;
        store.flush()?;
    }
    assert_eq!(store.try_get(b"key")?, Some(b"new".to_vec()));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.path().join("0000000001.seg"))?;
    file.set_len(0)?;
    assert!(store.try_get(b"key").is_err());
    assert!(store.try_contains(b"key").is_err());
    assert!(store.try_scan_prefix(b"k").is_err());
    Ok(())
}

#[test]
fn manifest_read_error_is_not_a_fresh_database() -> Result<()> {
    let dir = tempfile::tempdir()?;
    std::fs::create_dir(dir.path().join("MANIFEST"))?;
    assert!(olog_store::Store::open(dir.path()).is_err());
    let dir = tempfile::tempdir()?;
    std::fs::create_dir(dir.path().join("LOG"))?;
    assert!(olog_store::Store::open(dir.path()).is_err());
    Ok(())
}

#[test]
fn complete_wal_corruption_is_refused_without_repair() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut store = olog_store::Store::open(dir.path())?;
    let mut batch = olog_store::Batch::new();
    batch.put(b"key", b"value");
    store.commit(batch)?;
    drop(store);
    let path = dir.path().join("LOG");
    let mut bytes = std::fs::read(&path)?;
    bytes[4] ^= 1; // Complete record, damaged CRC, not an incomplete tail.
    std::fs::write(&path, &bytes)?;
    assert!(olog_store::Store::open(dir.path()).is_err());
    assert_eq!(
        std::fs::read(path)?,
        bytes,
        "corruption must not be silently truncated"
    );
    Ok(())
}

#[test]
fn append_after_torn_tail_survives_a_second_restart() -> Result<()> {
    use std::io::Write;
    let dir=tempfile::tempdir()?;
    let mut store=olog_store::Store::open(dir.path())?;
    let mut first=olog_store::Batch::new();
    first.put(b"first",b"committed");
    store.commit(first)?;
    drop(store);
    let mut log=std::fs::OpenOptions::new().append(true).open(dir.path().join("LOG"))?;
    log.write_all(&[0xff,0xff,0,0,0,0,0,0,1])?;
    log.sync_all()?;
    drop(log);
    let mut store=olog_store::Store::open(dir.path())?;
    assert_eq!(store.try_get(b"first")?,Some(b"committed".to_vec()));
    let mut second=olog_store::Batch::new();
    second.put(b"second",b"committed later");
    store.commit(second)?;
    drop(store);
    let store=olog_store::Store::open(dir.path())?;
    assert_eq!(store.try_get(b"first")?,Some(b"committed".to_vec()));
    assert_eq!(store.try_get(b"second")?,Some(b"committed later".to_vec()));
    Ok(())
}
