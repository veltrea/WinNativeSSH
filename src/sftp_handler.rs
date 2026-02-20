use crate::vss::{Snapshot, VssManager};
use log::{error, info};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode,
};
use russh_sftp::server::Handler;
use std::collections::HashMap;
use std::fs::Metadata;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::{self, File as TokioFile};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

#[derive(Debug)]
pub struct SftpError(pub StatusCode);

impl From<StatusCode> for SftpError {
    fn from(code: StatusCode) -> Self {
        Self(code)
    }
}

impl From<SftpError> for StatusCode {
    fn from(err: SftpError) -> StatusCode {
        err.0
    }
}

pub struct SftpHandler {
    state: Arc<Mutex<SftpState>>,
}

struct SftpState {
    root: PathBuf,
    handles: HashMap<u32, FileHandle>,
    next_handle: u32,
    snapshots_cache: Option<(Instant, Vec<Snapshot>)>,
}

enum FileHandle {
    File(TokioFile),
    Dir { entries: Vec<File>, index: usize },
}

impl SftpState {
    fn ensure_snapshots(&mut self) {
        let now = Instant::now();
        let should_refresh = match &self.snapshots_cache {
            Some((ts, _)) => now.duration_since(*ts) > Duration::from_secs(60),
            None => true,
        };

        if should_refresh {
            if let Ok(snaps) = VssManager::list_snapshots() {
                self.snapshots_cache = Some((now, snaps));
            } else if self.snapshots_cache.is_none() {
                self.snapshots_cache = Some((now, Vec::new()));
            }
        }
    }
}

impl SftpHandler {
    pub fn new(root: PathBuf) -> Self {
        Self {
            state: Arc::new(Mutex::new(SftpState {
                root,
                handles: HashMap::new(),
                next_handle: 1,
                snapshots_cache: None,
            })),
        }
    }

    fn is_path_allowed(path: &str) -> bool {
        let clean = path.replace('\\', "/");
        if clean.contains('\0') {
            return false;
        }
        if clean.starts_with("//") {
            return false;
        }
        for part in clean.split('/') {
            if part.is_empty() || part == "." {
                continue;
            }
            if part == ".." {
                return false;
            }
            if part.contains(':') {
                return false;
            }
        }
        true
    }

    fn resolve(root: &Path, path: &str, snapshots: Option<&[Snapshot]>) -> Option<PathBuf> {
        // VSS integration
        let clean_path = path.replace('\\', "/");
        if !Self::is_path_allowed(&clean_path) {
            return None;
        }
        if clean_path == "/.snapshots" || clean_path == "/.snapshots/" {
            // Virtual root, but we return a path that likely doesn't exist on disk.
            // We handle this in opendir/lstat specifically.
            // But for resolve, we just return the join usually.
            // However, to prevent "C:\.snapshots" access, we might want to be careful.
            return Some(root.join(".snapshots")); // Start with dummy
        }

        if clean_path.starts_with("/.snapshots/") {
            // /.snapshots/<ID>/...
            let parts: Vec<&str> = clean_path.splitn(4, '/').collect();
            if parts.len() >= 3 {
                let snap_id = parts[2];
                if let Some(snaps) = snapshots {
                    if let Some(snap) = snaps.iter().find(|s| s.id == snap_id) {
                        let volume = &snap.volume_path;
                        let mut p = PathBuf::from(volume);
                        if parts.len() > 3 {
                            p.push(parts[3].replace('/', "\\"));
                        }
                        return Some(p);
                    }
                }
            }
        }

        let mut full = root.to_path_buf();
        let trimmed = path.trim_start_matches('/').trim_start_matches('\\');
        if !trimmed.is_empty() {
            // Convert / to \ for Windows
            let win_path = trimmed.replace('/', "\\");
            full.push(win_path);
        }
        Some(full)
    }

    fn map_attributes(metadata: &Metadata) -> FileAttributes {
        // Basic mapping
        let mut mode = 0;
        if metadata.is_dir() {
            mode |= 0o40000; // S_IFDIR
            mode |= 0o755; // rwxr-xr-x
        } else {
            mode |= 0o100000; // S_IFREG
            mode |= 0o644; // rw-r--r--
        }

        #[cfg(windows)]
        {
            let win_attrs = metadata.file_attributes();
            if win_attrs & 0x1 != 0 {
                // FILE_ATTRIBUTE_READONLY
                mode &= !0o222;
            }
        }

        FileAttributes {
            size: Some(metadata.len()),
            permissions: Some(mode),
            ..Default::default()
        }
    }
}

impl Handler for SftpHandler {
    type Error = SftpError;

    fn unimplemented(&self) -> Self::Error {
        SftpError(StatusCode::OpUnsupported)
    }

    fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> impl Future<Output = Result<Handle, Self::Error>> + Send {
        let state = self.state.clone();
        async move {
            let mut state = state.lock().await;
            state.ensure_snapshots();
            let snaps = state.snapshots_cache.as_ref().map(|x| x.1.as_slice());
            let full_path = Self::resolve(&state.root, &filename, snaps)
                .ok_or(SftpError(StatusCode::PermissionDenied))?;
            info!("SFTP Open: {:?}", full_path);

            let mut options = fs::OpenOptions::new();
            if pflags.contains(OpenFlags::READ) {
                options.read(true);
            }
            if pflags.contains(OpenFlags::WRITE) {
                options.write(true);
            }
            if pflags.contains(OpenFlags::APPEND) {
                options.append(true);
            }
            if pflags.contains(OpenFlags::CREATE) {
                options.create(true);
            }
            if pflags.contains(OpenFlags::TRUNCATE) {
                options.truncate(true);
            }
            if pflags.contains(OpenFlags::EXCLUDE) {
                options.create_new(true);
            }

            match options.open(&full_path).await {
                Ok(file) => {
                    let h_id = state.next_handle;
                    state.next_handle += 1;
                    state.handles.insert(h_id, FileHandle::File(file));
                    Ok(Handle {
                        id,
                        handle: h_id.to_string(),
                    })
                }
                Err(e) => {
                    error!("SFTP Open error: {:?}", e);
                    Err(SftpError(StatusCode::NoSuchFile))
                }
            }
        }
    }

    fn close(
        &mut self,
        id: u32,
        handle: String,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let state = self.state.clone();
        async move {
            let mut state = state.lock().await;
            if let Ok(h) = handle.parse::<u32>() {
                if state.handles.remove(&h).is_some() {
                    return Ok(Status {
                        id,
                        status_code: StatusCode::Ok,
                        error_message: "".to_string(),
                        language_tag: "en-US".to_string(),
                    });
                }
            }
            Err(SftpError(StatusCode::Failure))
        }
    }

    fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> impl Future<Output = Result<Data, Self::Error>> + Send {
        let state = self.state.clone();
        async move {
            let mut state = state.lock().await;
            if let Ok(h) = handle.parse::<u32>() {
                if let Some(FileHandle::File(ref mut file)) = state.handles.get_mut(&h) {
                    if file.seek(std::io::SeekFrom::Start(offset)).await.is_err() {
                        return Err(SftpError(StatusCode::Failure));
                    }
                    let mut buf = vec![0; len as usize];
                    match file.read(&mut buf).await {
                        Ok(n) => {
                            buf.truncate(n);
                            if n == 0 && len > 0 {
                                return Err(SftpError(StatusCode::Eof));
                            }
                            return Ok(Data { id, data: buf });
                        }
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                return Err(SftpError(StatusCode::Eof));
                            }
                            return Err(SftpError(StatusCode::Failure));
                        }
                    }
                }
            }
            Err(SftpError(StatusCode::Failure))
        }
    }

    fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let state = self.state.clone();
        async move {
            let mut state = state.lock().await;
            if let Ok(h) = handle.parse::<u32>() {
                if let Some(FileHandle::File(ref mut file)) = state.handles.get_mut(&h) {
                    if file.seek(std::io::SeekFrom::Start(offset)).await.is_err() {
                        return Err(SftpError(StatusCode::Failure));
                    }
                    match file.write_all(&data).await {
                        Ok(_) => {
                            return Ok(Status {
                                id,
                                status_code: StatusCode::Ok,
                                error_message: "".to_string(),
                                language_tag: "en-US".to_string(),
                            })
                        }
                        Err(_) => return Err(SftpError(StatusCode::Failure)),
                    }
                }
            }
            Err(SftpError(StatusCode::Failure))
        }
    }

    fn opendir(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Handle, Self::Error>> + Send {
        let state = self.state.clone();
        async move {
            let mut state = state.lock().await;

            // Check for .snapshots
            let clean_path = path.replace('\\', "/");
            if clean_path == "/.snapshots" || clean_path == "/.snapshots/" {
                state.ensure_snapshots();
                let mut entries = Vec::new();
                if let Some((_, snaps)) = &state.snapshots_cache {
                    for snap in snaps {
                        let name = snap.id.clone();
                        let attrs = FileAttributes {
                            permissions: Some(0o40755),
                            ..Default::default()
                        };
                        entries.push(File::new(name, attrs));
                    }
                }
                let h_id = state.next_handle;
                state.next_handle += 1;
                state
                    .handles
                    .insert(h_id, FileHandle::Dir { entries, index: 0 });
                return Ok(Handle {
                    id,
                    handle: h_id.to_string(),
                });
            }

            state.ensure_snapshots();
            let snaps = state.snapshots_cache.as_ref().map(|x| x.1.as_slice());
            let full_path = Self::resolve(&state.root, &path, snaps)
                .ok_or(SftpError(StatusCode::PermissionDenied))?;
            match fs::read_dir(&full_path).await {
                Ok(mut rd) => {
                    let mut entries = Vec::new();
                    while let Ok(Some(entry)) = rd.next_entry().await {
                        let filename = entry.file_name().to_string_lossy().into_owned();
                        if let Ok(metadata) = entry.metadata().await {
                            entries.push(File::new(filename, Self::map_attributes(&metadata)));
                        }
                    }
                    let h_id = state.next_handle;
                    state.next_handle += 1;
                    state
                        .handles
                        .insert(h_id, FileHandle::Dir { entries, index: 0 });
                    Ok(Handle {
                        id,
                        handle: h_id.to_string(),
                    })
                }
                Err(_) => Err(SftpError(StatusCode::NoSuchFile)),
            }
        }
    }

    fn readdir(
        &mut self,
        id: u32,
        handle: String,
    ) -> impl Future<Output = Result<Name, Self::Error>> + Send {
        let state = self.state.clone();
        async move {
            let mut state = state.lock().await;
            if let Ok(h) = handle.parse::<u32>() {
                if let Some(FileHandle::Dir { entries, index, .. }) = state.handles.get_mut(&h) {
                    if *index >= entries.len() {
                        return Err(SftpError(StatusCode::Eof));
                    }
                    let chunk = entries[*index..].to_vec();
                    *index = entries.len();
                    return Ok(Name { id, files: chunk });
                }
            }
            Err(SftpError(StatusCode::Failure))
        }
    }

    fn lstat(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Attrs, Self::Error>> + Send {
        let state = self.state.clone();
        async move {
            let mut state = state.lock().await;

            let clean_path = path.replace('\\', "/");
            if clean_path == "/.snapshots" || clean_path == "/.snapshots/" {
                let attrs = FileAttributes {
                    permissions: Some(0o40755),
                    ..Default::default()
                };
                return Ok(Attrs { id, attrs });
            }

            state.ensure_snapshots();
            let snaps = state.snapshots_cache.as_ref().map(|x| x.1.as_slice());
            let full_path = Self::resolve(&state.root, &path, snaps)
                .ok_or(SftpError(StatusCode::PermissionDenied))?;
            match fs::metadata(full_path).await {
                Ok(meta) => Ok(Attrs {
                    id,
                    attrs: Self::map_attributes(&meta),
                }),
                Err(_) => Err(SftpError(StatusCode::NoSuchFile)),
            }
        }
    }

    fn stat(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Attrs, Self::Error>> + Send {
        self.lstat(id, path)
    }

    fn realpath(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Name, Self::Error>> + Send {
        let state = self.state.clone();
        async move {
            let mut state = state.lock().await;
            state.ensure_snapshots();
            let snaps = state.snapshots_cache.as_ref().map(|x| x.1.as_slice());
            let full_path = Self::resolve(&state.root, &path, snaps)
                .ok_or(SftpError(StatusCode::PermissionDenied))?;
            Ok(Name {
                id,
                files: vec![File::dummy(full_path.to_string_lossy().into_owned())],
            })
        }
    }

    fn remove(
        &mut self,
        id: u32,
        filename: String,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let state = self.state.clone();
        async move {
            let mut state = state.lock().await;
            state.ensure_snapshots();
            let snaps = state.snapshots_cache.as_ref().map(|x| x.1.as_slice());
            let full_path = Self::resolve(&state.root, &filename, snaps)
                .ok_or(SftpError(StatusCode::PermissionDenied))?;
            match fs::remove_file(full_path).await {
                Ok(_) => Ok(Status {
                    id,
                    status_code: StatusCode::Ok,
                    error_message: "".to_string(),
                    language_tag: "en-US".to_string(),
                }),
                Err(_) => Err(SftpError(StatusCode::Failure)),
            }
        }
    }

    fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let state = self.state.clone();
        async move {
            let mut state = state.lock().await;
            state.ensure_snapshots();
            let snaps = state.snapshots_cache.as_ref().map(|x| x.1.as_slice());
            let full_path = Self::resolve(&state.root, &path, snaps)
                .ok_or(SftpError(StatusCode::PermissionDenied))?;
            match fs::create_dir(full_path).await {
                Ok(_) => Ok(Status {
                    id,
                    status_code: StatusCode::Ok,
                    error_message: "".to_string(),
                    language_tag: "en-US".to_string(),
                }),
                Err(_) => Err(SftpError(StatusCode::Failure)),
            }
        }
    }

    fn rmdir(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let state = self.state.clone();
        async move {
            let mut state = state.lock().await;
            state.ensure_snapshots();
            let snaps = state.snapshots_cache.as_ref().map(|x| x.1.as_slice());
            let full_path = Self::resolve(&state.root, &path, snaps)
                .ok_or(SftpError(StatusCode::PermissionDenied))?;
            match fs::remove_dir(full_path).await {
                Ok(_) => Ok(Status {
                    id,
                    status_code: StatusCode::Ok,
                    error_message: "".to_string(),
                    language_tag: "en-US".to_string(),
                }),
                Err(_) => Err(SftpError(StatusCode::Failure)),
            }
        }
    }

    fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let state = self.state.clone();
        async move {
            let mut state = state.lock().await;
            state.ensure_snapshots();
            let snaps = state.snapshots_cache.as_ref().map(|x| x.1.as_slice());
            let old_full = Self::resolve(&state.root, &oldpath, snaps)
                .ok_or(SftpError(StatusCode::PermissionDenied))?;
            let new_full = Self::resolve(&state.root, &newpath, snaps)
                .ok_or(SftpError(StatusCode::PermissionDenied))?;
            match fs::rename(old_full, new_full).await {
                Ok(_) => Ok(Status {
                    id,
                    status_code: StatusCode::Ok,
                    error_message: "".to_string(),
                    language_tag: "en-US".to_string(),
                }),
                Err(_) => Err(SftpError(StatusCode::Failure)),
            }
        }
    }
}
