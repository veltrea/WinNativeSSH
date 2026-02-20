use crate::client_info::PreferredEncoding;
use anyhow::Result;
use log::info;

#[cfg(windows)]
use anyhow::anyhow;
#[cfg(windows)]
use log::error;
#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::io::FromRawHandle;
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(windows)]
use windows::Win32::System::Console::{ClosePseudoConsole, CreatePseudoConsole, HPCON};
#[cfg(windows)]
use windows::Win32::System::Pipes::CreatePipe;
#[cfg(windows)]
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
    UpdateProcThreadAttribute, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTUPINFOEXW,
};

pub struct WinShell {
    pub encoding: PreferredEncoding,
    #[cfg(windows)]
    pub h_pcon: Option<HPCON>,
    #[cfg(windows)]
    pub h_process: Option<HANDLE>,
    #[cfg(windows)]
    pub pipe_in_write: Option<HANDLE>,
    #[cfg(windows)]
    pub pipe_out_read: Option<HANDLE>,
}

impl WinShell {
    pub fn new(encoding: PreferredEncoding) -> Self {
        WinShell {
            encoding,
            #[cfg(windows)]
            h_pcon: None,
            #[cfg(windows)]
            h_process: None,
            #[cfg(windows)]
            pipe_in_write: None,
            #[cfg(windows)]
            pipe_out_read: None,
        }
    }

    #[cfg(windows)]
    pub fn get_pipes(&mut self) -> (Option<tokio::fs::File>, Option<tokio::fs::File>) {
        let f_in = self.pipe_in_write.take().map(|h| unsafe {
            tokio::fs::File::from_std(std::fs::File::from_raw_handle(h.0 as *mut _))
        });
        let f_out = self.pipe_out_read.take().map(|h| unsafe {
            tokio::fs::File::from_std(std::fs::File::from_raw_handle(h.0 as *mut _))
        });
        (f_in, f_out)
    }

    #[cfg(not(windows))]
    pub fn get_pipes(&mut self) -> (Option<tokio::fs::File>, Option<tokio::fs::File>) {
        (None, None)
    }

    #[cfg(windows)]
    pub fn spawn(&mut self, command: &str, cols: u16, rows: u16) -> Result<()> {
        info!("Spawning shell: {} ({}x{})", command, cols, rows);

        unsafe {
            let mut h_pipe_in_read = HANDLE::default();
            let mut h_pipe_in_write = HANDLE::default();
            let mut h_pipe_out_read = HANDLE::default();
            let mut h_pipe_out_write = HANDLE::default();
            let mut attr_list_buf: Vec<u8> = Vec::new();

            if let Err(e) = CreatePipe(&mut h_pipe_in_read, &mut h_pipe_in_write, None, 0) {
                return Err(anyhow!("CreatePipe(stdin) failed: {:?}", e));
            }
            if let Err(e) = CreatePipe(&mut h_pipe_out_read, &mut h_pipe_out_write, None, 0) {
                let _ = CloseHandle(h_pipe_in_read);
                let _ = CloseHandle(h_pipe_in_write);
                return Err(anyhow!("CreatePipe(stdout) failed: {:?}", e));
            }

            let pcon = match CreatePseudoConsole(
                windows::Win32::System::Console::COORD {
                    X: cols as i16,
                    Y: rows as i16,
                },
                h_pipe_in_read,
                h_pipe_out_write,
                0,
            ) {
                Ok(v) => v,
                Err(e) => {
                    let _ = CloseHandle(h_pipe_in_read);
                    let _ = CloseHandle(h_pipe_in_write);
                    let _ = CloseHandle(h_pipe_out_read);
                    let _ = CloseHandle(h_pipe_out_write);
                    return Err(anyhow!("CreatePseudoConsole failed: {:?}", e));
                }
            };

            // ConPTY has taken ownership of the read/write pipe ends.
            let _ = CloseHandle(h_pipe_in_read);
            let _ = CloseHandle(h_pipe_out_write);

            let mut si = STARTUPINFOEXW::default();
            si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;

            let mut attr_list_size: usize = 0;
            let _ = InitializeProcThreadAttributeList(
                LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
                1,
                0,
                &mut attr_list_size,
            );
            if attr_list_size == 0 {
                let _ = CloseHandle(h_pipe_in_write);
                let _ = CloseHandle(h_pipe_out_read);
                ClosePseudoConsole(pcon);
                return Err(anyhow!(
                    "InitializeProcThreadAttributeList did not return required buffer size"
                ));
            }
            attr_list_buf.resize(attr_list_size, 0);
            let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_list_buf.as_mut_ptr().cast());
            if let Err(e) = InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_list_size)
            {
                let _ = CloseHandle(h_pipe_in_write);
                let _ = CloseHandle(h_pipe_out_read);
                ClosePseudoConsole(pcon);
                return Err(anyhow!(
                    "InitializeProcThreadAttributeList(init) failed: {:?}",
                    e
                ));
            }
            if let Err(e) = UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                Some((&pcon as *const HPCON).cast()),
                std::mem::size_of::<HPCON>(),
                None,
                None,
            ) {
                DeleteProcThreadAttributeList(attr_list);
                let _ = CloseHandle(h_pipe_in_write);
                let _ = CloseHandle(h_pipe_out_read);
                ClosePseudoConsole(pcon);
                return Err(anyhow!("UpdateProcThreadAttribute failed: {:?}", e));
            }
            si.lpAttributeList = attr_list;

            let mut cmd_u16: Vec<u16> = OsStr::new(command)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let mut pi = PROCESS_INFORMATION::default();

            let res = CreateProcessW(
                None,
                windows::core::PWSTR(cmd_u16.as_mut_ptr()),
                None,
                None,
                false,
                EXTENDED_STARTUPINFO_PRESENT,
                None,
                None,
                &si.StartupInfo,
                &mut pi,
            );
            DeleteProcThreadAttributeList(attr_list);

            if res.is_ok() {
                self.h_pcon = Some(pcon);
                self.pipe_in_write = Some(h_pipe_in_write);
                self.pipe_out_read = Some(h_pipe_out_read);
                self.h_process = Some(pi.hProcess);
                let _ = CloseHandle(pi.hThread);
                info!("Shell process spawned, PID: {}", pi.dwProcessId);
                Ok(())
            } else {
                let err = windows::core::Error::from_win32();
                let _ = CloseHandle(h_pipe_in_write);
                let _ = CloseHandle(h_pipe_out_read);
                ClosePseudoConsole(pcon);
                error!("CreateProcessW failed: {:?}", err);
                Err(anyhow!("Failed to spawn shell process: {:?}", err))
            }
        }
    }

    #[cfg(not(windows))]
    pub fn spawn(&mut self, _command: &str, _cols: u16, _rows: u16) -> Result<()> {
        info!("Spawn stub called on non-Windows platform");
        Ok(())
    }

    pub fn transcode_to_client(&self, data: &[u8]) -> Vec<u8> {
        match self.encoding {
            PreferredEncoding::Cp932 => {
                let (cow, _encoding_used, _had_errors) =
                    encoding_rs::SHIFT_JIS.encode(std::str::from_utf8(data).unwrap_or(""));
                cow.into_owned()
            }
            _ => data.to_vec(),
        }
    }

    pub fn transcode_from_client(&self, data: &[u8]) -> Vec<u8> {
        match self.encoding {
            PreferredEncoding::Cp932 => {
                let (cow, _encoding_used, _had_errors) = encoding_rs::SHIFT_JIS.decode(data);
                cow.into_owned().into_bytes()
            }
            _ => data.to_vec(),
        }
    }
}

impl Drop for WinShell {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            if let Some(h) = self.h_pcon {
                ClosePseudoConsole(h);
            }
            if let Some(h) = self.h_process {
                let _ = CloseHandle(h);
            }
            if let Some(h) = self.pipe_in_write {
                let _ = CloseHandle(h);
            }
            if let Some(h) = self.pipe_out_read {
                let _ = CloseHandle(h);
            }
        }
    }
}
