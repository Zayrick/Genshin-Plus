#![cfg(windows)]

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, PROCESSENTRY32W,
    Process32FirstW, Process32NextW, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx, VirtualProtectEx,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, CreateRemoteThread, GetExitCodeThread, PROCESS_INFORMATION,
    ResumeThread, STARTUPINFOW, TerminateProcess,
};

pub fn to_wide_null(s: &OsStr) -> Vec<u16> {
    let mut wide: Vec<u16> = s.encode_wide().collect();
    wide.push(0);
    wide
}

fn io_err(context: &str) -> String {
    format!("{context}: {}", io::Error::last_os_error())
}

pub fn close_handle(handle: HANDLE) {
    if !handle.is_null() {
        unsafe {
            CloseHandle(handle);
        }
    }
}

pub fn get_pid_by_name(process_name: &str) -> Result<Option<u32>, String> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io_err(
            "CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) failed",
        ));
    }
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut ok = unsafe { Process32FirstW(snapshot, &mut entry) };
    while ok != 0 {
        let exe = widestr_to_osstring(&entry.szExeFile);
        if exe.to_string_lossy().eq_ignore_ascii_case(process_name) {
            let pid = entry.th32ProcessID;
            close_handle(snapshot);
            return Ok(Some(pid));
        }
        ok = unsafe { Process32NextW(snapshot, &mut entry) };
    }
    close_handle(snapshot);
    Ok(None)
}

pub fn get_module_base(pid: u32, module_name: &str) -> Result<Option<u64>, String> {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io_err("CreateToolhelp32Snapshot(TH32CS_SNAPMODULE) failed"));
    }

    let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
    let mut ok = unsafe { Module32FirstW(snapshot, &mut entry) };
    while ok != 0 {
        let name = widestr_to_osstring(&entry.szModule);
        if name.to_string_lossy().eq_ignore_ascii_case(module_name) {
            let base = entry.modBaseAddr as usize as u64;
            close_handle(snapshot);
            return Ok(Some(base));
        }
        ok = unsafe { Module32NextW(snapshot, &mut entry) };
    }
    close_handle(snapshot);
    Ok(None)
}

pub fn get_process_image_base(process: HANDLE) -> Result<u64, String> {
    let mut pbi: windows_sys::Win32::System::Threading::PROCESS_BASIC_INFORMATION =
        unsafe { std::mem::zeroed() };
    let mut ret_len = 0u32;
    let status = unsafe {
        NtQueryInformationProcess(
            process,
            ProcessBasicInformation,
            std::ptr::addr_of_mut!(pbi) as *mut _,
            std::mem::size_of::<windows_sys::Win32::System::Threading::PROCESS_BASIC_INFORMATION>()
                as u32,
            &mut ret_len,
        )
    };
    if status != 0 {
        return Err(format!(
            "NtQueryInformationProcess(ProcessBasicInformation) failed: NTSTATUS=0x{:08X}",
            status as u32
        ));
    }

    let peb = pbi.PebBaseAddress as usize as u64;
    if peb == 0 {
        return Err("PEB base address is null".to_string());
    }

    let mut out = [0u8; 8];
    read_process_memory(process, peb + 0x10, &mut out)?;
    Ok(u64::from_le_bytes(out))
}

pub fn create_process_suspended(
    exe_path: &Path,
    args: &[OsString],
) -> Result<PROCESS_INFORMATION, String> {
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let exe_w = to_wide_null(exe_path.as_os_str());

    let mut cmdline_w: Option<Vec<u16>> = None;
    let cmdline_ptr = if args.is_empty() {
        std::ptr::null_mut()
    } else {
        let cmd = build_windows_cmdline(args);
        let mut v: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
        let ptr = v.as_mut_ptr();
        cmdline_w = Some(v);
        ptr
    };

    let cur_dir = exe_path
        .parent()
        .ok_or_else(|| "exe has no parent directory".to_string())?;
    let cur_dir_w = to_wide_null(cur_dir.as_os_str());

    let ok = unsafe {
        CreateProcessW(
            exe_w.as_ptr(),
            cmdline_ptr,
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_SUSPENDED,
            std::ptr::null(),
            cur_dir_w.as_ptr(),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(io_err("CreateProcessW failed"));
    }
    drop(cmdline_w);
    Ok(pi)
}

pub fn resume_thread(thread: HANDLE) -> Result<(), String> {
    let rc = unsafe { ResumeThread(thread) };
    if rc == u32::MAX {
        return Err(io_err("ResumeThread failed"));
    }
    Ok(())
}

pub fn terminate_process(process: HANDLE) {
    unsafe {
        TerminateProcess(process, 0);
    }
}

pub fn read_process_memory(process: HANDLE, address: u64, buf: &mut [u8]) -> Result<(), String> {
    let mut read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            address as usize as *const _,
            buf.as_mut_ptr() as *mut _,
            buf.len(),
            &mut read,
        )
    };
    if ok == 0 {
        return Err(io_err("ReadProcessMemory failed"));
    }
    if read != buf.len() {
        return Err(format!(
            "ReadProcessMemory short read: {read} / {} bytes",
            buf.len()
        ));
    }
    Ok(())
}

pub fn write_process_memory(process: HANDLE, address: u64, buf: &[u8]) -> Result<(), String> {
    let mut written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            process,
            address as usize as *mut _,
            buf.as_ptr() as *const _,
            buf.len(),
            &mut written,
        )
    };
    if ok == 0 {
        return Err(io_err("WriteProcessMemory failed"));
    }
    if written != buf.len() {
        return Err(format!(
            "WriteProcessMemory short write: {written} / {} bytes",
            buf.len()
        ));
    }
    Ok(())
}

pub fn write_process_memory_protected(
    process: HANDLE,
    address: u64,
    buf: &[u8],
) -> Result<(), String> {
    if let Ok(()) = write_process_memory(process, address, buf) {
        return Ok(());
    }

    let page_start = address & !0xFFF;
    let page_end = (address + buf.len() as u64 + 0xFFF) & !0xFFF;
    let size = (page_end - page_start) as usize;

    let old = virtual_protect_ex_get_old(process, page_start, size, PAGE_EXECUTE_READWRITE)?;
    let result = write_process_memory(process, address, buf);
    let _ = virtual_protect_ex_get_old(process, page_start, size, old);
    result
}

pub fn virtual_alloc_ex(process: HANDLE, size: usize, protect: u32) -> Result<u64, String> {
    let addr = unsafe {
        VirtualAllocEx(
            process,
            std::ptr::null_mut(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            protect,
        )
    };
    if addr.is_null() {
        return Err(io_err("VirtualAllocEx failed"));
    }
    Ok(addr as usize as u64)
}

pub fn virtual_alloc_ex_at(
    process: HANDLE,
    address: u64,
    size: usize,
    protect: u32,
) -> Result<Option<u64>, String> {
    let addr = unsafe {
        VirtualAllocEx(
            process,
            address as usize as *mut _,
            size,
            MEM_COMMIT | MEM_RESERVE,
            protect,
        )
    };
    if addr.is_null() {
        return Ok(None);
    }
    Ok(Some(addr as usize as u64))
}

pub fn virtual_free_ex(process: HANDLE, address: u64) {
    unsafe {
        VirtualFreeEx(process, address as usize as *mut _, 0, MEM_RELEASE);
    }
}

pub fn virtual_protect_ex(
    process: HANDLE,
    address: u64,
    size: usize,
    protect: u32,
) -> Result<(), String> {
    let mut old = 0u32;
    let ok =
        unsafe { VirtualProtectEx(process, address as usize as *mut _, size, protect, &mut old) };
    if ok == 0 {
        return Err(io_err("VirtualProtectEx failed"));
    }
    Ok(())
}

fn virtual_protect_ex_get_old(
    process: HANDLE,
    address: u64,
    size: usize,
    protect: u32,
) -> Result<u32, String> {
    let mut old = 0u32;
    let ok =
        unsafe { VirtualProtectEx(process, address as usize as *mut _, size, protect, &mut old) };
    if ok == 0 {
        return Err(io_err("VirtualProtectEx failed"));
    }
    Ok(old)
}

pub fn create_remote_thread(process: HANDLE, start: u64, param: u64) -> Result<HANDLE, String> {
    let h = unsafe {
        CreateRemoteThread(
            process,
            std::ptr::null(),
            0,
            Some(std::mem::transmute::<
                u64,
                unsafe extern "system" fn(*mut core::ffi::c_void) -> u32,
            >(start)),
            param as usize as *const _,
            0,
            std::ptr::null_mut(),
        )
    };
    if h.is_null() {
        return Err(io_err("CreateRemoteThread failed"));
    }
    Ok(h)
}

pub fn get_exit_code_thread(thread: HANDLE) -> Result<u32, String> {
    let mut code = 0u32;
    let ok = unsafe { GetExitCodeThread(thread, &mut code) };
    if ok == 0 {
        return Err(io_err("GetExitCodeThread failed"));
    }
    Ok(code)
}

pub fn load_library_addr() -> u64 {
    LoadLibraryW as *const () as usize as u64
}

pub fn page_execute_read() -> u32 {
    PAGE_EXECUTE_READ
}

pub fn page_execute_readwrite() -> u32 {
    PAGE_EXECUTE_READWRITE
}

pub fn page_readwrite() -> u32 {
    PAGE_READWRITE
}

fn widestr_to_osstring(buf: &[u16]) -> OsString {
    let mut len = 0usize;
    while len < buf.len() && buf[len] != 0 {
        len += 1;
    }
    OsString::from_wide(&buf[..len])
}

fn build_windows_cmdline(args: &[OsString]) -> String {
    args.iter()
        .map(|a| quote_windows_arg(&a.to_string_lossy()))
        .collect::<Vec<String>>()
        .join(" ")
}

fn quote_windows_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    let needs_quotes = arg
        .bytes()
        .any(|b| b == b' ' || b == b'\t' || b == b'\n' || b == b'"');
    if !needs_quotes {
        return arg.to_string();
    }

    let mut out = String::new();
    out.push('"');

    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => {
                backslashes += 1;
            }
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                if backslashes > 0 {
                    out.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                }
                out.push(ch);
            }
        }
    }

    if backslashes > 0 {
        out.push_str(&"\\".repeat(backslashes * 2));
    }

    out.push('"');
    out
}
