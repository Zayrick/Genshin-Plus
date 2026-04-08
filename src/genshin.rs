use crate::cli::Cli;
use crate::pattern::Signature;
use crate::pe;
use crate::shellcode;
use crate::win;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::PROCESS_INFORMATION;
use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, MessageBoxA};

pub fn run(cli: &Cli) -> Result<(), String> {
    let exe_path = find_game_exe()?;

    if let Some(pid) = win::get_pid_by_name("yuanshen.exe")? {
        return Err(format!(
            "yuanshen.exe is already running (pid={pid}). Please close the game first."
        ));
    }

    let pi = win::create_process_suspended(&exe_path, &cli.game_args)?;
    let mut proc = ProcessGuard::new(pi);

    // If no FPS and no touch, just launch the game normally without injection
    if cli.fps.is_none() && !cli.touch {
        win::resume_thread(proc.pi.hThread)?;
        proc.disarm();
        return Ok(());
    }

    if let Some(fps) = cli.fps {
        unsafe {
            FPS_VALUE = fps;
        }
    }

    let is_old_version = std::fs::metadata(&exe_path)
        .map_err(|e| format!("read yuanshen.exe metadata failed: {e}"))?
        .len()
        < 0x800000;

    let game_dir = exe_path
        .parent()
        .ok_or_else(|| "exe has no parent directory".to_string())?;

    let exe_base = win::get_process_image_base(proc.pi.hProcess)?;

    let mut tar_mod_base = exe_base;
    if is_old_version {
        let unity_path = game_dir.join("UnityPlayer.dll");
        if !unity_path.is_file() {
            return Err(format!(
                "old version detected but UnityPlayer.dll not found: {}",
                unity_path.display()
            ));
        }
        tar_mod_base = remote_dll_inject(proc.pi.hProcess, &unity_path)?;
    }

    let (text_remote_addr, text_size) = read_section(proc.pi.hProcess, tar_mod_base, ".text")?;
    let text_copy = read_remote(proc.pi.hProcess, text_remote_addr, text_size)?;

    let p_unity_wndclass = scan_p_unity_wndclass(&text_copy, text_remote_addr).unwrap_or(0);
    let payloadoep = scan_payloadoep(&text_copy, text_remote_addr)?;
    let ptr_fps = if cli.fps.is_some() {
        Some(scan_fps_ptr(&text_copy, text_remote_addr)?)
    } else {
        None
    };

    // il2cpp section
    let mut il2cpp_mod_base = tar_mod_base;
    if is_old_version {
        let ua_path = game_dir
            .join("YuanShen_Data")
            .join("Native")
            .join("UserAssembly.dll");
        if !ua_path.is_file() {
            return Err(format!("UserAssembly.dll not found: {}", ua_path.display()));
        }
        il2cpp_mod_base = remote_dll_inject(proc.pi.hProcess, &ua_path)?;
    }

    let (il2cpp_remote_addr, il2cpp_size) =
        read_section(proc.pi.hProcess, il2cpp_mod_base, "il2cpp")?;
    let il2cpp_copy = read_remote(proc.pi.hProcess, il2cpp_remote_addr, il2cpp_size)?;

    let verfiy = scan_verfiy(&il2cpp_copy, il2cpp_remote_addr)?;

    let custom_dpi_scale = if cli.touch { 5.0 } else { 0.0 };
    let func_list = if cli.touch {
        Some(scan_mobile_ui(
            &il2cpp_copy,
            il2cpp_remote_addr,
            custom_dpi_scale,
        )?)
    } else {
        None
    };

    inject_patch(
        proc.pi.hProcess,
        tar_mod_base,
        ptr_fps,
        InjectArgs {
            verfiy,
            p_unity_wndclass,
            payloadoep,
            func_list,
        },
        custom_dpi_scale,
    )?;

    win::resume_thread(proc.pi.hThread)?;
    proc.disarm();

    std::thread::sleep(Duration::from_millis(2000));
    Ok(())
}

fn find_game_exe() -> Result<PathBuf, String> {
    let cwd = std::env::current_dir().map_err(|e| format!("get current_dir failed: {e}"))?;
    let exe_path = cwd.join("yuanshen.exe");
    if !exe_path.is_file() {
        return Err(format!(
            "`yuanshen.exe` not found in current directory: {}",
            cwd.display()
        ));
    }
    Ok(exe_path)
}

static mut FPS_VALUE: u32 = 120;

struct ProcessGuard {
    pi: PROCESS_INFORMATION,
    terminate_on_drop: bool,
}

impl ProcessGuard {
    fn new(pi: PROCESS_INFORMATION) -> Self {
        Self {
            pi,
            terminate_on_drop: true,
        }
    }

    fn disarm(&mut self) {
        self.terminate_on_drop = false;
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if self.terminate_on_drop {
            win::terminate_process(self.pi.hProcess);
        }
        win::close_handle(self.pi.hThread);
        win::close_handle(self.pi.hProcess);
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct HookFuncList {
    ui_unhook_time: u64,
    func_gui_set: u64,
    func_input_set: u64,
    grph_class: u64,
    grph_uicl_va: u32,
    grph_inputcl_va: u32,
    func_get_dpi: u64,
}

#[derive(Debug, Clone, Copy)]
struct InjectArgs {
    verfiy: u64,
    p_unity_wndclass: u64,
    payloadoep: u64,
    func_list: Option<HookFuncList>,
}

fn read_section(process: HANDLE, image_base: u64, name: &str) -> Result<(u64, usize), String> {
    let header = read_remote(process, image_base, 0x1000)?;
    let info = pe::find_section(image_base, &header, name)?
        .ok_or_else(|| format!("failed to locate PE section: {name}"))?;
    Ok((info.remote_addr, info.size))
}

fn read_remote(process: HANDLE, address: u64, size: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; size];
    win::read_process_memory(process, address, &mut buf)?;
    Ok(buf)
}

fn remote_dll_inject(process: HANDLE, dll_path: &Path) -> Result<u64, String> {
    let dll_w = win::to_wide_null(dll_path.as_os_str());
    let mut dll_bytes = Vec::<u8>::with_capacity(dll_w.len() * 2);
    for w in dll_w {
        dll_bytes.extend_from_slice(&w.to_le_bytes());
    }

    let alloc_size = 0x2000usize + dll_bytes.len().max(0x1000);
    let remote = win::virtual_alloc_ex(process, alloc_size, win::page_readwrite())?;

    let mut payload = [0u8; 0x20];
    write_u64(&mut payload, 0x00, 0xB848C03138EC8348);
    write_u64(&mut payload, 0x08, win::load_library_addr());
    write_u64(&mut payload, 0x10, 0x0FE605894890D0FF);
    write_u64(&mut payload, 0x18, 0xCCC338C483480000);

    let result = (|| -> Result<u64, String> {
        win::write_process_memory(process, remote, &payload)?;
        win::write_process_memory(process, remote + 0x1000, &dll_bytes)?;
        win::virtual_protect_ex(process, remote, 0x1000, win::page_execute_read())?;

        let thread = win::create_remote_thread(process, remote, remote + 0x1000)?;
        let _ =
            unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(thread, 60000) };

        let mut out = [0u8; 8];
        win::read_process_memory(process, remote + 0x1000, &mut out)?;
        win::close_handle(thread);

        let module = u64::from_le_bytes(out);
        if module == 0 {
            return Err(format!(
                "LoadLibraryW returned NULL for {}",
                dll_path.display()
            ));
        }
        Ok(module)
    })();

    win::virtual_free_ex(process, remote);
    result
}

fn scan_p_unity_wndclass(text: &[u8], remote_base: u64) -> Result<u64, String> {
    let sig = Signature::parse(
        "C7 44 24 28 00 00 00 80 C7 44 24 20 00 00 00 80 FF 15 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 85 C0",
    )?;
    let off = sig
        .scan(text)
        .ok_or_else(|| "failed to locate UnityWndclass pattern".to_string())?;

    let rip = off + 0x19;
    let rel = read_i32_le(text, rip)?;
    let target_off = (rip as i64 + rel as i64 + 4) as u64;
    Ok(remote_base + target_off)
}

fn scan_payloadoep(text: &[u8], remote_base: u64) -> Result<u64, String> {
    let sig = Signature::parse("48 83 EC 28 FF D1 31 C0 48 83 C4 28 C3")?;
    if let Some(off) = sig.scan(text) {
        return Ok(remote_base + off as u64);
    }

    let sig = Signature::parse("FF E1")?;
    let matches = sig.scan_all(text, 1024);
    if matches.is_empty() {
        return Ok(0);
    }
    let idx = pick_rdrand_index(matches.len()).unwrap_or(0);
    Ok(remote_base + matches[idx] as u64)
}

fn pick_rdrand_index(modulus: usize) -> Option<usize> {
    if modulus == 0 {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut out = 0u64;
        if std::arch::x86_64::_rdrand64_step(&mut out) == 1 {
            return Some((out as usize) % modulus);
        }
    }
    None
}

fn scan_fps_ptr(text: &[u8], remote_base: u64) -> Result<u64, String> {
    // 5.5
    let sig = Signature::parse("66 0F 6E 0D ?? ?? ?? ?? 0F 57 C0 0F 5B C9")?;
    if let Some(off) = sig.scan(text) {
        return Ok(remote_base + (off + 4) as u64);
    }
    // 5.4
    let sig = Signature::parse("7E 0C E8 ?? ?? ?? ?? 66 0F 6E C8 0F 5B C9")?;
    if let Some(off) = sig.scan(text) {
        let rip = off + 3;
        let rel = read_i32_le(text, rip)?;
        let target_off = (rip as i64 + rel as i64 + 6) as u64;
        return Ok(remote_base + target_off);
    }
    // 3.7 - 5.3
    let sig = Signature::parse("7F 0E E8 ?? ?? ?? ?? 66 0F 6E C8")?;
    if let Some(off) = sig.scan(text) {
        let rip = off + 3;
        let rel = read_i32_le(text, rip)?;
        let target_off = (rip as i64 + rel as i64 + 6) as u64;
        return Ok(remote_base + target_off);
    }
    // old
    let sig = Signature::parse("7F 0F 8B 05 ?? ?? ?? ?? 66 0F 6E C8")?;
    if let Some(off) = sig.scan(text) {
        return Ok(remote_base + (off + 4) as u64);
    }

    Err("failed to locate FPS pattern (outdated?)".to_string())
}

fn scan_verfiy(il2cpp: &[u8], remote_base: u64) -> Result<u64, String> {
    let sig = Signature::parse(
        "E8 ?? ?? ?? ?? EB 0D 48 89 F1 BA 02 00 00 00 E8 ?? ?? ?? ?? 48 89 F1 31 D2",
    )?;
    if let Some(off) = sig.scan(il2cpp) {
        return call_target(remote_base, il2cpp, off);
    }
    let sig =
        Signature::parse("E8 ?? ?? ?? ?? EB 0D 48 89 F1 BA 02 00 00 00 E8 ?? ?? ?? ?? 48 8B 0D")?;
    if let Some(off) = sig.scan(il2cpp) {
        return call_target(remote_base, il2cpp, off);
    }
    Err("failed to locate GI verfiy pattern".to_string())
}

fn call_target(remote_base: u64, buf: &[u8], call_off: usize) -> Result<u64, String> {
    let rel_off = call_off + 1;
    let rel = read_i32_le(buf, rel_off)?;
    let target_off = (rel_off as i64 + rel as i64 + 4) as u64;
    Ok(remote_base + target_off)
}

fn scan_mobile_ui(
    il2cpp: &[u8],
    remote_base: u64,
    custom_dpi_scale: f32,
) -> Result<HookFuncList, String> {
    let mut out = HookFuncList::default();

    // New pattern (v2.9.4+): calls now have an extra r8 argument
    let sig_new = Signature::parse(
        "48 8B 05 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? ?? 48 85 C9 0F ?? ?? ?? ?? ?? BA 02 00 00 00 41 B0 01 E8 ?? ?? ?? ?? 48 89 F9 BA 03 00 00 00 45 31 C0 E8",
    )?;
    // Old pattern (fallback)
    let sig_old = Signature::parse(
        "48 8B 05 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? ?? 48 85 C9 0F ?? ?? ?? ?? ?? BA 02 00 00 00 E8 ?? ?? ?? ?? 48 89 F9 BA 03 00 00 00 E8",
    )?;
    if let Some(off) = sig_new.scan(il2cpp) {
        out.grph_class = rip_target(remote_base, il2cpp, off + 0x3)?;
        out.grph_uicl_va = read_u32_le(il2cpp, off + 0xA)?;
        out.func_gui_set = call_target_at(remote_base, il2cpp, off + 0x20)?;
        out.func_input_set = call_target_at(remote_base, il2cpp, off + 0x30)?;
    } else if let Some(off) = sig_old.scan(il2cpp) {
        out.grph_class = rip_target(remote_base, il2cpp, off + 0x3)?;
        out.grph_uicl_va = read_u32_le(il2cpp, off + 0xA)?;
        out.func_gui_set = call_target_at(remote_base, il2cpp, off + 0x1D)?;
        out.func_input_set = call_target_at(remote_base, il2cpp, off + 0x2A)?;
    } else {
        return Err("failed to locate mobile UI pattern (GI)".to_string());
    }

    let sig = Signature::parse(
        "48 8B 05 ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 48 8B B8 ?? ?? ?? ?? 48 85 FF 0F 84 ?? ?? ?? ?? 83 BF ?? ?? ?? ?? 03",
    )?;
    let off = sig
        .scan(il2cpp)
        .ok_or_else(|| "failed to locate input UI class pattern (GI)".to_string())?;
    out.grph_inputcl_va = read_u32_le(il2cpp, off + 0x10)?;

    if custom_dpi_scale != 0.0 {
        let sig = Signature::parse("0F 14 F8 E8 ?? ?? ?? ?? 0F 14 F0 0F 59 F7")?;
        let off = sig
            .scan(il2cpp)
            .ok_or_else(|| "failed to locate DPI pattern (GI)".to_string())?;
        out.func_get_dpi = call_target_at(remote_base, il2cpp, off + 0x4)?;
    }

    let sig = Signature::parse(
        "E8 ?? ?? ?? ?? 48 89 D9 E8 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 0F 85 ?? ?? ?? ?? 48 8B 0D",
    )?;
    let off = sig
        .scan(il2cpp)
        .ok_or_else(|| "failed to locate UI unhook pattern (GI)".to_string())?;
    out.ui_unhook_time = call_target_at(remote_base, il2cpp, off + 0x9)?;

    Ok(out)
}

fn rip_target(remote_base: u64, buf: &[u8], disp_off: usize) -> Result<u64, String> {
    let rel = read_i32_le(buf, disp_off)?;
    let target_off = (disp_off as i64 + rel as i64 + 4) as u64;
    Ok(remote_base + target_off)
}

fn call_target_at(remote_base: u64, buf: &[u8], rel_off: usize) -> Result<u64, String> {
    let rel = read_i32_le(buf, rel_off)?;
    let target_off = (rel_off as i64 + rel as i64 + 4) as u64;
    Ok(remote_base + target_off)
}

fn read_i32_le(buf: &[u8], off: usize) -> Result<i32, String> {
    let bytes = buf
        .get(off..off + 4)
        .ok_or_else(|| "read_i32_le out of range".to_string())?;
    Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u32_le(buf: &[u8], off: usize) -> Result<u32, String> {
    let bytes = buf
        .get(off..off + 4)
        .ok_or_else(|| "read_u32_le out of range".to_string())?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn inject_patch(
    process: HANDLE,
    tar_mod_base: u64,
    ptr_fps: Option<u64>,
    args: InjectArgs,
    custom_dpi_scale: f32,
) -> Result<u64, String> {
    let mut sc = shellcode::new_shellcode_buffer()?;

    // Common patches
    if ptr_fps.is_some() {
        write_u32(&mut sc, 0x00, std::process::id());
        write_u64(&mut sc, 0x08, std::ptr::addr_of!(FPS_VALUE) as usize as u64);
    } else {
        // No FPS injection: set host_pid=0 so shellcode trampoline exits immediately
        write_u32(&mut sc, 0x00, 0);
    }
    write_u64(&mut sc, 0x80, MessageBoxA as *const () as usize as u64);
    write_u64(
        &mut sc,
        0x88,
        windows_sys::Win32::Foundation::CloseHandle as *const () as usize as u64,
    );
    write_u64(
        &mut sc,
        0x90,
        GetForegroundWindow as *const () as usize as u64,
    );

    // AutoExit=1: disable shellcode error msg popups (matches reference behavior).
    sc[0x18A..0x18C].copy_from_slice(&0x3AEBu16.to_le_bytes());

    let remote_payload = win::virtual_alloc_ex(process, 0x4000, win::page_readwrite())?;
    let mut hook_info_ptr = 0x2000usize;

    // PowerSaveSet (optional, only useful for FPS mode)
    if ptr_fps.is_some() && args.p_unity_wndclass != 0 {
        write_u64(
            &mut sc,
            0x30,
            remote_payload + shellcode::POWERSAVESET_FUNC_VA,
        );
        write_u64(
            &mut sc,
            (shellcode::POWERSAVESET_FUNC_VA as usize) + 0x10,
            args.p_unity_wndclass,
        );
        write_u32(
            &mut sc,
            (shellcode::POWERSAVESET_FUNC_VA as usize) + 0x1C,
            10,
        );
    } else {
        write_u64(
            &mut sc,
            shellcode::POWERSAVESET_FUNC_VA as usize,
            0x00000000CCC3C889,
        );
    }

    // Verify hook (required)
    write_u64(&mut sc, 0x20, remote_payload + 0x2000);
    write_u64(&mut sc, 0x28, args.verfiy);
    {
        let mut org = [0u8; 16];
        win::read_process_memory(process, args.verfiy, &mut org)?;
        sc[0x60..0x70].copy_from_slice(&org);
        let hook = make_abs_jmp(remote_payload + shellcode::GI_HOOKED_VFUNC_VA);
        sc[0x70..0x80].copy_from_slice(&hook);
        win::write_process_memory_protected(process, args.verfiy, &hook)?;
    }

    // Base FPS hook info (only when FPS injection is requested)
    if let Some(fps_ptr) = ptr_fps {
        let private_buffer = alloc_private_buffer(process, tar_mod_base)?;
        write_u64(&mut sc, 0x18, private_buffer);

        let alienaddr = fps_ptr & 0xFFFFFFFFFFFFFFF8;
        let mut orgpart = [0u8; 16];
        win::read_process_memory(process, alienaddr, &mut orgpart)?;
        let mut hookedpart = orgpart;
        let mask = (fps_ptr & 0x7) as usize;
        if mask + 4 > hookedpart.len() {
            return Err("fps patch mask out of range".to_string());
        }
        let immva = ((private_buffer as i64 - fps_ptr as i64) - 4) as i32;
        hookedpart[mask..mask + 4].copy_from_slice(&immva.to_le_bytes());

        write_u64(&mut sc, hook_info_ptr, alienaddr);
        write_u64(&mut sc, hook_info_ptr + 0x08, 0);
        sc[hook_info_ptr + 0x10..hook_info_ptr + 0x20].copy_from_slice(&hookedpart);
        sc[hook_info_ptr + 0x20..hook_info_ptr + 0x30].copy_from_slice(&orgpart);
        hook_info_ptr += 0x30;
    }

    // Touch + DPI injection (optional)
    if let Some(list) = args.func_list {
        // UI unhook hook
        write_u64(&mut sc, 0x40, list.ui_unhook_time);
        write_u64(&mut sc, 0x48, remote_payload + 0x3000);

        // Copy 0x20 bytes starting from Func_gui_set into payload+0x3000
        write_u64(&mut sc, 0x3000, list.func_gui_set);
        write_u64(&mut sc, 0x3008, list.func_input_set);
        write_u64(&mut sc, 0x3010, list.grph_class);
        write_u32(&mut sc, 0x3018, list.grph_uicl_va);
        write_u32(&mut sc, 0x301C, list.grph_inputcl_va);

        let mut org = [0u8; 16];
        win::read_process_memory(process, list.ui_unhook_time, &mut org)?;
        sc[0x50..0x60].copy_from_slice(&org);
        let hook = make_abs_jmp(remote_payload + shellcode::GI_UNHOOKED_UI_FVA);
        win::write_process_memory_protected(process, list.ui_unhook_time, &hook)?;

        if custom_dpi_scale != 0.0 && list.func_get_dpi != 0 {
            // Patch DPI function to return Custom_DPI_Scale * 96
            let mut patch = [
                0xB8u8, 0x60, 0x00, 0x00, 0x00, 0x66, 0x0F, 0x6E, 0xC0, 0x0F, 0x5B, 0xC0, 0xC3,
                0xCC, 0xCC, 0xCC,
            ];
            let dpiscale_n = (custom_dpi_scale * 96.0) as u32;
            patch[1..5].copy_from_slice(&dpiscale_n.to_le_bytes());

            let mut org = [0u8; 16];
            win::read_process_memory(process, list.func_get_dpi, &mut org)?;
            win::write_process_memory_protected(process, list.func_get_dpi, &patch)?;

            write_u64(&mut sc, hook_info_ptr, list.func_get_dpi);
            write_u64(&mut sc, hook_info_ptr + 0x08, 0);
            sc[hook_info_ptr + 0x10..hook_info_ptr + 0x20].copy_from_slice(&patch);
            sc[hook_info_ptr + 0x20..hook_info_ptr + 0x30].copy_from_slice(&org);
        }
    }

    // Write payload + start thread
    let result = (|| -> Result<u64, String> {
        win::write_process_memory(process, remote_payload, &sc)?;
        win::virtual_protect_ex(
            process,
            remote_payload,
            0x4000,
            win::page_execute_readwrite(),
        )?;

        let (start, param) = if args.payloadoep != 0 {
            (
                args.payloadoep,
                remote_payload + shellcode::SHELLCODE_ENTRY_VA,
            )
        } else {
            (remote_payload + shellcode::SHELLCODE_ENTRY_VA, 0)
        };
        let thread = win::create_remote_thread(process, start, param)?;

        let _ = unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(thread, 1000) };
        let ecode = win::get_exit_code_thread(thread)? as i32;
        if ecode < 0 {
            win::close_handle(thread);
            return Err(format!(
                "injected thread returned error: 0x{:08X}",
                ecode as u32
            ));
        }
        win::close_handle(thread);
        Ok(remote_payload)
    })();

    if result.is_err() {
        win::virtual_free_ex(process, remote_payload);
    }
    result
}

fn alloc_private_buffer(process: HANDLE, tar_mod_base: u64) -> Result<u64, String> {
    let mut offset = 0x10000u64;
    while offset < 0x7FFF8000 {
        if let Some(target) = tar_mod_base.checked_sub(offset) {
            if let Some(addr) =
                win::virtual_alloc_ex_at(process, target, 0x1000, win::page_readwrite())?
            {
                return Ok(addr);
            }
        } else {
            break;
        }
        offset += 0x1000;
    }
    Err("failed to allocate private buffer near module base".to_string())
}

fn make_abs_jmp(dst: u64) -> [u8; 16] {
    let mut buf = [0u8; 16];
    write_u64(&mut buf, 0x0, 0x225FF);
    write_u64(&mut buf, 0x8, dst);
    buf
}

fn write_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_u64(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}
