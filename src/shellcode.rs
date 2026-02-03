use std::sync::OnceLock;

pub const SHELLCODE_ENTRY_VA: u64 = 0x1D0;
pub const GI_UNHOOKED_UI_FVA: u64 = 0x240;
pub const GI_HOOKED_VFUNC_VA: u64 = 0x2D0;
pub const POWERSAVESET_FUNC_VA: u64 = 0x560;

const SHELLCODE_HEADER_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/reference/Genshin_StarRail_fps_unlocker/src/shellcode_header.h"
));

static SHELLCODE_CONST: OnceLock<Vec<u8>> = OnceLock::new();

pub fn new_shellcode_buffer() -> Result<Vec<u8>, String> {
    let sc = shellcode_const()?;
    let mut buf = vec![0u8; 0x4000];
    if sc.len() > buf.len() {
        return Err(format!("shellcode too large: {} > {}", sc.len(), buf.len()));
    }
    buf[..sc.len()].copy_from_slice(sc);
    Ok(buf)
}

pub fn shellcode_const() -> Result<&'static [u8], String> {
    if let Some(v) = SHELLCODE_CONST.get() {
        return Ok(v.as_slice());
    }
    let parsed = parse_shellcode_from_header()?;
    let _ = SHELLCODE_CONST.set(parsed);
    Ok(SHELLCODE_CONST
        .get()
        .ok_or_else(|| "failed to initialize shellcode buffer".to_string())?
        .as_slice())
}

fn parse_shellcode_from_header() -> Result<Vec<u8>, String> {
    if SHELLCODE_HEADER_BYTES.len() < 2 {
        return Err("shellcode_header.h is empty".to_string());
    }

    // The reference file is UTF-16BE with BOM (0xFE 0xFF).
    let bytes = SHELLCODE_HEADER_BYTES;
    let mut u16s = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0usize;
    if bytes[0] == 0xFE && bytes[1] == 0xFF {
        i = 2;
    }
    while i + 1 < bytes.len() {
        u16s.push(u16::from_be_bytes([bytes[i], bytes[i + 1]]));
        i += 2;
    }
    let text = String::from_utf16(&u16s)
        .map_err(|_| "invalid UTF-16 in shellcode_header.h".to_string())?;

    let marker = "const DECLSPEC_ALIGN(32) uint8_t _shellcode_Const[]";
    let start = text
        .find(marker)
        .ok_or_else(|| "failed to locate _shellcode_Const in shellcode_header.h".to_string())?;
    let brace_open = text[start..]
        .find('{')
        .ok_or_else(|| "failed to locate '{' for _shellcode_Const".to_string())?
        + start;
    let brace_close = text[brace_open..]
        .find("};")
        .ok_or_else(|| "failed to locate end of _shellcode_Const".to_string())?
        + brace_open;

    let body = &text[brace_open + 1..brace_close];

    let mut out = Vec::<u8>::new();
    for tok in body
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
    {
        let v = if let Some(hex) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
            u8::from_str_radix(hex, 16).map_err(|_| format!("invalid hex byte: {tok}"))?
        } else {
            let n: u32 = tok.parse().map_err(|_| format!("invalid byte: {tok}"))?;
            if n > 0xFF {
                return Err(format!("byte out of range: {tok}"));
            }
            n as u8
        };
        out.push(v);
    }

    if out.is_empty() {
        return Err("parsed _shellcode_Const is empty".to_string());
    }
    Ok(out)
}
