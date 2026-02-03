#[derive(Debug, Clone, Copy)]
pub struct SectionInfo {
    pub remote_addr: u64,
    pub size: usize,
}

pub fn find_section(
    image_base: u64,
    header: &[u8],
    name: &str,
) -> Result<Option<SectionInfo>, String> {
    if header.len() < 0x100 {
        return Err("PE header buffer too small".to_string());
    }
    if header.get(0..2) != Some(b"MZ") {
        return Err("invalid DOS header (missing MZ)".to_string());
    }
    let e_lfanew = read_u32_le(header, 0x3C)? as usize;
    if e_lfanew + 4 + 20 > header.len() {
        return Err("invalid PE header (e_lfanew out of range)".to_string());
    }
    if &header[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err("invalid NT header (missing PE signature)".to_string());
    }

    let number_of_sections = read_u16_le(header, e_lfanew + 6)? as usize;
    let size_of_optional_header = read_u16_le(header, e_lfanew + 20)? as usize;
    let section_table = e_lfanew + 4 + 20 + size_of_optional_header;
    let section_size = 40usize;

    for i in 0..number_of_sections {
        let off = section_table + i * section_size;
        if off + section_size > header.len() {
            break;
        }
        let raw_name = &header[off..off + 8];
        let end = raw_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(raw_name.len());
        let sec_name = std::str::from_utf8(&raw_name[..end]).unwrap_or("");
        if sec_name == name {
            let virtual_size = read_u32_le(header, off + 8)? as usize;
            let virtual_address = read_u32_le(header, off + 12)? as u64;
            return Ok(Some(SectionInfo {
                remote_addr: image_base + virtual_address,
                size: virtual_size,
            }));
        }
    }
    Ok(None)
}

fn read_u16_le(buf: &[u8], off: usize) -> Result<u16, String> {
    let bytes = buf
        .get(off..off + 2)
        .ok_or_else(|| "read_u16_le out of range".to_string())?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(buf: &[u8], off: usize) -> Result<u32, String> {
    let bytes = buf
        .get(off..off + 4)
        .ok_or_else(|| "read_u32_le out of range".to_string())?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
