"""
Disassemble the shellcode from shellcode.rs – linear sweep, full range.
Run: python disasm_shellcode.py > shellcode_disasm.asm
"""

import re, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# ── Read shellcode bytes ────────────────────────────────────────────
with open("src/shellcode.rs", "r", encoding="utf-8") as f:
    content = f.read()
blob_text = content.split("SHELLCODE_CONST")[1].split("];")[0]
SC = bytes(int(b, 16) for b in re.findall(r"0x([0-9A-Fa-f]{2})", blob_text))

CODE_START = 0x0A0
CODE_END   = len(SC)  # 0x1120

# ── Known labels ────────────────────────────────────────────────────
LABELS = {
    0x0A0: ("_shellcode_trampoline",   "Main entry trampoline – opens process handle, patches FPS, jumps to payload OEP"),
    0x130: ("_fps_sleep_logic",        "Read FPS target, call Sleep/GetForegroundWindow, decide delay"),
    0x190: ("_show_sync_failed_msgbox","Show 'Sync failed!' MessageBoxA error popup"),
    0x1D0: ("shellcode_entry",         "SHELLCODE_ENTRY_VA – primary entry point called via CreateRemoteThread"),
    0x220: ("_hksr_ui_set",            "HKSR_UISet_FuncVA (Star Rail specific)"),
    0x240: ("GI_UnHooked_UI_func",     "GI_UNHOOKED_UI_FVA – original UI function dispatcher (unhook path)"),
    0x2C0: ("_fps_cmov_write",         "Write final FPS value to target (nop'd cmova in latest)"),
    0x2D0: ("GI_hooked_Vfunc",        "GI_HOOKED_VFUNC_VA – hooked verify function, iterates hook table"),
    0x3F0: ("_VirtualAlloc_wrapper_RWX","NtAllocateVirtualMemory wrapper (PAGE_EXECUTE_READWRITE=0x40)"),
    0x400: ("_VirtualAlloc_wrapper_RW", "NtAllocateVirtualMemory wrapper (PAGE_READWRITE=0x20)"),
    0x410: ("_nt_alloc_impl",          "Shared NtAllocateVirtualMemory implementation"),
    0x450: ("_nt_create_thread",       "NtCreateThreadEx wrapper"),
    0x4B0: ("_nt_write_vmem",          "NtWriteVirtualMemory wrapper"),
    0x4F0: ("_nt_sleep",               "NtDelayExecution (Sleep) wrapper"),
    0x520: ("_nt_waitforsingle",       "NtWaitForSingleObject-like / check HWND"),
    0x560: ("PowerSaveSet_Func",       "POWERSAVESET_FUNC_VA – optional power-save WndClass setter"),
    0x5A0: ("_GetProcAddress_custom",  "Custom GetProcAddress – walk export table by name hash"),
    0x5C0: ("_resolve_pe_exports",     "PE export directory walker – resolve by ordinal / name"),
    0x720: ("_pe_loader_setup",        "PE loader prologue – walk PEB InLoadOrderModuleList"),
    0x900: ("_pe_mem_loader_entry",    "PE in-memory loader – resolve imports, relocations, call DllMain"),
}

# Build reverse label map for call annotation
label_by_addr = {a: n for a, (n, _) in LABELS.items()}

def r32(off): return struct.unpack_from("<I", SC, off)[0]
def r64(off): return struct.unpack_from("<Q", SC, off)[0]

# ── Print data header ───────────────────────────────────────────────
print("; " + "=" * 78)
print("; Shellcode disassembly – Genshin FPS Unlocker (linear sweep)")
print("; Total size: %d bytes (0x%X)" % (len(SC), len(SC)))
print("; " + "=" * 78)
print()
print("; ──── DATA HEADER (0x000 – 0x09F) ────")
print("; Patched at runtime by the injector (genshin.rs inject_patch)")
print()

data_fields = [
    (0x00, 4, "host_pid",            "Host process PID"),
    (0x04, 4, "magic",               "Magic: 0x688C9020"),
    (0x08, 8, "p_fps_value",         "Pointer to FPS_VALUE in host"),
    (0x10, 8, "reserved_10",         "Reserved"),
    (0x18, 8, "private_buffer",      "Private buffer near module base"),
    (0x20, 8, "hook_info_base",      "Hook info table (payload+0x2000)"),
    (0x28, 8, "verify_func_addr",    "Address of verify function to hook"),
    (0x30, 8, "powersave_func_ptr",  "PowerSaveSet function ptr (or 0)"),
    (0x38, 8, "reserved_38",         "Reserved"),
    (0x40, 8, "ui_unhook_time_addr", "UI unhook time func addr (touch mode)"),
    (0x48, 8, "ui_func_list_ptr",    "UI func list (payload+0x3000)"),
    (0x50, 16,"org_ui_unhook_bytes", "Original 16 bytes of ui_unhook_time"),
    (0x60, 16,"org_verify_bytes",    "Original 16 bytes of verify func"),
    (0x70, 16,"hooked_verify_jmp",   "Absolute jump patch for verify"),
    (0x80, 8, "p_MessageBoxA",       "Pointer to MessageBoxA"),
    (0x88, 8, "p_CloseHandle",       "Pointer to CloseHandle"),
    (0x90, 8, "p_GetForegroundWindow","Pointer to GetForegroundWindow"),
    (0x98, 8, "reserved_98",         "Reserved"),
]
for off, size, name, desc in data_fields:
    if size == 4:
        print("  ; 0x%03X [%2d] %-24s = 0x%08X  ; %s" % (off, size, name, r32(off), desc))
    elif size == 8:
        print("  ; 0x%03X [%2d] %-24s = 0x%016X  ; %s" % (off, size, name, r64(off), desc))
    else:
        hx = " ".join("%02X" % SC[off+i] for i in range(min(size,16)))
        print("  ; 0x%03X [%2d] %-24s = %s  ; %s" % (off, size, name, hx, desc))

print()

# ── Linear-sweep disassembly of entire code region ──────────────────
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

print("; " + "=" * 78)
print("; CODE SECTION (0x%03X – 0x%03X)" % (CODE_START, CODE_END))
print("; " + "=" * 78)

code = SC[CODE_START:CODE_END]
int3_run = 0  # track consecutive int3 for compression

for insn in md.disasm(code, CODE_START):
    addr = insn.address

    # ── Emit label if this address is known ──
    if addr in LABELS:
        name, comment = LABELS[addr]
        if int3_run:
            print("    ; ... (%d bytes int3 padding)" % int3_run)
            int3_run = 0
        print()
        print("; " + "─" * 78)
        print("; %s   (0x%03X)" % (name, addr))
        print("; %s" % comment)
        print("; " + "─" * 78)
        print("%s:" % name)

    # ── Compress int3 padding ──
    if insn.mnemonic == "int3":
        int3_run += 1
        continue
    if int3_run:
        print("    ; ... (%d bytes int3 padding)" % int3_run)
        int3_run = 0

    # ── Format instruction ──
    asm_text = "%s %s" % (insn.mnemonic, insn.op_str)
    hex_bytes = " ".join("%02X" % b for b in insn.bytes)
    annotation = ""

    # Annotate direct calls
    if insn.mnemonic == "call" and "0x" in insn.op_str:
        try:
            target = int(insn.op_str.replace("0x", ""), 16)
            if target in label_by_addr:
                annotation = "  ; -> %s" % label_by_addr[target]
        except:
            pass

    # Annotate jmp targets
    if insn.mnemonic in ("jmp", "je", "jne", "jb", "ja", "jbe", "jae", "jle", "jge", "jl", "jg", "js", "jns"):
        try:
            target = int(insn.op_str.replace("0x", ""), 16)
            if target in label_by_addr:
                annotation = "  ; -> %s" % label_by_addr[target]
        except:
            pass

    # Annotate syscall
    if insn.mnemonic == "syscall":
        annotation = "  ; NT syscall"

    print("    %-44s ; 0x%03X: %s%s" % (asm_text, addr, hex_bytes, annotation))

if int3_run:
    print("    ; ... (%d bytes int3 padding)" % int3_run)

print()
print("; " + "=" * 78)
print("; END OF SHELLCODE DISASSEMBLY")
print("; " + "=" * 78)
