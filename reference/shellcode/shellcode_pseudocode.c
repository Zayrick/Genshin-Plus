/*
 * ============================================================================
 *  shellcode_pseudocode.c
 *  Reverse-engineered C pseudocode of SHELLCODE_CONST (4384 bytes)
 *  from src/shellcode.rs — Genshin FPS Unlocker shellcode
 *
 *  This shellcode runs INSIDE the game process (injected via CreateRemoteThread).
 *  It reads the target FPS from the HOST process (injector) via NtReadVirtualMemory,
 *  and patches the game's internal FPS cap directly (since it's in-process).
 *
 *  Architecture: x86-64, Windows, uses direct NT syscalls (anti-hook)
 * ============================================================================
 *
 *  KEY DESIGN:
 *  - All API names are stored bitwise-NOT encrypted to evade static AV detection
 *  - NT syscall numbers are dynamically extracted from ntdll.dll at runtime
 *  - Custom syscall trampolines jump to random "syscall;ret" gadgets in ntdll
 *  - Pointers to the vtable are stored NOT-obfuscated (ptr = ~real_ptr)
 *  - Supports Wine/Proton: falls back to direct function calls if Wine is detected
 *  - The PE loader portion (_PE_MEM_LOADER[] in shellcode_header.h) is encrypted
 *    with a separate XOR/NOT scheme and decrypted at runtime
 *
 * ============================================================================
 */

#include <stdint.h>
#include <windows.h>
#include <winternl.h>  // for PEB, TEB structures

/* ═══════════════════════════════════════════════════════════════════════════
 *  DATA HEADER (0x000 – 0x09F)
 *  Patched by the Rust injector (genshin.rs inject_patch) before injection.
 *  All offsets are relative to the shellcode base address.
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    /* 0x00 */ uint32_t host_pid;           // Host (injector) process PID
    /* 0x04 */ uint32_t magic;              // 0x688C9020 (validation magic)
    /* 0x08 */ uint64_t p_fps_value;        // Ptr to FPS_VALUE in HOST process
    /* 0x10 */ uint64_t _reserved_10;
    /* 0x18 */ uint64_t private_buffer;     // Allocated near game module base
    /* 0x20 */ uint64_t hook_info_base;     // -> payload+0x2000 (HookEntry table)
    /* 0x28 */ uint64_t verify_func_addr;   // Game's verify function address
    /* 0x30 */ uint64_t powersave_func_ptr; // PowerSaveSet function (or 0)
    /* 0x38 */ uint64_t nt_vtable_ptr;      // [RUNTIME] NOT-obfuscated ptr to NtVtable
    /* 0x40 */ uint64_t ui_unhook_time;     // Game's UI unhook time function
    /* 0x48 */ uint64_t ui_func_list_ptr;   // -> payload+0x3000 (UIFuncList)
    /* 0x50 */ uint8_t  org_ui_unhook_bytes[16];  // Original 16 bytes of ui_unhook_time
    /* 0x60 */ uint8_t  org_verify_bytes[16];     // Original 16 bytes of verify function
    /* 0x70 */ uint8_t  hooked_verify_jmp[16];    // abs jmp patch → GI_hooked_Vfunc
    /* 0x80 */ void*    p_MessageBoxA;      // MessageBoxA from host
    /* 0x88 */ void*    p_CloseHandle;      // CloseHandle from host
    /* 0x90 */ void*    p_GetForegroundWindow; // GetForegroundWindow from host
    /* 0x98 */ uint64_t _reserved_98;
} ShellcodeHeader; // sizeof = 0xA0

/* Hook entry in the hook table at payload+0x2000 */
typedef struct {
    /* +0x00 */ uint64_t target_addr;       // Remote address to hook (0 = end sentinel)
    /* +0x08 */ uint64_t _reserved;
    /* +0x10 */ uint8_t  hooked_bytes[16];  // Bytes to write when hook is active
    /* +0x20 */ uint8_t  original_bytes[16];// Original bytes to restore when unhooking
} HookEntry; // sizeof = 0x30

/* UI function list at payload+0x3000 */
typedef struct {
    /* +0x00 */ uint64_t func_gui_set;      // GUI set function ptr
    /* +0x08 */ uint64_t func_input_set;    // Input set function ptr
    /* +0x10 */ uint64_t grph_class;        // Graphics class instance pointer
    /* +0x18 */ int32_t  grph_uicl_va;      // UI class vtable offset
    /* +0x1C */ int32_t  grph_inputcl_va;   // Input class vtable offset
} UIFuncList;

/* NT function vtable built at runtime by _pe_loader_setup */
typedef struct {
    /* +0x00 */ uint64_t _pad[6];
    /* +0x30 */ void*    NtReadVirtualMemory;        // Read from host process
    /* +0x38 */ void*    NtAllocateVirtualMemory;    // Allocate in-process
    /* +0x40 */ void*    NtFreeVirtualMemory;        // Free memory
    /* +0x48 */ void*    NtOpenProcess;              // Open process handle
    /* +0x50 */ void*    NtProtectVirtualMemory;     // Change page protection
    /* +0x58 */ uint64_t _pad2[2];
    /* +0x68 */ void*    NtDelayExecution;           // Sleep
} NtVtable;

/* For convenience: base address pointer */
#define BASE     ((ShellcodeHeader*)shellcode_base)
#define VTABLE() ({ void* p = (void*)BASE->nt_vtable_ptr; p = ~p; *(NtVtable**)p; })


/* ═══════════════════════════════════════════════════════════════════════════
 *  STRING DECRYPTION (0xF40)
 *  Each function name is stored as NOT-encrypted qwords. This function
 *  bitwise-NOTs `count` qwords in-place, then the caller writes a null
 *  terminator at the correct position.
 * ═══════════════════════════════════════════════════════════════════════════ */

// offset 0xF40
void decrypt_string(uint64_t* buf, uint8_t count) {
    for (int i = count - 1; i >= 0; i--)
        buf[i] = ~buf[i];
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SYSCALL NUMBER EXTRACTION (0xF70)
 *  Given a pointer to an NT function in ntdll, extract its syscall number.
 *  Handles hooked functions by searching nearby for unhooked stubs and
 *  interpolating the syscall number.
 *
 *  Typical ntdll stub:
 *    mov r10, rcx       ; 4C 8B D1
 *    mov eax, <number>  ; B8 xx xx xx xx
 *    ...
 *    syscall             ; 0F 05
 *    ret                 ; C3
 * ═══════════════════════════════════════════════════════════════════════════ */

// offset 0xF70
int extract_syscall_number(void* func_ptr, uint32_t* out_number) {
    if (!func_ptr)
        return 0;

    uint32_t first4 = *(uint32_t*)func_ptr;

    // Pattern: 4C 8B D1 B8 = "mov r10, rcx; mov eax, ..."
    if (first4 == 0xB8D18B4C) {
        *out_number = *(uint32_t*)((uint8_t*)func_ptr + 4);
        return 1;  // success
    }

    // If hooked (JMP rel32 / JMP [rip+disp] / MOV RAX,imm64): follow trampoline
    uint8_t* p = (uint8_t*)func_ptr;
    if (p[0] == 0xE9 || *(uint16_t*)p == 0x25FF || *(uint16_t*)p == 0xB848) {
        // Search surrounding functions for the pattern
        for (int dist = 1; dist <= 32; dist++) {
            // Check func_ptr - dist*16
            uint8_t* behind = p - dist * 16;
            if (*(uint32_t*)behind == 0xB8D18B4C) {
                uint32_t num = *(uint32_t*)(behind + 4);
                // Adjust: number = found_num + dist (or - dist)
                // Handles special case for "test" instruction at offset +8
                *out_number = num + dist;
                return 1;
            }
            // Check func_ptr + dist*16
            uint8_t* ahead = p + dist * 16;
            if (*(uint32_t*)ahead == 0xB8D18B4C) {
                *out_number = *(uint32_t*)(ahead + 4) - dist;
                return 1;
            }
        }
    }

    return 0xFFFFFFFF; // not found
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  PE LOADER SETUP (0x720 – 0xF23)
 *  a.k.a. _pe_loader_setup
 *
 *  1. Walk PEB → Ldr → InMemoryOrderModuleList to find ntdll.dll base
 *  2. Resolve 6 NT functions via custom GetProcAddress
 *  3. Extract syscall numbers (or save direct ptrs for Wine)
 *  4. Build obfuscated syscall trampolines in executable memory
 *  5. Store vtable pointer (NOT-obfuscated) at base+0x38
 * ═══════════════════════════════════════════════════════════════════════════ */

// offset 0x720 – called from shellcode_entry as: _pe_loader_setup(base+0x38, 0, base+0x38)
int32_t _pe_loader_setup(void* base_plus_38, uint32_t mode, STARTUPINFOW* si_out) {
    // ── Step 1: Find ntdll.dll base ──
    //   *(base+0x38) was set to 0x60 by caller → used as GS offset to PEB
    uint32_t gs_offset = *(uint32_t*)base_plus_38; // 0x60
    PEB* peb = (PEB*)__readgsqword(gs_offset);
    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* first = ldr->InMemoryOrderModuleList.Flink;
    LIST_ENTRY* second = first->Flink;

    void* ntdll_base = *(void**)((uint8_t*)second + 0x20); // DllBase of second module
    if (!ntdll_base) return 0xC0000135; // STATUS_DLL_NOT_FOUND

    void* third_base = *(void**)((uint8_t*)(second->Flink) + 0x20);
    if (!third_base) return 0xC0000135;

    // ── Step 2: Check if running under Wine/Proton ──
    int is_wine = 0;
    char wine_get_version_str[] = "wine_get_version"; // decrypted from NOT bytes
    void* wine_fn = GetProcAddress_custom(ntdll_base, wine_get_version_str);
    if (wine_fn) {
        is_wine = 1;
        void* heap = ((void*(*)())wine_fn)();
        // heap pointer saved for later use
    }

    // ── Step 3: Resolve NT functions and extract syscall numbers ──
    // Each name is stored as NOT-encrypted qwords, decrypted in-place.

    struct {
        const char* name;
        uint32_t    syscall_num; // extracted syscall number (non-Wine only)
        void*       func_ptr;   // raw ntdll function pointer (Wine only)
    } nt_funcs[] = {
        { "NtAllocateVirtualMemory", 0, NULL },  // [0]
        { "NtFreeVirtualMemory",     0, NULL },  // [1]
        { "NtReadVirtualMemory",     0, NULL },  // [2] - reads FPS from host
        { "NtProtectVirtualMemory",  0, NULL },  // [3]
        { "NtOpenProcess",           0, NULL },  // [4]
        { "NtDelayExecution",        0, NULL },  // [5]
    };

    for (int i = 0; i < 6; i++) {
        void* fn = GetProcAddress_custom(ntdll_base, nt_funcs[i].name);
        if (!fn) return 0xC002 + i; // error code

        if (is_wine) {
            nt_funcs[i].func_ptr = fn; // use direct call
        } else {
            int result = extract_syscall_number(fn, &nt_funcs[i].syscall_num);
            if (result != 1) return 0xC002 + i;
        }
    }

    // Also resolve NtDelayExecution function pointer for gadget scanning:
    void* nt_delay_fn = GetProcAddress_custom(ntdll_base, "NtDelayExecution");

    // ── Step 4: Build syscall trampolines (non-Wine) ──
    if (!is_wine) {
        // 4a. Find "syscall; ret" (0F 05 C3) gadgets in ntdll
        //   Search near NtDelayExecution for this pattern:
        uint8_t* scan_base = (uint8_t*)nt_delay_fn + 0x12;
        // ... or at +0x08 if the first attempt fails

        // 4b. Use RDTSC-based randomization to pick two random gadgets
        //   This makes the trampoline targets unpredictable to AV.
        void* gadget1 = NULL;
        void* gadget2 = NULL;
        while (1) {
            uint64_t tsc;
            __rdtsc(&tsc);
            uint32_t idx = (tsc & 0x7FF) << 4;
            uint8_t* candidate = scan_base + idx;
            uint32_t check = *(uint32_t*)candidate & 0xFFFFFF;
            if (check == 0xC3050F) { // syscall; ret
                gadget1 = candidate;
                break;
            }
        }
        while (1) {
            uint64_t tsc;
            __rdtsc(&tsc);
            uint32_t idx = (tsc & 0x7FF) << 4;
            uint8_t* candidate = scan_base + idx;
            uint32_t check = *(uint32_t*)candidate & 0xFFFFFF;
            if (check == 0xC3050F) {
                gadget2 = candidate;
                break;
            }
        }

        // 4c. Allocate 0x8000 bytes of executable memory
        //   Uses one of the gadgets directly as a bootstrap syscall.
        //   Params: NtAllocateVirtualMemory(-1, &ptr, 0, &size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
        void* trampoline_mem = NULL;
        SIZE_T alloc_size = 0x8000;
        // ... (direct syscall through gadget1 to allocate memory)

        // 4d. Build vtable + obfuscated trampolines
        //   Each trampoline entry (~0x60 bytes) uses code like:
        //
        //   trampoline:
        //       push rax
        //       mov eax, <syscall_number>    ; patched per-function
        //       push rcx
        //       mov rcx, ~gadget_addr        ; NOT-obfuscated gadget pointer
        //       xchg [rsp], rcx              ; swap with saved rcx
        //       pop rax                      ; pop original rax... (complex stack magic)
        //       lea rsp, [rsp - 0x680]       ; allocate large shadow space
        //       ... save registers, set up context, copy args ...
        //       not rcx                      ; de-obfuscate gadget address
        //       jmp rcx                      ; jump to syscall;ret gadget
        //
        //   Each trampoline does obfuscated register save/restore to hide
        //   the syscall pattern from memory scanners.

        // Trampolines are built at offsets within trampoline_mem:
        //   RDTSC-randomized sub-offsets within the page
        uint8_t* vtable_base = (uint8_t*)trampoline_mem + 0x1000;
        uint8_t* trampoline_base = (uint8_t*)trampoline_mem + 0x2000;

        // Patch syscall numbers into trampoline stubs:
        // trampoline[0] uses NtAllocateVirtualMemory's syscall #
        // trampoline[1] uses NtOpenProcess's syscall #
        // trampoline[2] uses NtProtectVirtualMemory's syscall #
        // trampoline[3] uses NtReadVirtualMemory's syscall #

        // 4e. Write vtable to trampoline_mem[0x1000]:
        //   vtable[0x30] = trampoline for NtReadVirtualMemory
        //   vtable[0x38] = trampoline for NtAllocateVirtualMemory
        //   vtable[0x48] = trampoline for NtOpenProcess
        //   vtable[0x68] = trampoline for NtDelayExecution
        //   (etc.)

        // Then execute an in-process NtAllocateVirtualMemory via the trampoline
        // to verify it works, and write the final vtable.

        // Store NOT-obfuscated pointer to vtable:
        *(uint64_t*)si_out = ~(uint64_t)vtable_base;

    } else {
        // ── Wine path ──
        // Allocate memory using direct NtAllocateVirtualMemory call
        void* wine_mem = NULL;
        SIZE_T wine_size = 0x2000;
        nt_funcs[0].func_ptr(/*NtAllocateVirtualMemory params*/);

        // Build simpler vtable with direct function pointers
        // Store function pointers at appropriate vtable offsets
        // ...

        *(uint64_t*)si_out = ~(uint64_t)wine_mem;
    }

    return 0; // success
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  CUSTOM GetProcAddress (0x5A0 – 0x70C)
 *  Walks the PE export directory of a loaded DLL to find a function by name.
 *  Supports both name-based and ordinal-based lookup.
 *  Uses binary search on the name table.
 * ═══════════════════════════════════════════════════════════════════════════ */

// offset 0x5A0
void* GetProcAddress_custom(void* module_base, const char* func_name) {
    if (!module_base || !func_name)
        return NULL;

    uint8_t* base = (uint8_t*)module_base;

    // Validate MZ header
    if (*(uint16_t*)base != 0x5A4D) // "MZ"
        return NULL;

    // Get PE header
    uint32_t pe_offset = *(uint32_t*)(base + 0x3C);
    uint32_t* pe_sig = (uint32_t*)(base + pe_offset);
    if (*pe_sig != 0x4550) // "PE\0\0"
        return NULL;

    // Get export directory from Optional Header data directory[0]
    uint32_t export_rva  = *(uint32_t*)(base + pe_offset + 0x88);
    uint32_t export_size = *(uint32_t*)(base + pe_offset + 0x8C);
    if (export_rva == 0)
        return NULL;

    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(base + export_rva);

    // Check if lookup by ordinal (func_name < 0xFFFF)
    if ((uintptr_t)func_name <= 0xFFFF) {
        uint32_t ordinal = (uint32_t)(uintptr_t)func_name - exports->Base;
        if (ordinal >= exports->NumberOfFunctions)
            return NULL;
        uint32_t* address_table = (uint32_t*)(base + exports->AddressOfFunctions);
        uint32_t func_rva = address_table[ordinal];
        goto resolve;
    }

    // Name-based lookup: binary search
    uint32_t num_names = exports->NumberOfNames;
    if (num_names == 0)
        goto not_found;

    uint32_t* name_table = (uint32_t*)(base + exports->AddressOfNames);
    uint32_t found_ordinal = 0xFFFFFFFF;
    int lo = 0, hi = num_names - 1;

    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        const char* export_name = (const char*)(base + name_table[mid]);

        // strcmp-like comparison
        const char* a = func_name;
        const char* b = export_name;
        while (*a && *a == *b) { a++; b++; }

        if (*a < *b)
            hi = mid - 1;
        else if (*a > *b)
            lo = mid + 1;
        else {
            // Found: get ordinal from ordinals table
            uint16_t* ordinal_table = (uint16_t*)(base + exports->AddressOfNameOrdinals);
            found_ordinal = ordinal_table[mid];
            break;
        }
    }

    if (found_ordinal >= exports->NumberOfFunctions)
        goto not_found;

    uint32_t func_rva;
    {
        uint32_t* address_table = (uint32_t*)(base + exports->AddressOfFunctions);
        func_rva = address_table[found_ordinal];
    }

resolve:
    if (func_rva == 0) goto not_found;

    // Check for forwarded export (RVA within export directory range)
    if (func_rva >= export_rva && func_rva < export_rva + export_size)
        goto not_found; // forwarded exports not supported

    return base + func_rva;

not_found:
    return NULL;
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  NT SYSCALL WRAPPERS – thin wrappers around the vtable
 *  Each reads the NOT-obfuscated vtable pointer from base+0x38,
 *  de-obfuscates it, and calls the appropriate trampoline.
 * ═══════════════════════════════════════════════════════════════════════════ */

// offset 0x3E0 – flush instruction cache / change to PAGE_EXECUTE_READWRITE
void VirtualProtect_RWX(void* addr) {
    // r8d = 0x40 (PAGE_EXECUTE_READWRITE), edx = 0x2000
    NtProtectVirtualMemory_wrapper(addr, 0x2000, PAGE_EXECUTE_READWRITE);
}

// offset 0x3F0 – change to PAGE_READWRITE
void VirtualProtect_RW(void* addr) {
    // r8d = 0x20 (PAGE_READWRITE), edx = 0x2000
    NtProtectVirtualMemory_wrapper(addr, 0x2000, PAGE_READWRITE);
}

// offset 0x400 (shared impl at 0x410)
NTSTATUS NtAllocateVirtualMemory_wrapper(void* preferred, SIZE_T size, uint32_t protect) {
    NtVtable* vt = VTABLE();
    void* base_addr = (void*)((uintptr_t)preferred & ~0xFFF); // page-align
    SIZE_T region_size = 0;
    uint32_t old_protect;
    NTSTATUS status = vt->NtAllocateVirtualMemory(
        (HANDLE)-1,    // current process
        &base_addr,
        0,
        &region_size,
        MEM_COMMIT,
        protect
    );
    return status == 0 ? (NTSTATUS)1 : 0; // 0=fail, 1=success (inverted)
}

// offset 0x460 – NtOpenProcess wrapper
HANDLE NtOpenProcess_wrapper(uint32_t pid, uint32_t access_mask) {
    NtVtable* vt = VTABLE();
    HANDLE handle = NULL;
    OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, NULL, 0, NULL, NULL };
    CLIENT_ID cid = { (HANDLE)(uintptr_t)pid, 0 };
    oa.Length = 0x30;
    oa.Attributes = 2; // OBJ_INHERIT
    NTSTATUS status = vt->NtOpenProcess(&handle, access_mask, &oa, &cid);
    return status == 0 ? handle : NULL;
}

// offset 0x4E0 – NtReadVirtualMemory wrapper (read from host process)
NTSTATUS NtReadVirtualMemory_wrapper(HANDLE process, void* address,
                                      void* buffer, SIZE_T size) {
    NtVtable* vt = VTABLE();
    SIZE_T bytes_read;
    return vt->NtReadVirtualMemory(process, address, buffer, size, &bytes_read);
}

// offset 0x520 – NtDelayExecution (sleep) wrapper
void NtSleep(uint32_t milliseconds) {
    NtVtable* vt = VTABLE();
    LARGE_INTEGER delay;
    delay.QuadPart = -(int64_t)milliseconds * 10000; // relative time, 100ns units
    vt->NtDelayExecution(FALSE, &delay);
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  SHELLCODE ENTRY POINT (0x1D0)
 *  Called by CreateRemoteThread with `param` = shellcode base address.
 *  Initializes the NT vtable, then starts the main FPS patching loop.
 * ═══════════════════════════════════════════════════════════════════════════ */

// offset 0x1D0 – SHELLCODE_ENTRY_VA
void shellcode_entry(void* param) {
    ShellcodeHeader* base = (ShellcodeHeader*)(
        (uint8_t*)&shellcode_entry - 0x1D0  // RIP-relative → base
    );

    // Use *(base+0x38) temporarily as STARTUPINFOW.cb field
    // to pass 0x60 (GS offset for PEB) to _pe_loader_setup
    *(uint32_t*)&base->nt_vtable_ptr = 0x60;

    // Step 1: Initialize NT syscall vtable
    int32_t result = _pe_loader_setup(
        &base->nt_vtable_ptr,   // rcx = base+0x38 (overwritten with vtable ptr)
        0,                       // edx = 0
        (STARTUPINFOW*)&base->nt_vtable_ptr  // r8
    );
    if (result != 0) return; // failed

    // Step 2: Allocate 0x4000 bytes RW in current process
    NtAllocateVirtualMemory_wrapper(base, 0x4000, PAGE_READWRITE);

    // Step 3: Start main FPS patching loop
    _shellcode_trampoline(base->host_pid);
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  MAIN LOOP – _shellcode_trampoline  (0x0A0)
 *  Runs indefinitely inside the game process:
 *  1. Opens a handle to the HOST (injector) process
 *  2. Reads the target FPS value from host's memory
 *  3. Applies the FPS cap to the game
 *  4. Sleeps and repeats
 * ═══════════════════════════════════════════════════════════════════════════ */

// offset 0x0A0
void _shellcode_trampoline(uint32_t host_pid) {
    // Open handle to host (injector) process with PROCESS_ALL_ACCESS
    HANDLE host_process = NtOpenProcess_wrapper(host_pid, 0x1FFFFF);
    if (!host_process) return;

    uint64_t* p_remote_fps = (uint64_t*)BASE->p_fps_value;
    uint32_t delay_ms = 500;

    while (1) {
        // Read FPS_VALUE from host process into local variable
        uint32_t local_fps;
        NTSTATUS status = NtReadVirtualMemory_wrapper(
            host_process, p_remote_fps, &local_fps, sizeof(local_fps)
        );

        if (status != 0) {
            // Read failed → show error and advance to next hook entry
            _show_sync_failed_msgbox();
        }

        // Apply FPS sleep logic and write the value
        _fps_sleep_logic(local_fps);

        // Sleep before next iteration
        NtSleep(delay_ms);
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  FPS SLEEP LOGIC (0x130)
 *  Reads the game's current FPS target from *p_fps_value.
 *  Adjusts the sleep duration based on FPS mode (power saving).
 *  Also checks if the game window is the foreground window.
 * ═══════════════════════════════════════════════════════════════════════════ */

// offset 0x130
void _fps_sleep_logic(uint32_t target_fps) {
    uint32_t* p_fps = (uint32_t*)BASE->p_fps_value;  // may be NULL initially
    uint32_t sleep_ms = target_fps;

    if (p_fps) {
        uint32_t current_fps = *p_fps;
        if (current_fps == 30) {
            sleep_ms = 60;              // patched at offset 0x158
        } else if (current_fps == 45) {
            // keep target_fps as-is
        } else {
            sleep_ms = 1000;            // patched at offset 0x150
        }
    }

    // Check foreground window (only if GetForegroundWindow available)
    HWND fg_hwnd = 0;
    if (BASE->p_GetForegroundWindow) {
        fg_hwnd = ((HWND(*)())BASE->p_GetForegroundWindow)();
        sleep_ms = (uint32_t)(uintptr_t)fg_hwnd;
    }

    uint32_t threshold = 240; // 0xF0
    // Compare and conditionally write FPS
    _fps_cmov_write(p_fps, target_fps, threshold);
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  FPS VALUE WRITE (0x2C0)
 *  Writes the target FPS to the game's memory.
 *
 *  IMPORTANT: Originally had "cmova ecx, edx" (cap FPS at 240 when
 *  game is not foreground). This was NOP'd in the latest update to
 *  allow unrestricted FPS at all times.
 * ═══════════════════════════════════════════════════════════════════════════ */

// offset 0x2C0
void _fps_cmov_write(uint32_t* p_fps, uint32_t target, uint32_t threshold) {
    // Was: if (target > threshold) target = threshold; // cmova ecx, edx
    // Now: NOP (removed the 240fps cap for background windows)

    *p_fps = target; // write FPS value to game memory
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  SHOW SYNC FAILED MSGBOX (0x180)
 *  Displays a "Sync failed!" error popup using MessageBoxA.
 * ═══════════════════════════════════════════════════════════════════════════ */

// offset 0x180
void _show_sync_failed_msgbox(void) {
    typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
    MessageBoxA_t msgbox = (MessageBoxA_t)BASE->p_MessageBoxA;

    // CloseHandle(something) first
    ((void(*)(HANDLE))BASE->p_CloseHandle)(/*handle*/);

    // "Sync failed!" error
    char text[] = "Sync failed!";    // 0x53 79 6E 63 20 66 61 69
    char title[] = "Error";          // 0x45 72 72 6F 72
    msgbox(NULL, text, title, MB_ICONERROR); // 0x10 = MB_ICONERROR
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  PowerSaveSet_Func (0x560)
 *  Optional function that returns the FPS limit based on whether the game
 *  window is the foreground window.
 *  If game IS foreground: return the target FPS (passed as ecx)
 *  If NOT foreground: return 10 (power save mode)
 * ═══════════════════════════════════════════════════════════════════════════ */

// offset 0x560 – POWERSAVESET_FUNC_VA
// The injector patches:
//   +0x10 = p_unity_wndclass HWND  (the expected foreground window)
//   +0x1C = power_save_fps (default 10)
uint32_t PowerSaveSet_Func(uint32_t desired_fps) {
    HWND current_fg = ((HWND(*)())BASE->p_GetForegroundWindow)();

    // Compare foreground HWND against the game's expected HWND
    // stored at a fixed address patched by the injector
    HWND expected_hwnd = *(HWND*)(/*patched address at offset 0x570*/);

    if (current_fg == expected_hwnd) {
        return desired_fps;    // game is foreground → full FPS
    } else {
        return 10;             // game is background → power save
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  HKSR_UISet  (0x220)
 *  Star Rail-specific function. Writes the FPS value and delegates to
 *  PowerSaveSet_Func. Not used for Genshin Impact.
 * ═══════════════════════════════════════════════════════════════════════════ */

// offset 0x220 – HKSR_UISet_FuncVA
uint32_t _hksr_ui_set(uint32_t fps_value) {
    uint32_t* p_fps = (uint32_t*)BASE->p_fps_value;
    uint32_t old_pid = BASE->host_pid;
    *p_fps = old_pid; // write something to FPS ptr
    return PowerSaveSet_Func(fps_value);
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  GI_UnHooked_UI_func (0x240)
 *  This is the UI "unhook" path for touch/mobile mode.
 *  Called when the game's ui_unhook_time function is hooked.
 *
 *  Process:
 *  1. Restore original bytes of ui_unhook_time (unhook it)
 *  2. Call the original ui_unhook_time function
 *  3. Then call func_gui_set and func_input_set to apply UI settings
 * ═══════════════════════════════════════════════════════════════════════════ */

// offset 0x240 – GI_UNHOOKED_UI_FVA
void GI_UnHooked_UI_func(uint64_t arg1, uint64_t arg2) {
    uint8_t* ui_func = (uint8_t*)BASE->ui_unhook_time;

    // Save arguments
    uint64_t saved_rcx = arg1;

    // Step 1: Make the memory writable (could be PAGE_EXECUTE_READ)
    VirtualProtect_RWX(ui_func); // at 0x3E0

    // Step 2: Restore original 16 bytes (remove our hook)
    memcpy(ui_func, BASE->org_ui_unhook_bytes, 16);

    // Step 3: Re-protect as executable
    VirtualProtect_RW(ui_func); // at 0x3F0

    // Step 4: Call the original function
    ((void(*)(uint64_t))ui_func)(saved_rcx);

    // Step 5: Apply UI modifications (touch/mobile mode)
    UIFuncList* ui_list = (UIFuncList*)BASE->ui_func_list_ptr;
    void* grph_instance = *(void**)ui_list->grph_class;
    grph_instance = *(void**)grph_instance; // double dereference

    if (grph_instance) {
        // Call func_gui_set(graphicsInstance[uicl_va], 0)
        uint8_t* obj = (uint8_t*)grph_instance;
        void* ui_target = *(void**)(obj + ui_list->grph_uicl_va);
        ((void(*)(void*, int))ui_list->func_gui_set)(ui_target, 0);

        // Call func_input_set(graphicsInstance[inputcl_va], 0)
        void* input_target = *(void**)(obj + ui_list->grph_inputcl_va);
        ((void(*)(void*, int))ui_list->func_input_set)(input_target, 0);
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  GI_hooked_Vfunc (0x2D0)
 *  This is the MAIN HOOK function. It replaces the game's "verify" function.
 *  Every time the game calls verify, this code intercepts it:
 *
 *  1. UNHOOK phase: Restore all hook entries to original bytes
 *     (so the game sees un-tampered memory if it integrity-checks)
 *  2. Call the ORIGINAL verify function
 *  3. RE-HOOK phase: Re-apply all hook patches
 *  4. Return the original verify result
 *
 *  This is a classic "unhook → call orig → re-hook" anti-detection pattern.
 * ═══════════════════════════════════════════════════════════════════════════ */

// offset 0x2D0 – GI_HOOKED_VFUNC_VA
uint64_t GI_hooked_Vfunc(uint64_t arg1, uint64_t arg2,
                          uint64_t arg3, uint64_t arg4) {
    HookEntry* hook_table = (HookEntry*)BASE->hook_info_base;
    uint8_t*   verify_fn  = (uint8_t*)BASE->verify_func_addr;

    // Save all 4 register arguments
    uint64_t saved_args[4] = { arg1, arg2, arg3, arg4 };

    // ── Phase 1: UNHOOK all entries ──
    // Walk the hook table; each entry is 0x30 bytes.
    // Restore original bytes so the game sees clean memory.
    for (int i = 0; ; i++) {
        HookEntry* entry = &hook_table[i];
        if (entry->target_addr == 0) break; // end sentinel

        uint8_t* target = (uint8_t*)entry->target_addr;
        VirtualProtect_RWX(target);  // make writable
        memcpy(target, entry->original_bytes, 16); // restore original
    }

    // Unhook the verify function itself
    VirtualProtect_RWX(verify_fn);
    memcpy(verify_fn, BASE->org_verify_bytes, 16);

    // ── Phase 2: Call ORIGINAL verify function ──
    uint64_t result = ((uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t))
                        verify_fn)(saved_args[0], saved_args[1],
                                   saved_args[2], saved_args[3]);

    // ── Phase 3: RE-HOOK the verify function ──
    memcpy(verify_fn, BASE->hooked_verify_jmp, 16); // re-apply abs jmp patch

    // ── Phase 4: RE-HOOK all entries ──
    for (int i = 0; ; i++) {
        HookEntry* entry = &hook_table[i];
        if (entry->target_addr == 0) break;

        uint8_t* target = (uint8_t*)entry->target_addr;
        memcpy(target, entry->hooked_bytes, 16); // re-apply hook patch
        VirtualProtect_RWX(target);  // flush and set executable
    }

    // Ensure verify function page is executable
    VirtualProtect_RWX(verify_fn);

    return result;
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  SYSCALL TRAMPOLINE STUB (0x1040)
 *  This is the generated trampoline code that makes indirect NT syscalls.
 *  It's built dynamically by _pe_loader_setup and looks like this:
 * ═══════════════════════════════════════════════════════════════════════════ */

// offset 0x1040 (dynamically generated, this is the template)
//
// The trampoline does the following (de-obfuscated):
//   1. Push return address
//   2. Save all registers (RBP, RSP, XMM0-3) via stack manipulation
//   3. Load the syscall number into EAX
//   4. Put the de-obfuscated gadget address (ntdll's "syscall;ret") into RCX
//   5. JMP RCX → executes the syscall and returns
//
// This avoids having "syscall" instruction in the shellcode itself,
// making it harder for AV to detect direct syscall usage.
//
// Pseudocode:
void __trampoline_template(void* vtable_entry_ptr) {
    // Read function-specific data from vtable entry
    uint64_t not_gadget_addr = *(uint64_t*)(vtable_entry_ptr + 8);
    void*    trampoline_code = *(void**)(vtable_entry_ptr + 0x10);

    // Save all registers onto stack
    // ... (complex stack frame setup) ...

    // Copy argument XMM registers (xmm0-xmm3) to stack shadow space
    // ... (movups xmm0/1/2/3 to [rsp+0x28..0x58]) ...

    // De-obfuscate the syscall gadget address
    void* gadget = (void*)(~not_gadget_addr);

    // JMP to gadget (which is "syscall; ret" in ntdll.dll)
    // EAX already has the syscall number from earlier setup
    goto *gadget;
}


/* ═══════════════════════════════════════════════════════════════════════════
 *  EXECUTION FLOW SUMMARY
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  [Host Process / Injector (Rust)]
 *    1. genshin::run() finds the game executable
 *    2. Creates suspended process, scans for FPS/verify/UI patterns
 *    3. Patches shellcode header (PIDs, function ptrs, hook entries)
 *    4. Writes shellcode into game process via WriteProcessMemory
 *    5. Creates remote thread at SHELLCODE_ENTRY_VA (0x1D0)
 *    6. Keeps running so the shellcode can read FPS_VALUE from it
 *
 *  [Game Process / Shellcode]
 *    1. shellcode_entry(0x1D0):
 *       - Walks PEB → ntdll → resolves 6 NT functions
 *       - Builds obfuscated syscall trampolines
 *       - Calls _shellcode_trampoline
 *
 *    2. _shellcode_trampoline(0x0A0):  [INFINITE LOOP]
 *       - NtOpenProcess → gets handle to host/injector process
 *       - NtReadVirtualMemory → reads FPS_VALUE from host's memory
 *       - _fps_sleep_logic → adjusts sleep based on FPS mode
 *       - _fps_cmov_write → writes FPS to game's internal cap
 *       - NtDelayExecution → sleep 500ms
 *       - Loop back
 *
 *    3. GI_hooked_Vfunc(0x2D0):  [CALLED BY GAME]
 *       Every time the game calls its verify function:
 *       - Unhook everything → call original → re-hook everything
 *       - This hides our patches during integrity checks
 *
 *    4. GI_UnHooked_UI_func(0x240):  [CALLED BY GAME, touch mode only]
 *       - Restores UI function → calls original → applies mobile UI settings
 *
 * ═══════════════════════════════════════════════════════════════════════════ */
