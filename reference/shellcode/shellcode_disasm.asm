; ==============================================================================
; Shellcode disassembly – Genshin FPS Unlocker (linear sweep)
; Total size: 4384 bytes (0x1120)
; ==============================================================================

; ──── DATA HEADER (0x000 – 0x09F) ────
; Patched at runtime by the injector (genshin.rs inject_patch)

  ; 0x000 [ 4] host_pid                 = 0x00000000  ; Host process PID
  ; 0x004 [ 4] magic                    = 0x688C9020  ; Magic: 0x688C9020
  ; 0x008 [ 8] p_fps_value              = 0x0000000000000000  ; Pointer to FPS_VALUE in host
  ; 0x010 [ 8] reserved_10              = 0x0000000000000000  ; Reserved
  ; 0x018 [ 8] private_buffer           = 0x0000000000000000  ; Private buffer near module base
  ; 0x020 [ 8] hook_info_base           = 0x0000000000000000  ; Hook info table (payload+0x2000)
  ; 0x028 [ 8] verify_func_addr         = 0x0000000000000000  ; Address of verify function to hook
  ; 0x030 [ 8] powersave_func_ptr       = 0x0000000000000000  ; PowerSaveSet function ptr (or 0)
  ; 0x038 [ 8] reserved_38              = 0x0000000000000000  ; Reserved
  ; 0x040 [ 8] ui_unhook_time_addr      = 0x0000000000000000  ; UI unhook time func addr (touch mode)
  ; 0x048 [ 8] ui_func_list_ptr         = 0x0000000000000000  ; UI func list (payload+0x3000)
  ; 0x050 [16] org_ui_unhook_bytes      = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ; Original 16 bytes of ui_unhook_time
  ; 0x060 [16] org_verify_bytes         = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ; Original 16 bytes of verify func
  ; 0x070 [16] hooked_verify_jmp        = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ; Absolute jump patch for verify
  ; 0x080 [ 8] p_MessageBoxA            = 0x0000000000000000  ; Pointer to MessageBoxA
  ; 0x088 [ 8] p_CloseHandle            = 0x0000000000000000  ; Pointer to CloseHandle
  ; 0x090 [ 8] p_GetForegroundWindow    = 0x0000000000000000  ; Pointer to GetForegroundWindow
  ; 0x098 [ 8] reserved_98              = 0xCCCCCCCCCCCCCCCC  ; Reserved

; ==============================================================================
; CODE SECTION (0x0A0 – 0x1120)
; ==============================================================================

; ──────────────────────────────────────────────────────────────────────────────
; _shellcode_trampoline   (0x0A0)
; Main entry trampoline – opens process handle, patches FPS, jumps to payload OEP
; ──────────────────────────────────────────────────────────────────────────────
_shellcode_trampoline:
    push rbp                                     ; 0x0A0: 55
    push rbx                                     ; 0x0A1: 53
    push rsi                                     ; 0x0A2: 56
    push rdi                                     ; 0x0A3: 57
    push r15                                     ; 0x0A4: 41 57
    sub rsp, 0x70                                ; 0x0A6: 48 83 EC 70
    lea rbp, [rsp + 0x20]                        ; 0x0AA: 48 8D 6C 24 20
    mov edx, ecx                                 ; 0x0AF: 89 CA
    mov ecx, 0x1fffff                            ; 0x0B1: B9 FF FF 1F 00
    call 0x460                                   ; 0x0B6: 48 E8 A4 03 00 00
    mov r15, rax                                 ; 0x0BC: 49 89 C7
    test rax, rax                                ; 0x0BF: 48 85 C0
    je 0x124                                     ; 0x0C2: 74 60
    mov rdi, qword ptr [rip - 0xc4]              ; 0x0C4: 44 48 8B 3D 3C FF FF FF
    xor r14, r14                                 ; 0x0CC: 4D 31 F6
    mov ebx, 0x1f4                               ; 0x0CF: BB F4 01 00 00
    lea rsi, [rip + 4]                           ; 0x0D4: 44 48 8D 35 04 00 00 00
    mov qword ptr [rbp + 8], rbx                 ; 0x0DC: 48 89 5D 08
    lea r8, [rsp + 0x28]                         ; 0x0E0: 4C 8D 44 24 28
    mov qword ptr [rsp + 0x20], r14              ; 0x0E5: 4C 89 74 24 20
    mov r9d, 4                                   ; 0x0EA: 41 B9 04 00 00 00
    mov rdx, rdi                                 ; 0x0F0: 48 89 FA
    mov rcx, r15                                 ; 0x0F3: 4C 89 F9
    call 0x4e0                                   ; 0x0F6: 48 E8 E4 03 00 00
    test eax, eax                                ; 0x0FC: 85 C0
    jne 0x110                                    ; 0x0FE: 75 10
    add rsi, 0x30                                ; 0x100: 48 83 C6 30
    mov rcx, r15                                 ; 0x104: 4C 89 F9
    call 0x180                                   ; 0x107: E8 74 00 00 00
    nop dword ptr [rax]                          ; 0x10C: 0F 1F 40 00
    mov ecx, dword ptr [rsp + 0x28]              ; 0x110: 8B 4C 24 28
    call 0x130                                   ; 0x114: 48 E8 16 00 00 00  ; -> _fps_sleep_logic
    mov ecx, ebx                                 ; 0x11A: 89 D9
    call 0x520                                   ; 0x11C: 48 E8 FE 03 00 00  ; -> _nt_waitforsingle
    jmp rsi                                      ; 0x122: FF E6
    add rsp, 0x70                                ; 0x124: 48 83 C4 70
    pop r15                                      ; 0x128: 41 5F
    pop rdi                                      ; 0x12A: 5F
    pop rsi                                      ; 0x12B: 5E
    pop rbx                                      ; 0x12C: 5B
    pop rbp                                      ; 0x12D: 5D
    ret                                          ; 0x12E: C3
    ; ... (1 bytes int3 padding)

; ──────────────────────────────────────────────────────────────────────────────
; _fps_sleep_logic   (0x130)
; Read FPS target, call Sleep/GetForegroundWindow, decide delay
; ──────────────────────────────────────────────────────────────────────────────
_fps_sleep_logic:
    sub rsp, 0x38                                ; 0x130: 48 83 EC 38
    mov rax, qword ptr [rip - 0x12c]             ; 0x134: 44 48 8B 05 D4 FE FF FF
    test rax, rax                                ; 0x13C: 48 85 C0
    je 0x15c                                     ; 0x13F: 74 1B
    mov eax, dword ptr cs:[rax]                  ; 0x141: 2E 8B 00
    cmp eax, 0x1e                                ; 0x144: 83 F8 1E
    je 0x156                                     ; 0x147: 74 0D
    cmp eax, 0x2d                                ; 0x149: 83 F8 2D
    je 0x15c                                     ; 0x14C: 74 0E
    mov ecx, 0x3e8                               ; 0x14E: 2E B9 E8 03 00 00
    jmp 0x15c                                    ; 0x154: EB 06
    mov ecx, 0x3c                                ; 0x156: 2E B9 3C 00 00 00
    mov rax, qword ptr [rip - 0x133]             ; 0x15C: 48 8B 05 CD FE FF FF
    test rax, rax                                ; 0x163: 48 85 C0
    je 0x16c                                     ; 0x166: 74 04
    call rax                                     ; 0x168: FF D0
    mov ecx, eax                                 ; 0x16A: 89 C1
    mov rax, qword ptr [rip - 0x15c]             ; 0x16C: 44 48 8B 05 A4 FE FF FF
    mov edx, 0xf0                                ; 0x174: BA F0 00 00 00
    cmp ecx, edx                                 ; 0x179: 39 D1
    jmp 0x2c0                                    ; 0x17B: E9 40 01 00 00  ; -> _fps_cmov_write
    sub rsp, 0x68                                ; 0x180: 48 83 EC 68
    call qword ptr [rip - 0x102]                 ; 0x184: FF 15 FE FE FF FF
    xor ecx, ecx                                 ; 0x18A: 31 C9
    lea rdx, ds:[rsp + 0x20]                     ; 0x18C: 3E 48 8D 54 24 20
    lea r8, [rdx + 0x10]                         ; 0x192: 4C 8D 42 10
    movabs rax, 0x69616620636e7953               ; 0x196: 48 B8 53 79 6E 63 20 66 61 69
    mov qword ptr [rdx + 8], 0x2164656c          ; 0x1A0: 48 C7 42 08 6C 65 64 21
    mov qword ptr [rdx], rax                     ; 0x1A8: 48 89 42 00
    mov dword ptr [r8], 0x6f727245               ; 0x1AC: 41 C7 00 45 72 72 6F
    mov word ptr [r8 + 4], 0x72                  ; 0x1B3: 66 41 C7 40 04 72 00
    mov r9d, 0x10                                ; 0x1BA: 41 B9 10 00 00 00
    call qword ptr [rip - 0x146]                 ; 0x1C0: FF 15 BA FE FF FF
    add rsp, 0x68                                ; 0x1C6: 48 83 C4 68
    ret                                          ; 0x1CA: C3
    ; ... (5 bytes int3 padding)

; ──────────────────────────────────────────────────────────────────────────────
; shellcode_entry   (0x1D0)
; SHELLCODE_ENTRY_VA – primary entry point called via CreateRemoteThread
; ──────────────────────────────────────────────────────────────────────────────
shellcode_entry:
    push rbx                                     ; 0x1D0: 40 53
    sub rsp, 0x60                                ; 0x1D2: 48 83 EC 60
    lea rbx, [rip - 0x1de]                       ; 0x1D6: 4C 48 8D 1D 22 FE FF FF
    lea rcx, [rbx + 0x38]                        ; 0x1DE: 48 8D 4B 38
    mov dword ptr [rcx], 0x60                    ; 0x1E2: C7 01 60 00 00 00
    xor edx, edx                                 ; 0x1E8: 31 D2
    mov r8, rcx                                  ; 0x1EA: 49 89 C8
    call 0x720                                   ; 0x1ED: E8 2E 05 00 00  ; -> _pe_loader_setup
    test eax, eax                                ; 0x1F2: 85 C0
    jne 0x212                                    ; 0x1F4: 75 1C
    mov rcx, rbx                                 ; 0x1F6: 48 89 D9
    mov edx, 0x4000                              ; 0x1F9: BA 00 40 00 00
    mov r8d, 0x20                                ; 0x1FE: 41 B8 20 00 00 00
    call 0x400                                   ; 0x204: 44 E8 F6 01 00 00  ; -> _VirtualAlloc_wrapper_RW
    mov ecx, dword ptr [rbx]                     ; 0x20A: 8B 0B
    call 0xa0                                    ; 0x20C: E8 8F FE FF FF  ; -> _shellcode_trampoline
    nop                                          ; 0x211: 90
    add rsp, 0x60                                ; 0x212: 48 83 C4 60
    pop rbx                                      ; 0x216: 5B
    ret                                          ; 0x217: C3
    ; ... (8 bytes int3 padding)

; ──────────────────────────────────────────────────────────────────────────────
; _hksr_ui_set   (0x220)
; HKSR_UISet_FuncVA (Star Rail specific)
; ──────────────────────────────────────────────────────────────────────────────
_hksr_ui_set:
    mov rax, qword ptr [rip - 0x208]             ; 0x220: 4C 48 8B 05 F8 FD FF FF
    mov r8, rcx                                  ; 0x228: 40 49 89 C8
    mov ecx, dword ptr [rip - 0x20a]             ; 0x22C: 8B 0D F6 FD FF FF
    mov dword ptr [rax], ecx                     ; 0x232: 89 08
    mov rcx, r8                                  ; 0x234: 4C 89 C1
    jmp 0x560                                    ; 0x237: E9 24 03 00 00  ; -> PowerSaveSet_Func
    ; ... (4 bytes int3 padding)

; ──────────────────────────────────────────────────────────────────────────────
; GI_UnHooked_UI_func   (0x240)
; GI_UNHOOKED_UI_FVA – original UI function dispatcher (unhook path)
; ──────────────────────────────────────────────────────────────────────────────
GI_UnHooked_UI_func:
    push rbx                                     ; 0x240: 53
    push rbp                                     ; 0x241: 55
    push rsi                                     ; 0x242: 56
    push rdi                                     ; 0x243: 57
    sub rsp, 0x48                                ; 0x244: 48 83 EC 48
    mov rbx, qword ptr [rip - 0x210]             ; 0x248: 4C 48 8B 1D F0 FD FF FF
    lea rbp, [rsp + 0x28]                        ; 0x250: 48 8D AC 24 28 00 00 00
    mov qword ptr [rbp + 8], rcx                 ; 0x258: 48 89 4D 08
    mov qword ptr [rbp + 0x10], rdx              ; 0x25C: 48 89 55 10
    mov rcx, rbx                                 ; 0x260: 48 89 D9
    call 0x3e0                                   ; 0x263: E8 78 01 00 00
    movdqu xmm0, xmmword ptr [rip - 0x220]       ; 0x268: F3 0F 6F 05 E0 FD FF FF
    movdqu xmmword ptr [rbx], xmm0               ; 0x270: F3 0F 7F 03
    mov rcx, rbx                                 ; 0x274: 48 89 D9
    call 0x3f0                                   ; 0x277: E8 74 01 00 00  ; -> _VirtualAlloc_wrapper_RWX
    mov rcx, qword ptr [rbp + 8]                 ; 0x27C: 48 8B 4D 08
    call rbx                                     ; 0x280: FF D3
    nop                                          ; 0x282: 48 90
    mov rdi, qword ptr [rip - 0x244]             ; 0x284: 4C 48 8B 3D BC FD FF FF
    mov rbx, qword ptr [rdi + 0x10]              ; 0x28C: 48 8B 5F 10
    mov rbx, qword ptr [rbx]                     ; 0x290: 48 8B 1B
    test rbx, rbx                                ; 0x293: 48 85 DB
    je 0x2b4                                     ; 0x296: 74 1C
    movsxd rax, dword ptr [rdi + 0x18]           ; 0x298: 48 63 47 18
    mov rcx, qword ptr [rbx + rax]               ; 0x29C: 48 8B 0C 03
    xor edx, edx                                 ; 0x2A0: 31 D2
    call qword ptr [rdi]                         ; 0x2A2: FF 17
    movsxd rax, dword ptr [rdi + 0x1c]           ; 0x2A4: 48 63 47 1C
    mov rcx, qword ptr [rbx + rax]               ; 0x2A8: 48 8B 0C 03
    xor edx, edx                                 ; 0x2AC: 31 D2
    call qword ptr [rdi + 8]                     ; 0x2AE: FF 97 08 00 00 00
    add rsp, 0x48                                ; 0x2B4: 48 83 C4 48
    pop rdi                                      ; 0x2B8: 5F
    pop rsi                                      ; 0x2B9: 5E
    pop rbp                                      ; 0x2BA: 5D
    pop rbx                                      ; 0x2BB: 5B
    ret                                          ; 0x2BC: C3
    ; ... (3 bytes int3 padding)

; ──────────────────────────────────────────────────────────────────────────────
; _fps_cmov_write   (0x2C0)
; Write final FPS value to target (nop'd cmova in latest)
; ──────────────────────────────────────────────────────────────────────────────
_fps_cmov_write:
    nop dword ptr [rax]                          ; 0x2C0: 0F 1F 40 00
    mov dword ptr [rax], ecx                     ; 0x2C4: 89 08
    add rsp, 0x38                                ; 0x2C6: 48 83 C4 38
    ret                                          ; 0x2CA: C3
    ; ... (5 bytes int3 padding)

; ──────────────────────────────────────────────────────────────────────────────
; GI_hooked_Vfunc   (0x2D0)
; GI_HOOKED_VFUNC_VA – hooked verify function, iterates hook table
; ──────────────────────────────────────────────────────────────────────────────
GI_hooked_Vfunc:
    push r15                                     ; 0x2D0: 41 57
    push r14                                     ; 0x2D2: 41 56
    push r13                                     ; 0x2D4: 41 55
    push r12                                     ; 0x2D6: 41 54
    push rbx                                     ; 0x2D8: 53
    push rbp                                     ; 0x2D9: 55
    push rsi                                     ; 0x2DA: 56
    push rdi                                     ; 0x2DB: 57
    sub rsp, 0x68                                ; 0x2DC: 48 83 EC 68
    mov rsi, qword ptr [rip - 0x2c8]             ; 0x2E0: 44 48 8B 35 38 FD FF FF
    mov rbx, qword ptr [rip - 0x2c8]             ; 0x2E8: 40 48 8B 1D 38 FD FF FF
    lea rbp, [rsp + 0x28]                        ; 0x2F0: 48 8D AC 24 28 00 00 00
    mov qword ptr [rbp + 8], rcx                 ; 0x2F8: 48 89 4D 08
    mov qword ptr [rbp + 0x10], rdx              ; 0x2FC: 48 89 55 10
    mov qword ptr [rbp + 0x18], r8               ; 0x300: 4C 89 45 18
    mov qword ptr [rbp + 0x20], r9               ; 0x304: 4C 89 4D 20
    lea rdi, [rip + 0xd0]                        ; 0x308: 4C 48 8D 3D D0 00 00 00
    xor r12, r12                                 ; 0x310: 4D 31 E4
    nop word ptr [rax + rax]                     ; 0x313: 66 66 66 66 66 0F 1F 84 00 00 00 00 00
    lea r13, [rsi + r12]                         ; 0x320: 4E 8D 2C 26
    mov rcx, qword ptr [r13]                     ; 0x324: 49 8B 4D 00
    mov r14, rcx                                 ; 0x328: 49 89 CE
    test rcx, rcx                                ; 0x32B: 48 85 C9
    je 0x348                                     ; 0x32E: 74 18
    call rdi                                     ; 0x330: FF D7
    test eax, eax                                ; 0x332: 85 C0
    je 0x342                                     ; 0x334: 74 0C
    movdqu xmm0, xmmword ptr [r13 + 0x20]        ; 0x336: F3 41 0F 6F 45 20
    movdqu xmmword ptr [r14], xmm0               ; 0x33C: F3 41 0F 7F 46 00
    add r12, 0x30                                ; 0x342: 49 83 C4 30
    jmp 0x320                                    ; 0x346: EB D8
    mov rcx, rbx                                 ; 0x348: 48 89 D9
    call 0x3e0                                   ; 0x34B: E8 90 00 00 00
    mov rcx, qword ptr [rbp + 8]                 ; 0x350: 48 8B 4D 08
    mov rdx, qword ptr [rbp + 0x10]              ; 0x354: 48 8B 55 10
    mov r8, qword ptr [rbp + 0x18]               ; 0x358: 4C 8B 45 18
    mov r9, qword ptr [rbp + 0x20]               ; 0x35C: 4C 8B 4D 20
    movdqu xmm0, xmmword ptr [rip - 0x308]       ; 0x360: F3 0F 6F 05 F8 FC FF FF
    movdqu xmmword ptr [rbx], xmm0               ; 0x368: F3 0F 7F 03
    call rbx                                     ; 0x36C: FF D3
    xchg r15, rax                                ; 0x36E: 49 97
    movdqu xmm0, xmmword ptr [rip - 0x308]       ; 0x370: F3 0F 6F 05 F8 FC FF FF
    movdqu xmmword ptr [rbx], xmm0               ; 0x378: F3 0F 7F 03
    lea rdi, [rip + 0x6c]                        ; 0x37C: 4C 48 8D 3D 6C 00 00 00
    xor r12, r12                                 ; 0x384: 4D 31 E4
    nop word ptr [rax + rax]                     ; 0x387: 66 0F 1F 84 00 00 00 00 00
    lea r13, [rsi + r12]                         ; 0x390: 4E 8D 2C 26
    mov rcx, qword ptr [r13]                     ; 0x394: 49 8B 4D 00
    mov r14, rcx                                 ; 0x398: 49 89 CE
    test rcx, rcx                                ; 0x39B: 48 85 C9
    je 0x3b4                                     ; 0x39E: 74 14
    movdqu xmm0, xmmword ptr [r13 + 0x10]        ; 0x3A0: F3 41 0F 6F 45 10
    movdqu xmmword ptr [r14], xmm0               ; 0x3A6: F3 41 0F 7F 46 00
    call rdi                                     ; 0x3AC: FF D7
    add r12, 0x30                                ; 0x3AE: 49 83 C4 30
    jmp 0x390                                    ; 0x3B2: EB DC
    mov rcx, rbx                                 ; 0x3B4: 48 89 D9
    call rdi                                     ; 0x3B7: 48 FF D7
    xchg r15, rax                                ; 0x3BA: 49 97
    add rsp, 0x68                                ; 0x3BC: 48 83 C4 68
    pop rdi                                      ; 0x3C0: 5F
    pop rsi                                      ; 0x3C1: 5E
    pop rbp                                      ; 0x3C2: 5D
    pop rbx                                      ; 0x3C3: 5B
    pop r12                                      ; 0x3C4: 41 5C
    pop r13                                      ; 0x3C6: 41 5D
    pop r14                                      ; 0x3C8: 41 5E
    pop r15                                      ; 0x3CA: 41 5F
    ret                                          ; 0x3CC: C3
    ; ... (19 bytes int3 padding)
    mov r8d, 0x40                                ; 0x3E0: 41 B8 40 00 00 00
    mov edx, 0x2000                              ; 0x3E6: BA 00 20 00 00
    jmp 0x400                                    ; 0x3EB: E9 10 00 00 00  ; -> _VirtualAlloc_wrapper_RW

; ──────────────────────────────────────────────────────────────────────────────
; _VirtualAlloc_wrapper_RWX   (0x3F0)
; NtAllocateVirtualMemory wrapper (PAGE_EXECUTE_READWRITE=0x40)
; ──────────────────────────────────────────────────────────────────────────────
_VirtualAlloc_wrapper_RWX:
    mov r8d, 0x20                                ; 0x3F0: 41 B8 20 00 00 00
    mov edx, 0x2000                              ; 0x3F6: BA 00 20 00 00
    jmp 0x400                                    ; 0x3FB: E9 00 00 00 00  ; -> _VirtualAlloc_wrapper_RW

; ──────────────────────────────────────────────────────────────────────────────
; _VirtualAlloc_wrapper_RW   (0x400)
; NtAllocateVirtualMemory wrapper (PAGE_READWRITE=0x20)
; ──────────────────────────────────────────────────────────────────────────────
_VirtualAlloc_wrapper_RW:
    mov qword ptr [rsp + 0x18], rdx              ; 0x400: 48 89 54 24 18
    sub rsp, 0x48                                ; 0x405: 48 83 EC 48
    mov r10, qword ptr [rip - 0x3d8]             ; 0x409: 4C 8B 15 28 FC FF FF

; ──────────────────────────────────────────────────────────────────────────────
; _nt_alloc_impl   (0x410)
; Shared NtAllocateVirtualMemory implementation
; ──────────────────────────────────────────────────────────────────────────────
_nt_alloc_impl:
    not r10                                      ; 0x410: 49 F7 D2
    mov dword ptr [rsp + 0x70], 0                ; 0x413: C7 44 24 70 00 00 00 00
    mov r9d, r8d                                 ; 0x41B: 45 89 C1
    lea r8, [rsp + 0x60]                         ; 0x41E: 4C 8D 44 24 60
    and rcx, 0xfffffffffffff000                  ; 0x423: 48 81 E1 00 F0 FF FF
    mov qword ptr [rsp + 0x30], rcx              ; 0x42A: 48 89 4C 24 30
    lea rdx, [rsp + 0x30]                        ; 0x42F: 48 8D 54 24 30
    mov r10, qword ptr [r10]                     ; 0x434: 4D 8B 52 00
    lea rax, [rsp + 0x70]                        ; 0x438: 48 8D 44 24 70
    mov qword ptr [rsp + 0x20], rax              ; 0x43D: 48 89 44 24 20
    or rcx, 0xffffffffffffffff                   ; 0x442: 48 83 C9 FF
    call qword ptr [r10 + 0x38]                  ; 0x446: 41 FF 52 38
    test eax, eax                                ; 0x44A: 85 C0
    je 0x456                                     ; 0x44C: 74 08
    xor eax, eax                                 ; 0x44E: 31 C0

; ──────────────────────────────────────────────────────────────────────────────
; _nt_create_thread   (0x450)
; NtCreateThreadEx wrapper
; ──────────────────────────────────────────────────────────────────────────────
_nt_create_thread:
    add rsp, 0x48                                ; 0x450: 48 83 C4 48
    ret                                          ; 0x454: C3
    ; ... (1 bytes int3 padding)
    inc eax                                      ; 0x456: FF C0
    add rsp, 0x48                                ; 0x458: 48 83 C4 48
    ret                                          ; 0x45C: C3
    ; ... (3 bytes int3 padding)
    sub rsp, 0x68                                ; 0x460: 48 83 EC 68
    mov r8, qword ptr [rip - 0x433]              ; 0x464: 4C 8B 05 CD FB FF FF
    xor rax, rax                                 ; 0x46B: 48 33 C0
    lea r9, [rsp + 0x20]                         ; 0x46E: 4C 8D 4C 24 20
    mov qword ptr [rsp + 0x80], rax              ; 0x473: 48 89 84 24 80 00 00 00
    xorps xmm0, xmm0                             ; 0x47B: 0F 57 C0
    mov qword ptr [rsp + 0x28], rax              ; 0x47E: 48 89 44 24 28
    not r8                                       ; 0x483: 49 F7 D0
    mov eax, edx                                 ; 0x486: 8B C2
    mov edx, ecx                                 ; 0x488: 8B D1
    movups xmmword ptr [rsp + 0x30], xmm0        ; 0x48A: 0F 11 44 24 30
    mov qword ptr [rsp + 0x20], rax              ; 0x48F: 48 89 44 24 20
    lea rcx, [rsp + 0x80]                        ; 0x494: 48 8D 8C 24 80 00 00 00
    movups xmmword ptr [rsp + 0x40], xmm0        ; 0x49C: 0F 11 44 24 40
    mov dword ptr [rsp + 0x30], 0x30             ; 0x4A1: C7 44 24 30 30 00 00 00
    movups xmmword ptr [rsp + 0x50], xmm0        ; 0x4A9: 0F 11 44 24 50
    mov dword ptr [rsp + 0x48], 2                ; 0x4AE: C7 44 24 48 02 00 00 00
    mov rax, qword ptr [r8]                      ; 0x4B6: 49 8B 00
    lea r8, [rsp + 0x30]                         ; 0x4B9: 4C 8D 44 24 30
    call qword ptr [rax + 0x48]                  ; 0x4BE: FF 90 48 00 00 00
    test eax, eax                                ; 0x4C4: 85 C0
    je 0x4d0                                     ; 0x4C6: 74 08
    xor eax, eax                                 ; 0x4C8: 33 C0
    add rsp, 0x68                                ; 0x4CA: 48 83 C4 68
    ret                                          ; 0x4CE: C3
    ; ... (1 bytes int3 padding)
    mov rax, qword ptr [rsp + 0x80]              ; 0x4D0: 48 8B 84 24 80 00 00 00
    add rsp, 0x68                                ; 0x4D8: 48 83 C4 68
    ret                                          ; 0x4DC: C3
    ; ... (3 bytes int3 padding)
    sub rsp, 0x38                                ; 0x4E0: 48 83 EC 38
    mov rax, qword ptr [rip - 0x4b3]             ; 0x4E4: 48 8B 05 4D FB FF FF
    not rax                                      ; 0x4EB: 48 F7 D0
    mov rax, qword ptr [rax]                     ; 0x4EE: 48 8B 00
    mov r10, qword ptr [rax + 0x30]              ; 0x4F1: 4C 8B 50 30
    lea rax, [rsp + 0x60]                        ; 0x4F5: 48 8D 44 24 60
    mov qword ptr [rsp + 0x20], rax              ; 0x4FA: 48 89 44 24 20
    call r10                                     ; 0x4FF: 41 FF D2
    test eax, eax                                ; 0x502: 85 C0
    je 0x50e                                     ; 0x504: 74 08
    xor eax, eax                                 ; 0x506: 31 C0
    add rsp, 0x38                                ; 0x508: 48 83 C4 38
    ret                                          ; 0x50C: C3
    ; ... (1 bytes int3 padding)
    inc eax                                      ; 0x50E: FF C0
    add rsp, 0x38                                ; 0x510: 48 83 C4 38
    ret                                          ; 0x514: C3
    ; ... (11 bytes int3 padding)

; ──────────────────────────────────────────────────────────────────────────────
; _nt_waitforsingle   (0x520)
; NtWaitForSingleObject-like / check HWND
; ──────────────────────────────────────────────────────────────────────────────
_nt_waitforsingle:
    push rbx                                     ; 0x520: 40 53
    sub rsp, 0x20                                ; 0x522: 48 83 EC 20
    mov rdx, qword ptr [rip - 0x4f5]             ; 0x526: 48 8B 15 0B FB FF FF
    mov ebx, ecx                                 ; 0x52D: 8B D9
    imul rcx, rbx, -0x2710                       ; 0x52F: 48 69 CB F0 D8 FF FF
    not rdx                                      ; 0x536: 48 F7 D2
    mov rdx, qword ptr [rdx]                     ; 0x539: 48 8B 12
    mov qword ptr [rsp + 0x38], rcx              ; 0x53C: 48 89 4C 24 38
    xor ecx, ecx                                 ; 0x541: 33 C9
    mov rax, qword ptr [rdx + 0x68]              ; 0x543: 48 8B 42 68
    lea rdx, [rsp + 0x38]                        ; 0x547: 48 8D 54 24 38
    call rax                                     ; 0x54C: FF D0
    add rsp, 0x20                                ; 0x54E: 48 83 C4 20
    pop rbx                                      ; 0x552: 5B
    ret                                          ; 0x553: C3
    ; ... (12 bytes int3 padding)

; ──────────────────────────────────────────────────────────────────────────────
; PowerSaveSet_Func   (0x560)
; POWERSAVESET_FUNC_VA – optional power-save WndClass setter
; ──────────────────────────────────────────────────────────────────────────────
PowerSaveSet_Func:
    push rbx                                     ; 0x560: 40 53
    sub rsp, 0x30                                ; 0x562: 48 83 EC 30
    mov ebx, ecx                                 ; 0x566: 89 CB
    call qword ptr [rip - 0x4de]                 ; 0x568: FF 15 22 FB FF FF
    movabs rcx, 0                                ; 0x56E: 48 B9 00 00 00 00 00 00 00 00
    cmp qword ptr [rcx], rax                     ; 0x578: 48 39 01
    mov eax, 0xa                                 ; 0x57B: B8 0A 00 00 00
    cmove eax, ebx                               ; 0x580: 2E 0F 44 C3
    add rsp, 0x30                                ; 0x584: 48 83 C4 30
    pop rbx                                      ; 0x588: 5B
    ret                                          ; 0x589: C3
    ; ... (22 bytes int3 padding)

; ──────────────────────────────────────────────────────────────────────────────
; _GetProcAddress_custom   (0x5A0)
; Custom GetProcAddress – walk export table by name hash
; ──────────────────────────────────────────────────────────────────────────────
_GetProcAddress_custom:
    mov qword ptr [rsp + 0x20], rsi              ; 0x5A0: 48 89 74 24 20
    push rdi                                     ; 0x5A5: 57
    push r13                                     ; 0x5A6: 41 55
    push r14                                     ; 0x5A8: 41 56
    push r15                                     ; 0x5AA: 41 57
    mov rsi, rdx                                 ; 0x5AC: 48 8B F2
    mov r9, rcx                                  ; 0x5AF: 4C 8B C9
    test rcx, rcx                                ; 0x5B2: 48 85 C9
    je 0x6fe                                     ; 0x5B5: 0F 84 43 01 00 00
    test rdx, rdx                                ; 0x5BB: 48 85 D2
    je 0x6fe                                     ; 0x5BE: 0F 84 3A 01 00 00
    mov eax, 0x5a4d                              ; 0x5C4: B8 4D 5A 00 00
    cmp word ptr [rcx], ax                       ; 0x5C9: 66 39 01
    jne 0x6fe                                    ; 0x5CC: 0F 85 2C 01 00 00
    mov eax, dword ptr [rcx + 0x3c]              ; 0x5D2: 8B 41 3C
    cmp dword ptr [rax + rcx], 0x4550            ; 0x5D5: 81 3C 08 50 45 00 00
    jne 0x6fe                                    ; 0x5DC: 0F 85 1C 01 00 00
    mov r15d, dword ptr [rax + rcx + 0x88]       ; 0x5E2: 44 8B BC 08 88 00 00 00
    test r15d, r15d                              ; 0x5EA: 45 85 FF
    je 0x6fe                                     ; 0x5ED: 0F 84 0B 01 00 00
    mov r13d, dword ptr [rax + rcx + 0x8c]       ; 0x5F3: 44 8B AC 08 8C 00 00 00
    mov r14d, 0xffffffff                         ; 0x5FB: 41 BE FF FF FF FF
    lea rdi, [rcx + r15]                         ; 0x601: 4A 8D 3C 39
    cmp rdx, 0xffff                              ; 0x605: 48 81 FA FF FF 00 00
    ja 0x628                                     ; 0x60C: 77 1A
    sub esi, dword ptr [rdi + 0x10]              ; 0x60E: 2B 77 10
    cmp esi, dword ptr [rdi + 0x14]              ; 0x611: 3B 77 14
    jae 0x6fe                                    ; 0x614: 0F 83 E4 00 00 00
    mov eax, dword ptr [rdi + 0x1c]              ; 0x61A: 8B 47 1C
    add rax, rcx                                 ; 0x61D: 48 03 C1
    mov edx, dword ptr [rax + rsi*4]             ; 0x620: 8B 14 B0
    jmp 0x6db                                    ; 0x623: E9 B3 00 00 00
    mov r10d, dword ptr [rdi + 0x18]             ; 0x628: 44 8B 57 18
    test r10d, r10d                              ; 0x62C: 45 85 D2
    je 0x6c9                                     ; 0x62F: 0F 84 94 00 00 00
    mov qword ptr [rsp + 0x38], r12              ; 0x635: 4C 89 64 24 38
    xor r11d, r11d                               ; 0x63A: 45 33 DB
    mov r12d, dword ptr [rdi + 0x20]             ; 0x63D: 44 8B 67 20
    add r12, r9                                  ; 0x641: 4D 03 E1
    sub r10d, 1                                  ; 0x644: 41 83 EA 01
    js 0x6c4                                     ; 0x648: 78 7A
    mov qword ptr [rsp + 0x28], rbx              ; 0x64A: 48 89 5C 24 28
    mov qword ptr [rsp + 0x30], rbp              ; 0x64F: 48 89 6C 24 30
    nop word ptr [rax + rax]                     ; 0x654: 66 66 66 66 0F 1F 84 00 00 00 00 00
    lea ebx, [r10 + r11]                         ; 0x660: 43 8D 1C 1A
    mov r8, rsi                                  ; 0x664: 4C 8B C6
    sar ebx, 1                                   ; 0x667: D1 FB
    mov eax, dword ptr [r12 + rbx*4]             ; 0x669: 41 8B 04 9C
    add rax, r9                                  ; 0x66D: 49 03 C1
    sub r8, rax                                  ; 0x670: 4C 2B C0
    nop word ptr [rax + rax]                     ; 0x673: 66 66 66 66 66 0F 1F 84 00 00 00 00 00
    movzx ecx, byte ptr [r8 + rax]               ; 0x680: 41 0F B6 0C 00
    movzx edx, byte ptr [rax]                    ; 0x685: 0F B6 10
    lea rax, [rax + 1]                           ; 0x688: 48 8D 40 01
    test cl, cl                                  ; 0x68C: 84 C9
    je 0x694                                     ; 0x68E: 74 04
    cmp cl, dl                                   ; 0x690: 3A CA
    je 0x680                                     ; 0x692: 74 EC
    cmp cl, dl                                   ; 0x694: 3A CA
    jae 0x69e                                    ; 0x696: 73 06
    lea r10d, [rbx - 1]                          ; 0x698: 44 8D 53 FF
    jmp 0x6b5                                    ; 0x69C: EB 17
    jbe 0x6a6                                    ; 0x69E: 76 06
    lea r11d, [rbx + 1]                          ; 0x6A0: 44 8D 5B 01
    jmp 0x6b5                                    ; 0x6A4: EB 0F
    mov ecx, dword ptr [rdi + 0x24]              ; 0x6A6: 8B 4F 24
    lea r11d, [r10 + 1]                          ; 0x6A9: 45 8D 5A 01
    add rcx, r9                                  ; 0x6AD: 49 03 C9
    movzx r14d, word ptr [rcx + rbx*2]           ; 0x6B0: 44 0F B7 34 59
    cmp r11d, r10d                               ; 0x6B5: 45 3B DA
    jle 0x660                                    ; 0x6B8: 7E A6
    mov rbp, qword ptr [rsp + 0x30]              ; 0x6BA: 48 8B 6C 24 30
    mov rbx, qword ptr [rsp + 0x28]              ; 0x6BF: 48 8B 5C 24 28
    mov r12, qword ptr [rsp + 0x38]              ; 0x6C4: 4C 8B 64 24 38
    cmp r14d, dword ptr [rdi + 0x14]             ; 0x6C9: 44 3B 77 14
    jae 0x6fe                                    ; 0x6CD: 73 2F
    mov eax, dword ptr [rdi + 0x1c]              ; 0x6CF: 8B 47 1C
    add rax, r9                                  ; 0x6D2: 49 03 C1
    mov ecx, r14d                                ; 0x6D5: 41 8B CE
    mov edx, dword ptr [rax + rcx*4]             ; 0x6D8: 8B 14 88
    test edx, edx                                ; 0x6DB: 85 D2
    je 0x6fe                                     ; 0x6DD: 74 1F
    cmp edx, r15d                                ; 0x6DF: 41 3B D7
    jb 0x6ec                                     ; 0x6E2: 72 08
    lea eax, [r15 + r13]                         ; 0x6E4: 43 8D 04 2F
    cmp edx, eax                                 ; 0x6E8: 3B D0
    jb 0x6fe                                     ; 0x6EA: 72 12
    mov eax, edx                                 ; 0x6EC: 8B C2
    add rax, r9                                  ; 0x6EE: 49 03 C1
    mov rsi, qword ptr [rsp + 0x40]              ; 0x6F1: 48 8B 74 24 40
    pop r15                                      ; 0x6F6: 41 5F
    pop r14                                      ; 0x6F8: 41 5E
    pop r13                                      ; 0x6FA: 41 5D
    pop rdi                                      ; 0x6FC: 5F
    ret                                          ; 0x6FD: C3
    mov rsi, qword ptr [rsp + 0x40]              ; 0x6FE: 48 8B 74 24 40
    xor eax, eax                                 ; 0x703: 33 C0
    pop r15                                      ; 0x705: 41 5F
    pop r14                                      ; 0x707: 41 5E
    pop r13                                      ; 0x709: 41 5D
    pop rdi                                      ; 0x70B: 5F
    ret                                          ; 0x70C: C3
    ; ... (19 bytes int3 padding)

; ──────────────────────────────────────────────────────────────────────────────
; _pe_loader_setup   (0x720)
; PE loader prologue – walk PEB InLoadOrderModuleList
; ──────────────────────────────────────────────────────────────────────────────
_pe_loader_setup:
    mov r11, rsp                                 ; 0x720: 4C 8B DC
    push rbp                                     ; 0x723: 55
    push rsi                                     ; 0x724: 56
    push rdi                                     ; 0x725: 57
    lea rbp, [r11 - 0x48]                        ; 0x726: 49 8D 6B B8
    sub rsp, 0x130                               ; 0x72A: 48 81 EC 30 01 00 00
    mov eax, dword ptr [rcx]                     ; 0x731: 8B 01
    mov rsi, r8                                  ; 0x733: 49 8B F0
    mov rcx, qword ptr gs:[rax]                  ; 0x736: 65 48 8B 08
    mov rax, qword ptr [rcx + 0x18]              ; 0x73A: 48 8B 41 18
    mov rcx, qword ptr [rax + 0x20]              ; 0x73E: 48 8B 48 20
    mov rax, qword ptr [rcx]                     ; 0x742: 48 8B 01
    mov rdi, qword ptr [rax + 0x20]              ; 0x745: 48 8B 78 20
    test rdi, rdi                                ; 0x749: 48 85 FF
    je 0xf14                                     ; 0x74C: 0F 84 C2 07 00 00
    mov rax, qword ptr [rax]                     ; 0x752: 48 8B 00
    cmp qword ptr [rax + 0x20], 0                ; 0x755: 48 83 78 20 00
    je 0xf14                                     ; 0x75A: 0F 84 B4 07 00 00
    mov qword ptr [r11 + 8], rbx                 ; 0x760: 49 89 5B 08
    mov qword ptr [r11 + 0x10], r14              ; 0x764: 4D 89 73 10
    xor r14d, r14d                               ; 0x768: 45 33 F6
    mov ebx, edx                                 ; 0x76B: 8B DA
    test edx, edx                                ; 0x76D: 85 D2
    jne 0x7b7                                    ; 0x76F: 75 46
    movabs rax, 0x8b9a98a09a919688               ; 0x771: 48 B8 88 96 91 9A A0 98 9A 8B
    lea rcx, [rsp + 0x38]                        ; 0x77B: 48 8D 4C 24 38
    mov qword ptr [rsp + 0x38], rax              ; 0x780: 48 89 44 24 38
    mov dl, 2                                    ; 0x785: B2 02
    movabs rax, 0x9190968c8d9a89a0               ; 0x787: 48 B8 A0 89 9A 8D 8C 96 90 91
    mov qword ptr [rsp + 0x40], rax              ; 0x791: 48 89 44 24 40
    call 0xf40                                   ; 0x796: E8 A5 07 00 00
    lea rdx, [rsp + 0x38]                        ; 0x79B: 48 8D 54 24 38
    mov qword ptr [rsp + 0x48], r14              ; 0x7A0: 4C 89 74 24 48
    mov rcx, rdi                                 ; 0x7A5: 48 8B CF
    call 0x5a0                                   ; 0x7A8: E8 F3 FD FF FF  ; -> _GetProcAddress_custom
    test rax, rax                                ; 0x7AD: 48 85 C0
    je 0x7b7                                     ; 0x7B0: 74 05
    call rax                                     ; 0x7B2: FF D0
    mov rbx, qword ptr [rax]                     ; 0x7B4: 48 8B 18
    movabs rax, 0x9e9c909393be8bb1               ; 0x7B7: 48 B8 B1 8B BE 93 93 90 9C 9E
    lea rcx, [rsp + 0x38]                        ; 0x7C1: 48 8D 4C 24 38
    mov qword ptr [rsp + 0x38], rax              ; 0x7C6: 48 89 44 24 38
    mov dl, 3                                    ; 0x7CB: B2 03
    movabs rax, 0x9e8a8b8d96a99a8b               ; 0x7CD: 48 B8 8B 9A A9 96 8D 8B 8A 9E
    mov qword ptr [rsp + 0x40], rax              ; 0x7D7: 48 89 44 24 40
    movabs rax, 0x32868d90929ab293               ; 0x7DC: 48 B8 93 B2 9A 92 90 8D 86 32
    mov qword ptr [rsp + 0x48], rax              ; 0x7E6: 48 89 44 24 48
    call 0xf40                                   ; 0x7EB: E8 50 07 00 00
    lea rdx, [rsp + 0x38]                        ; 0x7F0: 48 8D 54 24 38
    mov byte ptr [rsp + 0x4f], r14b              ; 0x7F5: 44 88 74 24 4F
    mov rcx, rdi                                 ; 0x7FA: 48 8B CF
    call 0x5a0                                   ; 0x7FD: E8 9E FD FF FF  ; -> _GetProcAddress_custom
    test rax, rax                                ; 0x802: 48 85 C0
    je 0x81d                                     ; 0x805: 74 16
    test rbx, rbx                                ; 0x807: 48 85 DB
    jne 0x824                                    ; 0x80A: 75 18
    lea rdx, [rbp - 0x14]                        ; 0x80C: 48 8D 55 EC
    mov rcx, rax                                 ; 0x810: 48 8B C8
    call 0xf70                                   ; 0x813: E8 58 07 00 00
    cmp eax, 1                                   ; 0x818: 83 F8 01
    je 0x828                                     ; 0x81B: 74 0B
    mov eax, 0xc002                              ; 0x81D: B8 02 C0 00 00
    jmp 0x8a3                                    ; 0x822: EB 7F
    mov qword ptr [rbp - 0x78], rax              ; 0x824: 48 89 45 88
    movabs rax, 0x96a99a9a8db98bb1               ; 0x828: 48 B8 B1 8B B9 8D 9A 9A A9 96
    mov qword ptr [rsp + 0x160], r15             ; 0x832: 4C 89 BC 24 60 01 00 00
    mov qword ptr [rsp + 0x38], rax              ; 0x83A: 48 89 44 24 38
    lea rcx, [rsp + 0x38]                        ; 0x83F: 48 8D 4C 24 38
    movabs rax, 0x9ab2939ee6868d90               ; 0x844: 48 B8 90 8D 86 E6 9E 93 B2 9A
    movabs r15, 0x929ab2939e8a8b8d               ; 0x84E: 49 BF 8D 8B 8A 9E 93 B2 9A 92
    mov dl, 3                                    ; 0x858: B2 03
    mov qword ptr [rsp + 0x48], rax              ; 0x85A: 48 89 44 24 48
    mov qword ptr [rsp + 0x40], r15              ; 0x85F: 4C 89 7C 24 40
    call 0xf40                                   ; 0x864: E8 D7 06 00 00
    lea rdx, [rsp + 0x38]                        ; 0x869: 48 8D 54 24 38
    mov byte ptr [rsp + 0x4b], r14b              ; 0x86E: 44 88 74 24 4B
    mov rcx, rdi                                 ; 0x873: 48 8B CF
    call 0x5a0                                   ; 0x876: E8 25 FD FF FF  ; -> _GetProcAddress_custom
    test rax, rax                                ; 0x87B: 48 85 C0
    je 0x896                                     ; 0x87E: 74 16
    test rbx, rbx                                ; 0x880: 48 85 DB
    jne 0x8be                                    ; 0x883: 75 39
    lea rdx, [rbp - 0x10]                        ; 0x885: 48 8D 55 F0
    mov rcx, rax                                 ; 0x889: 48 8B C8
    call 0xf70                                   ; 0x88C: E8 DF 06 00 00
    cmp eax, 1                                   ; 0x891: 83 F8 01
    je 0x8c2                                     ; 0x894: 74 2C
    mov eax, 0xc003                              ; 0x896: B8 03 C0 00 00
    mov r15, qword ptr [rsp + 0x160]             ; 0x89B: 4C 8B BC 24 60 01 00 00
    mov rbx, qword ptr [rsp + 0x150]             ; 0x8A3: 48 8B 9C 24 50 01 00 00
    mov r14, qword ptr [rsp + 0x158]             ; 0x8AB: 4C 8B B4 24 58 01 00 00
    add rsp, 0x130                               ; 0x8B3: 48 81 C4 30 01 00 00
    pop rdi                                      ; 0x8BA: 5F
    pop rsi                                      ; 0x8BB: 5E
    pop rbp                                      ; 0x8BC: 5D
    ret                                          ; 0x8BD: C3
    mov qword ptr [rbp - 0x70], rax              ; 0x8BE: 48 89 45 90
    movabs rax, 0x96a99b9e9aad8bb1               ; 0x8C2: 48 B8 B1 8B AD 9A 9E 9B A9 96
    mov qword ptr [rsp + 0x40], r15              ; 0x8CC: 4C 89 7C 24 40
    mov qword ptr [rsp + 0x38], rax              ; 0x8D1: 48 89 44 24 38
    lea rcx, [rsp + 0x38]                        ; 0x8D6: 48 8D 4C 24 38
    movabs rax, 0x8ab92293f7868d90               ; 0x8DB: 48 B8 90 8D 86 F7 93 22 B9 8A
    mov dl, 3                                    ; 0x8E5: B2 03
    mov qword ptr [rsp + 0x48], rax              ; 0x8E7: 48 89 44 24 48
    call 0xf40                                   ; 0x8EC: E8 4F 06 00 00
    lea rdx, [rsp + 0x38]                        ; 0x8F1: 48 8D 54 24 38
    mov byte ptr [rsp + 0x4b], r14b              ; 0x8F6: 44 88 74 24 4B
    mov rcx, rdi                                 ; 0x8FB: 48 8B CF
    call 0x5a0                                   ; 0x8FE: E8 9D FC FF FF  ; -> _GetProcAddress_custom
    test rax, rax                                ; 0x903: 48 85 C0
    je 0x91e                                     ; 0x906: 74 16
    test rbx, rbx                                ; 0x908: 48 85 DB
    jne 0x928                                    ; 0x90B: 75 1B
    lea rdx, [rbp - 8]                           ; 0x90D: 48 8D 55 F8
    mov rcx, rax                                 ; 0x911: 48 8B C8
    call 0xf70                                   ; 0x914: E8 57 06 00 00
    cmp eax, 1                                   ; 0x919: 83 F8 01
    je 0x92c                                     ; 0x91C: 74 0E
    mov eax, 0xc004                              ; 0x91E: B8 04 C0 00 00
    jmp 0x89b                                    ; 0x923: E9 73 FF FF FF
    mov qword ptr [rbp - 0x60], rax              ; 0x928: 48 89 45 A0
    movabs rax, 0x9c9a8b908daf8bb1               ; 0x92C: 48 B8 B1 8B AF 8D 90 8B 9A 9C
    lea rcx, [rsp + 0x38]                        ; 0x936: 48 8D 4C 24 38
    mov qword ptr [rsp + 0x38], rax              ; 0x93B: 48 89 44 24 38
    mov dl, 3                                    ; 0x940: B2 03
    movabs rax, 0x939e8a8b8d96a98b               ; 0x942: 48 B8 8B A9 96 8D 8B 8A 9E 93
    mov qword ptr [rsp + 0x40], rax              ; 0x94C: 48 89 44 24 40
    movabs rax, 0xafe9868d90929ab2               ; 0x951: 48 B8 B2 9A 92 90 8D 86 E9 AF
    mov qword ptr [rsp + 0x48], rax              ; 0x95B: 48 89 44 24 48
    call 0xf40                                   ; 0x960: E8 DB 05 00 00
    lea rdx, [rsp + 0x38]                        ; 0x965: 48 8D 54 24 38
    mov byte ptr [rsp + 0x4e], r14b              ; 0x96A: 44 88 74 24 4E
    mov rcx, rdi                                 ; 0x96F: 48 8B CF
    call 0x5a0                                   ; 0x972: E8 29 FC FF FF  ; -> _GetProcAddress_custom
    test rax, rax                                ; 0x977: 48 85 C0
    je 0x992                                     ; 0x97A: 74 16
    test rbx, rbx                                ; 0x97C: 48 85 DB
    jne 0x99c                                    ; 0x97F: 75 1B
    lea rdx, [rbp - 4]                           ; 0x981: 48 8D 55 FC
    mov rcx, rax                                 ; 0x985: 48 8B C8
    call 0xf70                                   ; 0x988: E8 E3 05 00 00
    cmp eax, 1                                   ; 0x98D: 83 F8 01
    je 0x9a0                                     ; 0x990: 74 0E
    mov eax, 0xc006                              ; 0x992: B8 06 C0 00 00
    jmp 0x89b                                    ; 0x997: E9 FF FE FF FF
    mov qword ptr [rbp - 0x58], rax              ; 0x99C: 48 89 45 A8
    movabs rax, 0x8daf919a8fb08bb1               ; 0x9A0: 48 B8 B1 8B B0 8F 9A 91 AF 8D
    lea rcx, [rsp + 0x60]                        ; 0x9AA: 48 8D 4C 24 60
    mov qword ptr [rsp + 0x60], rax              ; 0x9AF: 48 89 44 24 60
    mov dl, 2                                    ; 0x9B4: B2 02
    movabs rax, 0xa2bf1a8c8c9a9c90               ; 0x9B6: 48 B8 90 9C 9A 8C 8C 1A BF A2
    mov qword ptr [rsp + 0x68], rax              ; 0x9C0: 48 89 44 24 68
    call 0xf40                                   ; 0x9C5: E8 76 05 00 00
    lea rdx, [rsp + 0x60]                        ; 0x9CA: 48 8D 54 24 60
    mov byte ptr [rsp + 0x6d], r14b              ; 0x9CF: 44 88 74 24 6D
    mov rcx, rdi                                 ; 0x9D4: 48 8B CF
    call 0x5a0                                   ; 0x9D7: E8 C4 FB FF FF  ; -> _GetProcAddress_custom
    test rax, rax                                ; 0x9DC: 48 85 C0
    je 0x9f7                                     ; 0x9DF: 74 16
    test rbx, rbx                                ; 0x9E1: 48 85 DB
    jne 0xa01                                    ; 0x9E4: 75 1B
    lea rdx, [rbp + 4]                           ; 0x9E6: 48 8D 55 04
    mov rcx, rax                                 ; 0x9EA: 48 8B C8
    call 0xf70                                   ; 0x9ED: E8 7E 05 00 00
    cmp eax, 1                                   ; 0x9F2: 83 F8 01
    je 0xa05                                     ; 0x9F5: 74 0E
    mov eax, 0xc008                              ; 0x9F7: B8 08 C0 00 00
    jmp 0x89b                                    ; 0x9FC: E9 9A FE FF FF
    mov qword ptr [rbp - 0x48], rax              ; 0xA01: 48 89 45 B8
    movabs rax, 0xba869e939abb8bb1               ; 0xA05: 48 B8 B1 8B BB 9A 93 9E 86 BA
    lea rcx, [rbp + 0x18]                        ; 0xA0F: 48 8D 4D 18
    mov qword ptr [rbp + 0x18], rax              ; 0xA13: 48 89 45 18
    mov dl, 2                                    ; 0xA17: B2 02
    movabs rax, 0x9190968b8a9c9a87               ; 0xA19: 48 B8 87 9A 9C 8A 8B 96 90 91
    mov qword ptr [rbp + 0x20], rax              ; 0xA23: 48 89 45 20
    call 0xf40                                   ; 0xA27: E8 14 05 00 00
    lea rdx, [rbp + 0x18]                        ; 0xA2C: 48 8D 55 18
    mov qword ptr [rbp + 0x28], r14              ; 0xA30: 4C 89 75 28
    mov rcx, rdi                                 ; 0xA34: 48 8B CF
    call 0x5a0                                   ; 0xA37: E8 64 FB FF FF  ; -> _GetProcAddress_custom
    test rax, rax                                ; 0xA3C: 48 85 C0
    je 0xf0a                                     ; 0xA3F: 0F 84 C5 04 00 00
    mov qword ptr [rbp - 0x28], rax              ; 0xA45: 48 89 45 D8
    test rbx, rbx                                ; 0xA49: 48 85 DB
    jne 0xe50                                    ; 0xA4C: 0F 85 FE 03 00 00
    mov ecx, dword ptr [rax + 0x12]              ; 0xA52: 8B 48 12
    lea r8, [rax + 0x12]                         ; 0xA55: 4C 8D 40 12
    and ecx, 0xffffff                            ; 0xA59: 81 E1 FF FF FF 00
    cmp ecx, 0xc3050f                            ; 0xA5F: 81 F9 0F 05 C3 00
    je 0xa7e                                     ; 0xA65: 74 17
    lea r8, [rax + 8]                            ; 0xA67: 4C 8D 40 08
    mov eax, dword ptr [rax + 8]                 ; 0xA6B: 8B 40 08
    and eax, 0xffffff                            ; 0xA6E: 25 FF FF FF 00
    cmp eax, 0xc3050f                            ; 0xA73: 3D 0F 05 C3 00
    jne 0xf0a                                    ; 0xA78: 0F 85 8C 04 00 00
    mov eax, dword ptr [rbp - 0x14]              ; 0xA7E: 8B 45 EC
    mov qword ptr [rsp + 0x40], rax              ; 0xA81: 48 89 44 24 40
    nop word ptr [rax + rax]                     ; 0xA86: 66 66 0F 1F 84 00 00 00 00 00
    rdtsc                                        ; 0xA90: 0F 31
    shl rdx, 0x20                                ; 0xA92: 48 C1 E2 20
    or rax, rdx                                  ; 0xA96: 48 0B C2
    mov rcx, rax                                 ; 0xA99: 48 8B C8
    and ecx, 0x7ff                               ; 0xA9C: 81 E1 FF 07 00 00
    shl rcx, 4                                   ; 0xAA2: 48 C1 E1 04
    add rcx, r8                                  ; 0xAA6: 49 03 C8
    mov eax, dword ptr [rcx]                     ; 0xAA9: 8B 01
    and eax, 0xffffff                            ; 0xAAB: 25 FF FF FF 00
    cmp eax, 0xc3050f                            ; 0xAB0: 3D 0F 05 C3 00
    jne 0xa90                                    ; 0xAB5: 75 D9
    nop word ptr [rax + rax]                     ; 0xAB7: 66 0F 1F 84 00 00 00 00 00
    rdtsc                                        ; 0xAC0: 0F 31
    shl rdx, 0x20                                ; 0xAC2: 48 C1 E2 20
    or rax, rdx                                  ; 0xAC6: 48 0B C2
    mov rbx, rax                                 ; 0xAC9: 48 8B D8
    and ebx, 0x7ff                               ; 0xACC: 81 E3 FF 07 00 00
    shl rbx, 4                                   ; 0xAD2: 48 C1 E3 04
    add rbx, r8                                  ; 0xAD6: 49 03 D8
    mov edx, dword ptr [rbx]                     ; 0xAD9: 8B 13
    and edx, 0xffffff                            ; 0xADB: 81 E2 FF FF FF 00
    cmp edx, 0xc3050f                            ; 0xAE1: 81 FA 0F 05 C3 00
    jne 0xac0                                    ; 0xAE7: 75 D7
    not rcx                                      ; 0xAE9: 48 F7 D1
    mov dword ptr [rsp + 0x28], 4                ; 0xAEC: C7 44 24 28 04 00 00 00
    mov qword ptr [rsp + 0x38], rcx              ; 0xAF4: 48 89 4C 24 38
    lea r9, [rsp + 0x30]                         ; 0xAF9: 4C 8D 4C 24 30
    lea rcx, [rsp + 0x38]                        ; 0xAFE: 48 8D 4C 24 38
    mov qword ptr [rsp + 0x48], 0xffffffffffffffff ; 0xB03: 48 C7 44 24 48 FF FF FF FF
    xor r8d, r8d                                 ; 0xB0C: 45 33 C0
    mov qword ptr [rsp + 0x30], 0x8000           ; 0xB0F: 48 C7 44 24 30 00 80 00 00
    lea rdx, [rsp + 0x58]                        ; 0xB18: 48 8D 54 24 58
    mov qword ptr [rsp + 0x58], r14              ; 0xB1D: 4C 89 74 24 58
    mov dword ptr [rsp + 0x20], 0x3000           ; 0xB22: C7 44 24 20 00 30 00 00
    call 0x1040                                  ; 0xB2A: E8 11 05 00 00
    test eax, eax                                ; 0xB2F: 85 C0
    js 0x89b                                     ; 0xB31: 0F 88 64 FD FF FF
    mov rax, qword ptr [rsp + 0x58]              ; 0xB37: 48 8B 44 24 58
    lea rdi, [rax + 0x1000]                      ; 0xB3C: 48 8D B8 00 10 00 00
    mov qword ptr [rax], rdi                     ; 0xB43: 48 89 38
    mov r8, qword ptr [rsp + 0x58]               ; 0xB46: 4C 8B 44 24 58
    add r8, 0x2000                               ; 0xB4B: 49 81 C0 00 20 00 00
    mov dword ptr [rbp + 0x68], r14d             ; 0xB52: 44 89 75 68
    sub qword ptr [rsp + 0x30], 0x2000           ; 0xB56: 48 81 6C 24 30 00 20 00 00
    mov qword ptr [rsp + 0x60], r8               ; 0xB5F: 4C 89 44 24 60
    rdtsc                                        ; 0xB64: 0F 31
    shl rdx, 0x20                                ; 0xB66: 48 C1 E2 20
    not rbx                                      ; 0xB6A: 48 F7 D3
    or rdx, rax                                  ; 0xB6D: 48 0B D0
    lea rax, [rsp + 0x70]                        ; 0xB70: 48 8D 44 24 70
    xor rdx, rax                                 ; 0xB75: 48 33 D0
    lea rax, [rbp - 0x20]                        ; 0xB78: 48 8D 45 E0
    mov rcx, rdx                                 ; 0xB7C: 48 8B CA
    shr rcx, 0x20                                ; 0xB7F: 48 C1 E9 20
    mov r9, rcx                                  ; 0xB83: 4C 8B C9
    mov r10, rcx                                 ; 0xB86: 4C 8B D1
    xor r9, rdx                                  ; 0xB89: 4C 33 CA
    not r10d                                     ; 0xB8C: 41 F7 D2
    xor r9, rax                                  ; 0xB8F: 4C 33 C8
    movzx ecx, r9w                               ; 0xB92: 41 0F B7 C9
    xor r10d, r9d                                ; 0xB96: 45 33 D1
    mov rax, r9                                  ; 0xB99: 49 8B C1
    shr rax, 0x10                                ; 0xB9C: 48 C1 E8 10
    xor ax, r9w                                  ; 0xBA0: 66 41 33 C1
    movabs r9, 0xffffffff042444c7                ; 0xBA4: 49 B9 C7 44 24 04 FF FF FF FF
    movzx r11d, al                               ; 0xBAE: 44 0F B6 D8
    xor rax, rcx                                 ; 0xBB2: 48 33 C1
    movzx eax, al                                ; 0xBB5: 0F B6 C0
    lea rax, [rax + 0x40]                        ; 0xBB8: 48 8D 40 40
    shl r11, 4                                   ; 0xBBC: 49 C1 E3 04
    shl rax, 4                                   ; 0xBC0: 48 C1 E0 04
    add r11, r8                                  ; 0xBC4: 4D 03 D8
    lea r8, [rax + r11]                          ; 0xBC7: 4E 8D 04 18
    movzx eax, dx                                ; 0xBCB: 0F B7 C2
    not ax                                       ; 0xBCE: 66 F7 D0
    mov qword ptr [r8 + 8], rbx                  ; 0xBD1: 49 89 58 08
    xor rax, rcx                                 ; 0xBD5: 48 33 C1
    mov dword ptr [r8 + 0x10], 0x58d4850         ; 0xBD8: 41 C7 40 10 50 48 8D 05
    movzx edx, al                                ; 0xBE0: 0F B6 D0
    movabs rax, 0xb94850592414874c               ; 0xBE3: 48 B8 4C 87 14 24 59 50 48 B9
    mov qword ptr [r8], rax                      ; 0xBED: 49 89 00
    add rdx, 3                                   ; 0xBF0: 48 83 C2 03
    mov byte ptr [r8 + 0x28], 0xc3               ; 0xBF4: 41 C6 40 28 C3
    shl rdx, 4                                   ; 0xBF9: 48 C1 E2 04
    add rdx, r8                                  ; 0xBFD: 49 03 D0
    movzx ecx, r10b                              ; 0xC00: 41 0F B6 CA
    shl ecx, 4                                   ; 0xC04: C1 E1 04
    add rcx, rdx                                 ; 0xC07: 48 03 CA
    lea eax, [rcx + 0x60]                        ; 0xC0A: 8D 41 60
    sub eax, r8d                                 ; 0xC0D: 41 2B C0
    sub eax, 0x18                                ; 0xC10: 83 E8 18
    mov dword ptr [r8 + 0x14], eax               ; 0xC13: 41 89 40 14
    mov rax, rdx                                 ; 0xC17: 48 8B C2
    shl rax, 0x20                                ; 0xC1A: 48 C1 E0 20
    or rax, 0x2404c748                           ; 0xC1E: 48 0D 48 C7 04 24
    mov qword ptr [r8 + 0x18], rax               ; 0xC24: 49 89 40 18
    mov rax, rdx                                 ; 0xC28: 48 8B C2
    and rax, r9                                  ; 0xC2B: 49 23 C1
    or rax, 0x42444c7                            ; 0xC2E: 48 0D C7 44 24 04
    mov qword ptr [r8 + 0x20], rax               ; 0xC34: 49 89 40 20
    movabs rax, 0xffffff0024a48d48               ; 0xC38: 48 B8 48 8D A4 24 00 FF FF FF
    mov qword ptr [rcx + 0x60], rax              ; 0xC42: 48 89 41 60
    movabs rax, 0x22024a48d48                    ; 0xC46: 48 B8 48 8D A4 24 20 02 00 00
    mov qword ptr [rcx + 0x68], rax              ; 0xC50: 48 89 41 68
    movabs rax, 0x8b48944824048748               ; 0xC54: 48 B8 48 87 04 24 48 94 48 8B
    mov qword ptr [rcx + 0x70], rax              ; 0xC5E: 48 89 41 70
    movabs rax, 0x834800408b480868               ; 0xC62: 48 B8 68 08 48 8B 40 00 48 83
    mov qword ptr [rcx + 0x78], rax              ; 0xC6C: 48 89 41 78
    movabs rax, 0x24a48d48c48b4850               ; 0xC70: 48 B8 50 48 8B C4 48 8D A4 24
    mov dword ptr [rcx + 0x80], 0xccc310c4       ; 0xC7A: C7 81 80 00 00 00 C4 10 C3 CC
    mov qword ptr [rdx], rax                     ; 0xC84: 48 89 42 00
    movabs rax, 0x242c8748fffff980               ; 0xC88: 48 B8 80 F9 FF FF 48 87 2C 24
    mov qword ptr [rdx + 8], rax                 ; 0xC92: 48 89 42 08
    movabs rax, 0x2404894808ec8348               ; 0xC96: 48 B8 48 83 EC 08 48 89 04 24
    mov qword ptr [rdx + 0x10], rax              ; 0xCA0: 48 89 42 10
    movabs rax, 0xfffffee024a48d48               ; 0xCA4: 48 B8 48 8D A4 24 E0 FE FF FF
    mov qword ptr [rdx + 0x18], rax              ; 0xCAE: 48 89 42 18
    movabs rax, 0x8408d48288930ff                ; 0xCB2: 48 B8 FF 30 89 28 48 8D 40 08
    mov qword ptr [rdx + 0x20], rax              ; 0xCBC: 48 89 42 20
    movabs rax, 0x2444110f3040100f               ; 0xCC0: 48 B8 0F 10 40 30 0F 11 44 24
    mov qword ptr [rdx + 0x28], rax              ; 0xCCA: 48 89 42 28
    movabs rax, 0x44110f4040100f28               ; 0xCCE: 48 B8 28 0F 10 40 40 0F 11 44
    mov qword ptr [rdx + 0x30], rax              ; 0xCD8: 48 89 42 30
    movabs rax, 0x110f5040100f3824               ; 0xCDC: 48 B8 24 38 0F 10 40 50 0F 11
    mov qword ptr [rdx + 0x38], rax              ; 0xCE6: 48 89 42 38
    movabs rax, 0xf6040100f482444                ; 0xCEA: 48 B8 44 24 48 0F 10 40 60 0F
    mov qword ptr [rdx + 0x40], rax              ; 0xCF4: 48 89 42 40
    movabs r9, 0xcccce1ffd1f74844                ; 0xCF8: 49 B9 44 48 F7 D1 FF E1 CC CC
    movabs rax, 0x40874858244411                 ; 0xD02: 48 B8 11 44 24 58 48 87 40 00
    mov qword ptr [rdx + 0x48], rax              ; 0xD0C: 48 89 42 48
    mov qword ptr [rdx + 0x50], r9               ; 0xD10: 4C 89 4A 50
    mov rcx, r11                                 ; 0xD14: 4C 89 D9
    not r8                                       ; 0xD17: 49 F7 D0
    movabs rax, 0xcccccccccccccccc               ; 0xD1A: 48 B8 CC CC CC CC CC CC CC CC
    mov qword ptr [rcx + 0x18], rax              ; 0xD24: 48 89 41 18
    movabs rax, 0xb948ffffffffb851               ; 0xD28: 48 B8 51 B8 FF FF FF FF 48 B9
    mov qword ptr [rcx], rax                     ; 0xD32: 48 89 41 00
    mov qword ptr [rcx + 8], r8                  ; 0xD36: 4C 89 41 08
    mov qword ptr [rcx + 0x10], r9               ; 0xD3A: 4C 89 49 10
    movdqu xmm0, xmmword ptr [rcx]               ; 0xD3E: F3 0F 6F 01
    movdqu xmm1, xmmword ptr [r11 + 0x10]        ; 0xD42: F3 41 0F 6F 4B 10
    movdqu xmmword ptr [rcx + 0x20], xmm0        ; 0xD48: F3 0F 7F 41 20
    movdqu xmmword ptr [rcx + 0x30], xmm1        ; 0xD4D: F3 0F 7F 49 30
    movdqu xmmword ptr [rcx + 0x40], xmm0        ; 0xD52: F3 0F 7F 41 40
    movdqu xmmword ptr [rcx + 0x50], xmm1        ; 0xD57: F3 0F 7F 49 50
    movdqu xmmword ptr [rcx + 0x60], xmm0        ; 0xD5C: F3 0F 7F 41 60
    movdqu xmmword ptr [rcx + 0x70], xmm1        ; 0xD61: F3 0F 7F 49 70
    mov r9d, 0x20                                ; 0xD66: 41 B9 20 00 00 00
    lea rdx, [rsp + 0x60]                        ; 0xD6C: 48 8D 54 24 60
    lea r8, [rsp + 0x30]                         ; 0xD71: 4C 8D 44 24 30
    nop                                          ; 0xD76: 90
    mov eax, dword ptr [rbp - 0x14]              ; 0xD77: 8B 45 EC
    mov dword ptr [rcx + 2], eax                 ; 0xD7A: 89 41 02
    mov eax, dword ptr [rbp + 4]                 ; 0xD7D: 8B 45 04
    mov qword ptr [rbp - 0x78], rcx              ; 0xD80: 48 89 4D 88
    add rcx, 0x20                                ; 0xD84: 48 83 C1 20
    mov dword ptr [rcx + 2], eax                 ; 0xD88: 89 41 02
    mov eax, dword ptr [rbp - 4]                 ; 0xD8B: 8B 45 FC
    mov qword ptr [rbp - 0x48], rcx              ; 0xD8E: 48 89 4D B8
    add rcx, 0x20                                ; 0xD92: 48 83 C1 20
    mov dword ptr [rcx + 2], eax                 ; 0xD96: 89 41 02
    mov eax, dword ptr [rbp - 8]                 ; 0xD99: 8B 45 F8
    mov qword ptr [rbp - 0x58], rcx              ; 0xD9C: 48 89 4D A8
    add rcx, 0x20                                ; 0xDA0: 48 83 C1 20
    mov dword ptr [rcx + 2], eax                 ; 0xDA4: 89 41 02
    mov eax, dword ptr [rbp - 4]                 ; 0xDA7: 8B 45 FC
    mov qword ptr [rsp + 0x40], rax              ; 0xDAA: 48 89 44 24 40
    lea rax, [rbp + 0x68]                        ; 0xDAF: 48 8D 45 68
    mov qword ptr [rbp - 0x60], rcx              ; 0xDB3: 48 89 4D A0
    lea rcx, [rsp + 0x38]                        ; 0xDB7: 48 8D 4C 24 38
    mov qword ptr [rsp + 0x20], rax              ; 0xDBC: 48 89 44 24 20
    notrack call 0x1040                          ; 0xDC1: 3E 3E E8 78 02 00 00
    test eax, eax                                ; 0xDC8: 85 C0
    js 0x89b                                     ; 0xDCA: 0F 88 CB FA FF FF
    movaps xmm0, xmmword ptr [rsp + 0x70]        ; 0xDD0: 0F 28 44 24 70
    lea rax, [rbp + 0x68]                        ; 0xDD5: 48 8D 45 68
    mov qword ptr [rsp + 0x30], 0x2000           ; 0xDD9: 48 C7 44 24 30 00 20 00 00
    lea r8, [rsp + 0x30]                         ; 0xDE2: 4C 8D 44 24 30
    movups xmmword ptr [rdi], xmm0               ; 0xDE7: 0F 11 07
    lea rdx, [rsp + 0x58]                        ; 0xDEA: 48 8D 54 24 58
    mov r9d, 2                                   ; 0xDEF: 41 B9 02 00 00 00
    movaps xmm1, xmmword ptr [rbp - 0x80]        ; 0xDF5: 0F 28 4D 80
    lea rcx, [rsp + 0x38]                        ; 0xDF9: 48 8D 4C 24 38
    movups xmmword ptr [rdi + 0x10], xmm1        ; 0xDFE: 0F 11 4F 10
    mov qword ptr [rsp + 0x20], rax              ; 0xE02: 48 89 44 24 20
    movaps xmm0, xmmword ptr [rbp - 0x70]        ; 0xE07: 0F 28 45 90
    movups xmmword ptr [rdi + 0x20], xmm0        ; 0xE0B: 0F 11 47 20
    movaps xmm1, xmmword ptr [rbp - 0x60]        ; 0xE0F: 0F 28 4D A0
    movups xmmword ptr [rdi + 0x30], xmm1        ; 0xE13: 0F 11 4F 30
    movaps xmm0, xmmword ptr [rbp - 0x50]        ; 0xE17: 0F 28 45 B0
    movups xmmword ptr [rdi + 0x40], xmm0        ; 0xE1B: 0F 11 47 40
    movaps xmm1, xmmword ptr [rbp - 0x40]        ; 0xE1F: 0F 28 4D C0
    movups xmmword ptr [rdi + 0x50], xmm1        ; 0xE23: 0F 11 4F 50
    movaps xmm0, xmmword ptr [rbp - 0x30]        ; 0xE27: 0F 28 45 D0
    movups xmmword ptr [rdi + 0x60], xmm0        ; 0xE2B: 0F 11 47 60
    call 0x1040                                  ; 0xE2F: E8 0C 02 00 00
    test eax, eax                                ; 0xE34: 85 C0
    js 0x89b                                     ; 0xE36: 0F 88 5F FA FF FF
    mov rax, qword ptr [rsp + 0x58]              ; 0xE3C: 48 8B 44 24 58
    not rax                                      ; 0xE41: 48 F7 D0
    mov qword ptr [rsi], rax                     ; 0xE44: 48 89 06
    xor eax, eax                                 ; 0xE47: 33 C0
    jmp 0x89b                                    ; 0xE49: E9 4D FA FF FF
    ; ... (2 bytes int3 padding)
    mov dword ptr [rsp + 0x28], 4                ; 0xE50: C7 44 24 28 04 00 00 00
    lea r9, [rsp + 0x60]                         ; 0xE58: 4C 8D 4C 24 60
    mov qword ptr [rsp + 0x30], r14              ; 0xE5D: 4C 89 74 24 30
    lea rdx, [rsp + 0x30]                        ; 0xE62: 48 8D 54 24 30
    mov qword ptr [rsp + 0x60], 0x2000           ; 0xE67: 48 C7 44 24 60 00 20 00 00
    mov dword ptr [rsp + 0x20], 0x3000           ; 0xE70: C7 44 24 20 00 30 00 00
    or rcx, 0xffffffffffffffff                   ; 0xE78: 48 83 C9 FF
    call qword ptr [rbp - 0x78]                  ; 0xE7C: 48 FF 55 88
    test eax, eax                                ; 0xE80: 85 C0
    js 0x89b                                     ; 0xE82: 0F 88 13 FA FF FF
    mov rcx, qword ptr [rsp + 0x30]              ; 0xE88: 48 8B 4C 24 30
    lea r8, [rsp + 0x60]                         ; 0xE8D: 4C 8D 44 24 60
    mov r9d, 2                                   ; 0xE92: 41 B9 02 00 00 00
    lea rdx, [rsp + 0x30]                        ; 0xE98: 48 8D 54 24 30
    lea rax, [rcx + 0x1000]                      ; 0xE9D: 48 8D 81 00 10 00 00
    mov qword ptr [rcx], rax                     ; 0xEA4: 48 89 01
    or rcx, 0xffffffffffffffff                   ; 0xEA7: 48 83 C9 FF
    movaps xmm0, xmmword ptr [rsp + 0x70]        ; 0xEAB: 0F 28 44 24 70
    movups xmmword ptr [rax], xmm0               ; 0xEB0: 0F 11 00
    movaps xmm1, xmmword ptr [rbp - 0x80]        ; 0xEB3: 0F 28 4D 80
    movups xmmword ptr [rax + 0x10], xmm1        ; 0xEB7: 0F 11 48 10
    movaps xmm0, xmmword ptr [rbp - 0x70]        ; 0xEBB: 0F 28 45 90
    movups xmmword ptr [rax + 0x20], xmm0        ; 0xEBF: 0F 11 40 20
    movaps xmm1, xmmword ptr [rbp - 0x60]        ; 0xEC3: 0F 28 4D A0
    movups xmmword ptr [rax + 0x30], xmm1        ; 0xEC7: 0F 11 48 30
    movaps xmm0, xmmword ptr [rbp - 0x50]        ; 0xECB: 0F 28 45 B0
    movups xmmword ptr [rax + 0x40], xmm0        ; 0xECF: 0F 11 40 40
    movaps xmm1, xmmword ptr [rbp - 0x40]        ; 0xED3: 0F 28 4D C0
    movups xmmword ptr [rax + 0x50], xmm1        ; 0xED7: 0F 11 48 50
    movaps xmm0, xmmword ptr [rbp - 0x30]        ; 0xEDB: 0F 28 45 D0
    movups xmmword ptr [rax + 0x60], xmm0        ; 0xEDF: 0F 11 40 60
    lea rax, [rbp + 0x68]                        ; 0xEE3: 48 8D 45 68
    mov qword ptr [rsp + 0x20], rax              ; 0xEE7: 48 89 44 24 20
    call qword ptr [rbp - 0x58]                  ; 0xEEC: 48 FF 55 A8
    test eax, eax                                ; 0xEF0: 85 C0
    jne 0x89b                                    ; 0xEF2: 0F 85 A3 F9 FF FF
    mov rax, qword ptr [rsp + 0x30]              ; 0xEF8: 48 8B 44 24 30
    not rax                                      ; 0xEFD: 48 F7 D0
    mov qword ptr [rsi], rax                     ; 0xF00: 48 89 06
    xor eax, eax                                 ; 0xF03: 33 C0
    jmp 0x89b                                    ; 0xF05: E9 91 F9 FF FF
    mov eax, 0xdeadc0de                          ; 0xF0A: B8 DE C0 AD DE
    jmp 0x89b                                    ; 0xF0F: E9 87 F9 FF FF
    mov eax, 0xc0000135                          ; 0xF14: B8 35 01 00 C0
    add rsp, 0x130                               ; 0xF19: 48 81 C4 30 01 00 00
    pop rdi                                      ; 0xF20: 5F
    pop rsi                                      ; 0xF21: 5E
    pop rbp                                      ; 0xF22: 5D
    ret                                          ; 0xF23: C3
    ; ... (28 bytes int3 padding)
    add dl, 0xff                                 ; 0xF40: 80 C2 FF
    je 0xf5c                                     ; 0xF43: 74 17
    movzx eax, dl                                ; 0xF45: 0F B6 C2
    lea rax, [rcx + rax*8]                       ; 0xF48: 48 8D 04 C1
    nop dword ptr [rax]                          ; 0xF4C: 0F 1F 40 00
    not qword ptr [rax]                          ; 0xF50: 48 F7 10
    lea rax, [rax - 8]                           ; 0xF53: 48 8D 40 F8
    add dl, 0xff                                 ; 0xF57: 80 C2 FF
    jne 0xf50                                    ; 0xF5A: 75 F4
    movzx eax, dl                                ; 0xF5C: 0F B6 C2
    not qword ptr [rcx + rax*8]                  ; 0xF5F: 48 F7 14 C1
    lea rcx, [rcx + rax*8]                       ; 0xF63: 48 8D 0C C1
    ret                                          ; 0xF67: C3
    ; ... (8 bytes int3 padding)
    mov r10, rdx                                 ; 0xF70: 4C 8B D2
    mov r8, rcx                                  ; 0xF73: 4C 8B C1
    test rcx, rcx                                ; 0xF76: 48 85 C9
    je 0x1038                                    ; 0xF79: 0F 84 B9 00 00 00
    mov eax, dword ptr [rcx]                     ; 0xF7F: 8B 01
    cmp eax, 0xb8d18b4c                          ; 0xF81: 3D 4C 8B D1 B8
    jne 0xf93                                    ; 0xF86: 75 0B
    mov eax, dword ptr [rcx + 4]                 ; 0xF88: 8B 41 04
    mov dword ptr [rdx], eax                     ; 0xF8B: 89 02
    mov eax, 1                                   ; 0xF8D: B8 01 00 00 00
    ret                                          ; 0xF92: C3
    cmp al, 0xe9                                 ; 0xF93: 3C E9
    je 0xfaf                                     ; 0xF95: 74 18
    mov ecx, 0x25ff                              ; 0xF97: B9 FF 25 00 00
    cmp ax, cx                                   ; 0xF9C: 66 3B C1
    je 0xfaf                                     ; 0xF9F: 74 0E
    mov ecx, 0xb848                              ; 0xFA1: B9 48 B8 00 00
    cmp ax, cx                                   ; 0xFA6: 66 3B C1
    jne 0x1038                                   ; 0xFA9: 0F 85 89 00 00 00
    mov eax, 1                                   ; 0xFAF: B8 01 00 00 00
    mov ecx, 0x10                                ; 0xFB4: B9 10 00 00 00
    nop dword ptr [rax]                          ; 0xFB9: 0F 1F 80 00 00 00 00
    mov edx, ecx                                 ; 0xFC0: 8B D1
    mov r9, r8                                   ; 0xFC2: 4D 8B C8
    sub r9, rdx                                  ; 0xFC5: 4C 2B CA
    cmp dword ptr [r9], 0xb8d18b4c               ; 0xFC8: 41 81 39 4C 8B D1 B8
    je 0x1017                                    ; 0xFCF: 74 46
    cmp dword ptr [rdx + r8], 0xb8d18b4c         ; 0xFD1: 42 81 3C 02 4C 8B D1 B8
    lea r9, [rdx + r8]                           ; 0xFD9: 4E 8D 0C 02
    je 0xfef                                     ; 0xFDD: 74 10
    add ecx, 0x10                                ; 0xFDF: 83 C1 10
    inc eax                                      ; 0xFE2: FF C0
    cmp eax, 0x20                                ; 0xFE4: 83 F8 20
    jbe 0xfc0                                    ; 0xFE7: 76 D7
    mov eax, 0xffffffff                          ; 0xFE9: B8 FF FF FF FF
    ret                                          ; 0xFEE: C3
    add ecx, 4                                   ; 0xFEF: 83 C1 04
    mov r8d, dword ptr [rcx + r8]                ; 0xFF2: 46 8B 04 01
    mov edx, r8d                                 ; 0xFF6: 41 8B D0
    sub r8d, eax                                 ; 0xFF9: 44 2B C0
    mov ecx, eax                                 ; 0xFFC: 8B C8
    shr ecx, 1                                   ; 0xFFE: D1 E9
    mov eax, 1                                   ; 0x1000: B8 01 00 00 00
    sub edx, ecx                                 ; 0x1005: 2B D1
    cmp dword ptr [r9 + 8], 0x82504f6            ; 0x1007: 41 81 79 08 F6 04 25 08
    cmove r8d, edx                               ; 0x100F: 44 0F 44 C2
    mov dword ptr [r10], r8d                     ; 0x1013: 45 89 02
    ret                                          ; 0x1016: C3
    mov edx, eax                                 ; 0x1017: 8B D0
    shr edx, 1                                   ; 0x1019: D1 EA
    cmp dword ptr [r9 + 8], 0x82504f6            ; 0x101B: 41 81 79 08 F6 04 25 08
    cmovne edx, eax                              ; 0x1023: 0F 45 D0
    add ecx, -4                                  ; 0x1026: 83 C1 FC
    sub r8, rcx                                  ; 0x1029: 4C 2B C1
    mov eax, 1                                   ; 0x102C: B8 01 00 00 00
    add edx, dword ptr [r8]                      ; 0x1031: 41 03 10
    mov dword ptr [r10], edx                     ; 0x1034: 41 89 12
    ret                                          ; 0x1037: C3
    xor eax, eax                                 ; 0x1038: 33 C0
    ret                                          ; 0x103A: C3
    ; ... (5 bytes int3 padding)
    push qword ptr [rcx + 8]                     ; 0x1040: 48 FF 71 08
    mov r10, qword ptr [rcx + 0x10]              ; 0x1044: 4C 8B 51 10
    mov rcx, qword ptr [rcx]                     ; 0x1048: 48 8B 49 00
    lea rax, [rip + 0x6c]                        ; 0x104C: 44 48 8D 05 6C 00 00 00
    push rax                                     ; 0x1054: 50
    mov rax, rsp                                 ; 0x1055: 48 8B C4
    lea rsp, [rsp - 0x680]                       ; 0x1058: 48 8D A4 24 80 F9 FF FF
    xchg qword ptr [rsp], rbp                    ; 0x1060: 48 87 2C 24
    sub rsp, 8                                   ; 0x1064: 48 83 EC 08
    mov qword ptr [rsp], rax                     ; 0x1068: 48 89 04 24
    lea rsp, [rsp - 0x120]                       ; 0x106C: 48 8D A4 24 E0 FE FF FF
    push qword ptr [rax]                         ; 0x1074: FF 30
    mov dword ptr [rax], ebp                     ; 0x1076: 89 28
    lea rax, [rax + 8]                           ; 0x1078: 48 8D 40 08
    movups xmm0, xmmword ptr [rax + 0x30]        ; 0x107C: 0F 10 40 30
    movups xmmword ptr [rsp + 0x28], xmm0        ; 0x1080: 0F 11 44 24 28
    movups xmm0, xmmword ptr [rax + 0x40]        ; 0x1085: 0F 10 40 40
    movups xmmword ptr [rsp + 0x38], xmm0        ; 0x1089: 0F 11 44 24 38
    movups xmm0, xmmword ptr [rax + 0x50]        ; 0x108E: 0F 10 40 50
    movups xmmword ptr [rsp + 0x48], xmm0        ; 0x1092: 0F 11 44 24 48
    movups xmm0, xmmword ptr [rax + 0x60]        ; 0x1097: 0F 10 40 60
    movups xmmword ptr [rsp + 0x58], xmm0        ; 0x109B: 0F 11 44 24 58
    xchg qword ptr [rax], rax                    ; 0x10A0: 48 87 40 00
    not rcx                                      ; 0x10A4: 44 48 F7 D1
    jmp rcx                                      ; 0x10A8: FF E1
    ; ... (22 bytes int3 padding)
    lea rsp, [rsp - 0x3590a84c]                  ; 0x10C0: 48 8D A4 24 B4 57 6F CA
    lea rsp, [rsp - 0x157b7b15]                  ; 0x10C8: 48 8D A4 24 EB 84 84 EA
    lea rsp, [rsp + 0x4b0c2481]                  ; 0x10D0: 48 8D A4 24 81 24 0C 4B
    xchg qword ptr [rsp], rax                    ; 0x10D8: 48 87 04 24
    xchg rsp, rax                                ; 0x10DC: 48 94
    mov rbp, qword ptr [rax + 8]                 ; 0x10DE: 48 8B 68 08
    mov rax, qword ptr [rax]                     ; 0x10E2: 48 8B 40 00
    add rsp, 0x10                                ; 0x10E6: 48 83 C4 10
    ret                                          ; 0x10EA: C3
    ; ... (53 bytes int3 padding)

; ==============================================================================
; END OF SHELLCODE DISASSEMBLY
; ==============================================================================
