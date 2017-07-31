
EXTERN VmmVmExitHandler     : PROC
EXTERN VmmVmxFailureHandler : PROC
EXTERN UtilDumpGpRegisters  : PROC

.CONST
VMX_OK					 EQU 0
VMX_ERROR_WITH_STATUS    EQU 1
VMX_ERROR_WITHOUT_STATUS EQU 2

; x64下 自实现 pushaq popaq          
PUSHAQ MACRO    ; 16 次 push
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    -1      ; 假装保存 rsp
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
ENDM

; Loads all general purpose registers from the stack
POPAQ MACRO
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    add     rsp, 8    ; 假装恢复 rsp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
ENDM

; 赋值所有的常规寄存器和标志寄存器
ASM_DUMP_REGISTERS MACRO
    pushfq
    PUSHAQ      ; rsp - 8 * 16
   
    mov rcx, rsp    ; rsp = GuestContext
    mov rdx, rsp
    add rdx, 8 * 17 ; rdx = StackPointer

    sub rsp, 28h    ; ??? 
    call UtilDumpGpRegisters ; UtilDumpGpRegisters(GuestContext, StackPointr)
    add rsp, 28h

    POPAQ
    popfq
ENDM

.CODE
; bool _stdcall AsmInitializeVm(_In_ void(*VmInitializationRoutine)(_In_ ULONG_PTR, _In_ ULONG_PTR, _In_opt_ void*), _In_opt_ void* Context);
AsmInitializeVm PROC
    ; pushfq 后，rsp没有16位对齐(rsp -= 8)。但是后面的PUSHAQ让rsp下移了17次(rsp -= 8 * 17)。两次加起来使得rsp对齐了16位。所以在下面函数调用的时候，也只需要对齐即可16位即可。
    pushfq
    PUSHAQ

    mov rax, rcx
    mov r8, rdx
    mov rdx, AsmResumeVm
    mov rcx, rsp

    ; 64位调用约定 - 为子函数开辟栈区
    ; 3 * 8 + 8 正好对齐
    sub rsp, 20h
    call rax        ; VmInitializationRoutine(rsp, AsmResume, Context)
    add rsp, 20h

    POPAQ
    popfq
    xor rax, rax    ; false
    ret

; Vm 实际代码
; vmlaunch 实际启动代码
AsmResumeVm:
    nop
    POPAQ
    popfq

    sub rsp, 8
    ASM_DUMP_REGISTERS
    add rsp, 8

    xor rax, rax
    inc rax         ; true
    ret

AsmInitializeVm ENDP

; void __stdcall AsmVmmEntryPoint();
AsmVmmEntryPoint PROC
    ; 标志寄存器已经有 VMCS 保存，这里不再保存
    PUSHAQ
    mov rcx, rsp ; rcx - old registers

    ; 保存 XMM 寄存器
    sub rsp, 60h
    movaps xmmword ptr [rsp +  0h], xmm0
    movaps xmmword ptr [rsp + 10h], xmm1
    movaps xmmword ptr [rsp + 20h], xmm2
    movaps xmmword ptr [rsp + 30h], xmm3
    movaps xmmword ptr [rsp + 40h], xmm4
    movaps xmmword ptr [rsp + 50h], xmm5

    sub rsp, 20h  ; 一个参数 对齐成16，加上 8 位返回。由于前面rsp是已经对齐的。所以这里还要再加 8 对齐。共20
    call VmmVmExitHandler ; VmmVmExitHandler(GuestContext);
    add rsp, 20h

    ; 恢复 XMM registers
    movaps xmm0, xmmword ptr [rsp +  0h]
    movaps xmm1, xmmword ptr [rsp + 10h]
    movaps xmm2, xmmword ptr [rsp + 20h]
    movaps xmm3, xmmword ptr [rsp + 30h]
    movaps xmm4, xmmword ptr [rsp + 40h]
    movaps xmm5, xmmword ptr [rsp + 50h]
    add rsp, 60h

    test al, al
    jz ExitVm

    POPAQ
    vmresume 
    jmp VmxError

ExitVm:
    POPAQ
    vmxoff	; 执行完成后
	;   rax = Guest's rflags
    ;   rdx = Guest's rsp
    ;   rcx = Guest's rip for the next instruction 
    ;   检查 ZF CF
    jz VmxError
    jz VmxError
    push rax
    popfq        ; GuestFlags
    mov rsp, rdx ; GuestRsp  
    push rcx     
    ret

VmxError:
;   触发一个致命错误
    pushfq
    PUSHAQ  ; 8 * 16

    mov rcx, rsp
    sub rsp, 28h ; 一参 -> 16, +8
    call VmmVmxFailureHandler
    add rsp, 28h
    int 3

AsmVmmEntryPoint ENDP

; unsigned char __stdcall AsmVmxCall(_In_ ULONG_PTR HypercallNumber, _In_opt_ void* Context);
AsmVmxCall PROC
    vmcall

    jz ErrorWithCode
    jc ErrorWithoutCode
    xor rax, rax
    ret

ErrorWithCode:
    mov rax, VMX_ERROR_WITH_STATUS
    ret

ErrorWithoutCode:
    mov rax, VMX_ERROR_WITHOUT_STATUS
    ret

AsmVmxCall ENDP


; void __stdcall AsmWriteGDT(_In_ const GDTR *gdtr);
AsmWriteGDT PROC
    lgdt fword ptr [rcx]
    ret
AsmWriteGDT ENDP

; void __stdcall AsmReadGDT(_Out_ GDTR *gdtr);
AsmReadGDT PROC
    sgdt [rcx]
    ret
AsmReadGDT ENDP

; void __stdcall AsmWriteLDTR(_In_ USHORT local_segmeng_selector);
AsmWriteLDTR PROC
    lldt cx
    ret
AsmWriteLDTR ENDP

; USHORT __stdcall AsmReadLDTR();
AsmReadLDTR PROC
    sldt ax
    ret
AsmReadLDTR ENDP

; void __stdcall AsmWriteTR(_In_ USHORT task_register);
AsmWriteTR PROC
    ltr cx
    ret
AsmWriteTR ENDP

; USHORT __stdcall AsmReadTR();
AsmReadTR PROC
    str ax
    ret
AsmReadTR ENDP

; void __stdcall AsmWriteES(_In_ USHORT segment_selector);
AsmWriteES PROC
    mov es, cx
    ret
AsmWriteES ENDP

; USHORT __stdcall AsmReadES();
AsmReadES PROC
    mov ax, es
    ret
AsmReadES ENDP

; void __stdcall AsmWriteCS(_In_ USHORT segment_selector);
AsmWriteCS PROC
    mov cs, cx
    ret
AsmWriteCS ENDP

; USHORT __stdcall AsmReadCS();
AsmReadCS PROC
    mov ax, cs
    ret
AsmReadCS ENDP

; void __stdcall AsmWriteSS(_In_ USHORT segment_selector);
AsmWriteSS PROC
    mov ss, cx
    ret
AsmWriteSS ENDP

; USHORT __stdcall AsmReadSS();
AsmReadSS PROC
    mov ax, ss
    ret
AsmReadSS ENDP

; void __stdcall AsmWriteDS(_In_ USHORT segment_selector);
AsmWriteDS PROC
    mov ds, cx
    ret
AsmWriteDS ENDP

; USHORT __stdcall AsmReadDS();
AsmReadDS PROC
    mov ax, ds
    ret
AsmReadDS ENDP

; void __stdcall AsmWriteFS(_In_ USHORT segment_selector);
AsmWriteFS PROC
    mov fs, cx
    ret
AsmWriteFS ENDP

; USHORT __stdcall AsmReadFS();
AsmReadFS PROC
    mov ax, fs
    ret
AsmReadFS ENDP

; void __stdcall AsmWriteGS(_In_ USHORT segment_selector);
AsmWriteGS PROC
    mov gs, cx
    ret
AsmWriteGS ENDP

; USHORT __stdcall AsmReadGS();
AsmReadGS PROC
    mov ax, gs
    ret
AsmReadGS ENDP

; ULONG_PTR __stdcall AsmLoadAccessRightsByte(_In_ ULONG_PTR segment_selector);
AsmLoadAccessRightsByte PROC
    lar rax, rcx
    ret
AsmLoadAccessRightsByte ENDP

; void __stdcall AsmInvalidateInternalCaches();
AsmInvalidateInternalCaches PROC
    invd
    ret
AsmInvalidateInternalCaches ENDP

; void __stdcall AsmWriteCR2(_In_ ULONG_PTR cr2_value);
AsmWriteCR2 PROC
    mov cr2, rcx
    ret
AsmWriteCR2 ENDP

;	unsigned char __stdcall AsmInvept(_In_ INV_EPT_TYPE InveptType, _In_ const INV_EPT_DESCRIPTOR* InveptDescriptor);
AsmInvept PROC
    db 66h, 0fh, 38h, 80h, 0ah
    ; invept rcx, qword ptr [rdx]
    jz ErrorWithCode
    jc ErrorWithoutCode
    xor rax, rax ; VMX_OK
    ret

ErrorWithoutCode:
    mov rax, VMX_ERROR_WITHOUT_STATUS
    ret

ErrorWithCode:
    mov rax, VMX_ERROR_WITH_STATUS
    ret
AsmInvept ENDP

AsmInvvpid PROC
    db 66h, 0fh, 38h, 81h, 0ah
    ; invvpid rcx, qword [rdx]
    jz ErrorWithCode
    jc ErrorWithoutCode
    xor rax, rax
    ret

ErrorWithCode:
    mov rax, VMX_ERROR_WITH_STATUS
    ret

ErrorWithoutCode:
    mov rax, VMX_ERROR_WITHOUT_STATUS
    ret

AsmInvvpid ENDP

PURGE PUSHAQ
PURGE POPAQ
PURGE ASM_DUMP_REGISTERS
END