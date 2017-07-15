.686P
.model flat, stdcall
.mmx
.xmm

; export functions to use in asm
extern UtilDumpGpRegisters@8 : PROC



; macro
; 复制所有通用寄存器和标志寄存器 - 将所有寄存器值放入栈区
ASM_DUMP_REGISTER  MACRO
	pushfd			    ; pushn EFlags
	pushad				; -4 * 8	Push EAX, ECX, EDX, EBX, ESP, EBP, ESI, and EDI
			
	mov ecx, esp		;
	mov edx, esp
	add edx, 4 * 9	    ; esp 复原

	push ecx
	push edx

	; 输出寄存器的值
	call UtilDumpGpRegisters@8	; UtilDumpGpRegisters(all_regs, stack_pointer);
		
	popad
	popfd
ENDM

.code
; 虚拟化初始化函数
; bool __stdcall AsmInitializeVm(_In_ void (*vm_initialization_routine)(_In_ ULONG_PTR, _In_ ULONG_PTR,  _In_opt_ void *), _In_opt_ void *context);
AsmInitializeVm PROC VmInitializationRoutine, Context

	pushfd
	pushad

	mov ecx, esp		; esp

	; 调用VmInitializationRoutine 
	push Context
	push AsmResumeVm
	push ecx
	call VmInitializationRoutine	;  VmInitializationRoutine(esp, AsmResumeVm, Context)

	popad
	popfd

	xor eax, eax
	ret

AsmResumeVm:
	nop
	popad
	popfd

	ASM_DUMP_REGISTERS

	xor eax, eax
	inc eax
	ret

AsmInitializeVm	ENDP