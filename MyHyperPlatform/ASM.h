#pragma once

#include "ia32_type.h"

EXTERN_C_START

// 对VM初始化的一层包装
// @param VmInitializationRoutine 进入VMX-mode的入口函数
// @param Context Context参数
// @return true 当函数执行成功
bool _stdcall AsmInitializeVm(_In_ void(*VmInitializationRoutine)(_In_ ULONG_PTR, _In_ ULONG_PTR, _In_opt_ void*), _In_opt_ void* Context);

// 加载 访问权限 位
// @param SegmentSelector 想要得到访问权限的段选择符
// @return 访问权限位
ULONG_PTR __stdcall AsmLoadAccessRightsByte(_In_ ULONG_PTR SegmentSelector);

// GDT 读写函数
void __stdcall AsmReadGDT(_Out_ GDTR* Gdtr);
void __stdcall AsmWriteGDT(_In_ GDTR* Gdtr);

// 读取 SGDT
inline void __lgdt(_In_ void* gdtr)
{
	AsmWriteGDT(static_cast<GDTR*>(gdtr));
}


//  激活处理器VMX模式
// @param VmsSupportPhysicalAddress  64位的 VMXON 区域地址
// @return Equivalent to #VmxStatus
inline unsigned char __vmx_on(_In_ unsigned __int64 *VmsSupportPhysicalAddress) 
{
	// 2.6.6.1 VMXON 指令
	FLAG_REGISTER FlagRegister = {};
	PHYSICAL_ADDRESS PhysicalAddress = {};
	PhysicalAddress.QuadPart = *VmsSupportPhysicalAddress;
	
	__asm 
	{
		push PhysicalAddress.HighPart
		push PhysicalAddress.LowPart

		// _emit 指令就是硬编码写入 F3 0F C7 34 24
		_emit  0xF3
		_emit  0x0F
		_emit  0xC7
		_emit  0x34
		_emit  0x24  // VMXON [ESP] | 参数就是上面push进来的

		pushfd
		pop FlagRegister.all
		add esp, 8
	}

	// 判断开启是否成功
	if (FlagRegister.fields.cf) 
		return 2;
	
	if (FlagRegister.fields.zf) 
		return 1;
	
	return 0;
}

// 初始化 VMCS 区域。 并设置 VMCS 区域 launch state 值为 clear 
// @param VmcsPhysicalAddress VMCS 物理地址
// @return VMX_STATUS
inline unsigned  char __vmx_vmclear(_In_ unsigned __int64* VmcsPhysicalAddress)
{
	FLAG_REGISTER FlagRegister = { 0 };
	PHYSICAL_ADDRESS PhysicalAddress = { 0 };

	PhysicalAddress.QuadPart = *VmcsPhysicalAddress;

	_asm
	{
		push PhysicalAddress.HighPart;
		push PhysicalAddress.LowPart;

		// 似乎可以直接写汇编指令
		_emit 0x66
		_emit 0x0F
		_emit 0xc7
		_emit 0x34
		_emit 0x24  // VMCLEAR [ESP]

		// 取出 EFlag 的值 放入自己的变量
		pushfd		
		pop FlagRegister.all

		add esp, 8
	}

	if (FlagRegister.fields.cf)
		return 2;

	if (FlagRegister.fields.zf)
		return 1;

	return 0;
}

// 2.6.5.1 VMCS 管理指令 - VMPTRLD 指令
//  加载一个64位的物理地址，作为当前 current-VMCS pointer 
//  除了 VMXON VMPRTLD VMCLEAR 其它指令都是使用 内部维护的 VMCS 指针
inline unsigned char __vmx_vmptrld(_In_ unsigned __int64* VmcsPhysicalAddress)
{
	FLAG_REGISTER FlagRegitser = { 0 };
	PHYSICAL_ADDRESS PhysicalAddress = { 0 };

	PhysicalAddress.QuadPart = *VmcsPhysicalAddress;

	_asm
	{
		push PhysicalAddress.HighPart;
		push PhysicalAddress.LowPart;

		_emit 0x0F;
		_emit 0xC7;
		_emit 0x34;
		_emit 0x24;	// VMPTRLD [esp]

		pushfd
		pop FlagRegitser.all

		add esp, 8
	}

	if (FlagRegitser.fields.cf)
		return 2;

	if (FlagRegitser.fields.zf)
		return 1;

	return 0;
}

// 读取 GDT
inline void __sgdt(_Out_ void* Gdtr)
{
	AsmReadGDT(static_cast<GDTR*>(Gdtr));
}

// 写入 GDT
inline void __igdt(_In_ void* Gdtr)
{
	AsmWriteGDT(static_cast<GDTR*>(Gdtr));
}

// 写入特定值到当前VMCS特定域里面
inline unsigned char __vmx_vmwrite(_In_ size_t Field, _In_ size_t FieldValue)
{
	FLAG_REGISTER Flags = { 0 };
	__asm
	{
		pushad
		push FieldValue
		mov eax, Field

		_emit 0x0F
		_emit 0x79
		_emit 0x04
		_emit 0x24	// VMWRITE EAX, [ESP]

		pushfd
		pop Flags

		add esp, 4
		popad
	}

	if (Flags.fields.cf)
		return 2;

	if (Flags.fields.zf)
		return 1;

	return 0;
}

// Reads a specified field from the current VMCS
// @param Field  The VMCS field to read
// @param FieldValue  A pointer to the location to store the value read from the VMCS field specified by the Field parameter
// @return Equivalent to #VmxStatus
inline unsigned char __vmx_vmread(_In_ size_t Field, _Out_ size_t *FieldValue) 
{
	FLAG_REGISTER Flags = { 0 };

	__asm 
	{
		pushad
		mov eax, Field

		_emit 0x0F
		_emit 0x78
		_emit 0xC3  // VMREAD  EBX, EAX

		pushfd
		pop Flags.all

		mov eax, FieldValue
		mov[eax], ebx
		popad
	}

	if (Flags.fields.cf) 
		return 2;
	
	if (Flags.fields.zf) 
		return 1;
	
	return 0;
}

// Places the calling application in VMX non-root operation state (VM enter)
// @return Equivalent to #VmxStatus
inline unsigned char __vmx_vmlaunch() 
{
	FLAG_REGISTER Flags = { 0 };

	__asm 
	{
		_emit 0x0f
		_emit 0x01
		_emit 0xc2  // VMLAUNCH

		pushfd
		pop Flags.all
	}

	if (Flags.fields.cf)
		return 2;
	
	if (Flags.fields.zf)
		return 1;
	
	return 0;
}

// 写入 CR2
void __stdcall AsmWriteCR2(_In_ ULONG_PTR Cr2Value);

// 刷新 EPT 转换缓存 - 执行 INVEPT 指令
// @param InveptType INVEPT指令执行类型
// @param INV_EPT_DESCRIPTOR 描述符
unsigned char __stdcall AsmInvept(_In_ INV_EPT_TYPE InveptType, _In_ const INV_EPT_DESCRIPTOR* InveptDescriptor);

// 刷新 LineAddress -> HPA 转换缓存
// @param InvVpidType 转换类型
// @param InvVpidDescriptor  转换描述符
unsigned char __stdcall AsmInvvpid(_In_ INV_VPID_TYPE InvVpidType, _In_ const INV_VPID_DESCRIPTOR* InvVpidDescriptor);

USHORT __stdcall AsmReadES();

USHORT __stdcall AsmReadCS();

USHORT __stdcall AsmReadSS();

USHORT __stdcall AsmReadDS();

USHORT __stdcall AsmReadFS();

USHORT __stdcall AsmReadGS();

USHORT __stdcall AsmReadLDTR();

USHORT __stdcall AsmReadTR();

// VMM 入口 - 当发生 VM-exit 呼叫函数
void __stdcall AsmVmmEntryPoint();

// 执行 VMCALL
// @param HypercallNumber 一个HypercallNumber
// @param Context VMCALL 背景文 
unsigned char __stdcall AsmVmxCall(_In_ ULONG_PTR HypercallNumber, _In_opt_ void* Context);

// 刷新 CPU 内置缓存
void __stdcall AsmInvalidateInternalCaches();

EXTERN_C_END