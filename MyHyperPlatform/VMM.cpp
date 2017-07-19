#include "VMM.h"
#include <intrin.h>
#include "ASM.h"
#include "Common.h"
#include "EPT.h"
#include "Log.h"
#include "Util.h"
#include "Performance.h"


EXTERN_C_START

struct VMM_INITIAL_STACK
{
	GP_REGISTER GpRegister;
	ULONG_PTR   Reserved;
	PROCESSOR_DATA* ProcessorData;
};

struct GUEST_CONTEXT
{
	union 
	{
		VMM_INITIAL_STACK* Stack;
		GP_REGISTER* GpRegister;
	};

	FLAG_REGISTER Flag;
	ULONG_PTR Ip;
	ULONG_PTR Cr8;
	KIRQL Irql;
	bool VmContinue;
};
#if defined(_AMD64_)
static_assert(sizeof(GUEST_CONTEXT) == 40, "Size check");
#else
static_assert(sizeof(GUEST_CONTEXT) == 20, "Size check");
#endif

DECLSPEC_NORETURN void __stdcall VmmVmxFailureHandler(_Inout_ ALL_REGISTERS* AllRegisters);
bool __stdcall VmmVmExitHandler(_Inout_ VMM_INITIAL_STACK *Stack);


// 由 AsmVmExitHandler 呼叫 - 处理 VM-exit
#pragma warning(push)
#pragma warning(disable : 28167)
_Use_decl_annotations_ bool __stdcall VmmVmExitHandler(VMM_INITIAL_STACK *Stack)
{
	// 保存 guest 背景文 
	const auto GuestIrql = KeGetCurrentIrql();
	const auto GuestCr8 = IsX64() ? __readcr8() : 0;
	// 提升 IRQL - ??? 为啥提升
	if (GuestIrql < DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();

	NT_ASSERT(Stack->Reserved == MAXULONG_PTR);	
	GUEST_CONTEXT GuestContext = { Stack, UtilVmRead(VMCS_FIELD::kGuestRflags), UtilVmRead(VMCS_FIELD::kGuestRip), GuestCr8, GuestIrql, true };
	GuestContext.GpRegister->sp = UtilVmRead(VMCS_FIELD::kGuestRsp);

	// 传入实际处理函数
	VmmHandleVmExit(&GuestContext);

	// 如果VM错误，不再执行 - 刷新缓存
	if (!GuestContext.VmContinue)
	{
		UtilInveptGlobal();
		UtilInvvpidAllContext();
	}
	// 回复 IRQL
	if (GuestContext.Irql < DISPATCH_LEVEL)
		KeLowerIrql(GuestContext.Irql);

	// 更新 CR8 ???
	if (IsX64())
	{
		__writecr8(GuestContext.Cr8);
	}

	return GuestContext.VmContinue;
}

// Handle VMRESUME or VMXOFF failure. Fatal error.
_Use_decl_annotations_ void __stdcall VmmVmxFailureHandler(ALL_REGISTERS* AllRegisters)
{
	UNREFERENCED_PARAMETER(AllRegisters);
	
}

//  分发 VM-exit 给具体的处理函数
_Use_decl_annotations_ static void VmmHandleVmExit(GUEST_CONTEXT* GuestContext)
{
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
}

EXTERN_C_END



