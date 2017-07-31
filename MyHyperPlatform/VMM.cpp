#include "VMM.h"
#include <intrin.h>
#include "ASM.h"
#include "Common.h"
#include "EPT.h"
#include "Log.h"
#include "Util.h"
#include "Performance.h"


EXTERN_C_START

// Vmm文件主要处理 VM-exit 第五章节

// 决定是否记录 VM-Exit
static const long kVmmEnableRecordVmExit = true;
// 每个处理器应该记录多少
static const long kVmmNumberOfRecords = 100;
// 支持记录多少个处理器的消息
static const long kVmmNumberOfProcessors = 2;

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

// VM-exit 事件的上下文记录
struct VM_EXIT_HISTORY
{
	GP_REGISTER GpRegister;
	ULONG_PTR Ip;
	VM_EXIT_INFORMATION ExitReason;
	ULONG_PTR ExitQualification;
	ULONG_PTR InstructionInfo;
};

DECLSPEC_NORETURN void __stdcall VmmVmxFailureHandler(_Inout_ ALL_REGISTERS* AllRegisters);
bool __stdcall VmmVmExitHandler(_Inout_ VMM_INITIAL_STACK *Stack);
static void VmmHandleVmExit(_Inout_ GUEST_CONTEXT* GuestContext);

static void VmmDumpGuestState();

static void VmmHandleException(_Inout_ GUEST_CONTEXT* GuestContext);
DECLSPEC_NORETURN static void VmmHandleTripleFault(_Inout_ GUEST_CONTEXT* GuestContext);
static void VmmHandleCpuid(_Inout_ GUEST_CONTEXT* GuestContext);
static void VmmHandleInvalidateInternalCaches(_Inout_ GUEST_CONTEXT* GuestContext);
static void VmmHandleInvalidateTlbEntry(_Inout_ GUEST_CONTEXT* GuestContext);
static void VmmHandleRdtsc(_Inout_ GUEST_CONTEXT* GuestContext);
static void VmmHandleCrAccess(_Inout_ GUEST_CONTEXT* GuestContext);
static void VmmHandleDrAccess(_Inout_ GUEST_CONTEXT* GuestContext);
static void VmmHandleIoPort(_Inout_ GUEST_CONTEXT* GuestContext);
static void VmmHandleMsrReadAccess(_Inout_ GUEST_CONTEXT* GuestContext);
static void VmmHandleMsrWriteAccess(_Inout_ GUEST_CONTEXT* GuestContext);
static void VmmHandleMsrAccess(_Inout_ GUEST_CONTEXT* GuestContext, _In_ bool ReadAccess);
static void VmmHandleMonitorTrap(_Inout_ GUEST_CONTEXT* GuestContext);
static void VmmHandleGdtrOrIdtrAccess(_Inout_ GUEST_CONTEXT* GuestContext);
static void VmmHandleLdtrOrTrAccess(_Inout_ GUEST_CONTEXT* GuestContext);
static void VmmHandleEptViolation(_Inout_ GUEST_CONTEXT* GuestContext);
static void VmmHandleVmCallTermination(_In_ GUEST_CONTEXT* GuestContext, _Inout_ void* Context);
static void VmmIndicateUnsuccessfulVmcall(_In_ GUEST_CONTEXT* GuestContext);
static void VmmIndicateSuccessfulVmcall(_In_ GUEST_CONTEXT* GuestContext);
static void VmmHandleVmx(_In_ GUEST_CONTEXT* GuestContext);
static void VmmHandleRdtscp(_In_ GUEST_CONTEXT* GuestContext);
static void VmmHandleXsetbv(_In_ GUEST_CONTEXT* GuestContext);
static void VmmHandleUnexpectedExit(_In_ GUEST_CONTEXT* GuestContext);
static void VmmHandleEptMisconfig(_Inout_ GUEST_CONTEXT* GuestContext);
static void VmmHandleVmCall(_Inout_ GUEST_CONTEXT* GuestContext);

static void VmmInjectInterruption(_In_ INTERRUPTION_TYPE InterruptionType, _In_ INTERRUPTION_VECTOR InterruptionVector, _In_ bool DeliverErrorCode, _In_ ULONG32 ErrorCode);
static UCHAR VmmGetGuestCpl();
static void VmmIoWrapper(_In_ bool ToMemory,_In_ bool IsString,_In_ SIZE_T SizeOfAccess,_In_ unsigned short Port,
						 _Inout_ void* Address,_In_ unsigned long Count);
static ULONG_PTR* VmmSelectRegister(_In_ ULONG Index,_In_ GUEST_CONTEXT* GuestContext);


// 下面的变量都是用来进行记录和发生bug时进行检查
static ULONG g_VmmNextHistroyIndex[kVmmNumberOfProcessors];
static VM_EXIT_HISTORY g_VmmVmExitHistroy[kVmmNumberOfProcessors][kVmmNumberOfRecords];	// 为 kVmmNumberOfProcessors 个处理器记录 kVmmNumberOfRecords 个记录


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
	const auto GuestIp = UtilVmRead(VMCS_FIELD::kGuestRip);

	const auto VmxError = (AllRegisters->flags.fields.zf) ? UtilVmRead(VMCS_FIELD::kVmInstructionError) : 0;
	MYHYPERPLATFORM_COMMON_BUG_CHECK(HYPERPLATFORM_BUG_CHECK::kCriticalVmxInstructionFailure, VmxError, 0, 0);
}

//  分发 VM-exit 给具体的处理函数
// 3.10 P247 VM-exit 信息类字段
_Use_decl_annotations_ static void VmmHandleVmExit(GUEST_CONTEXT* GuestContext)
{
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

	//MYHYPERPLATFORM_COMMON_DBG_BREAK();

	const VM_EXIT_INFORMATION ExitReason = { static_cast<ULONG32>(UtilVmRead(VMCS_FIELD::kVmExitReason)) };

	if (kVmmEnableRecordVmExit)
	{
		// 记录 VM-Exit 消息
		const auto Processor = KeGetCurrentProcessorNumberEx(nullptr);
		auto& Index = g_VmmNextHistroyIndex[Processor];
		auto& Histroy = g_VmmVmExitHistroy[Processor][Index];

		Histroy.GpRegister = *GuestContext->GpRegister;
		Histroy.Ip = GuestContext->Ip;
		Histroy.ExitReason = ExitReason;
		Histroy.ExitQualification = UtilVmRead(VMCS_FIELD::kExitQualification);
		Histroy.InstructionInfo = UtilVmRead(VMCS_FIELD::kVmxInstructionInfo);

		Index++;
		// 如果已经记录两个了，那么下一个记录覆盖第一个记录
		if (Index == kVmmNumberOfRecords)
			Index = 0;
	}

	// switc 退出原因 - 进行处理
	switch (ExitReason.fields.reason)
	{
		case VMX_EXIT_REASON::kExceptionOrNmi:
			VmmHandleException(GuestContext);
			break;
		case VMX_EXIT_REASON::kTripleFault:
			VmmHandleTripleFault(GuestContext);
			break;
		case VMX_EXIT_REASON::kCpuid:
			VmmHandleCpuid(GuestContext);
			break;
		case VMX_EXIT_REASON::kInvd:
			VmmHandleInvalidateInternalCaches(GuestContext);
			break;
		case VMX_EXIT_REASON::kInvlpg:
			VmmHandleInvalidateTlbEntry(GuestContext);
			break;
		case VMX_EXIT_REASON::kRdtsc:
			VmmHandleRdtsc(GuestContext);
			break;
		case VMX_EXIT_REASON::kCrAccess:
			VmmHandleCrAccess(GuestContext);
			break;
		case VMX_EXIT_REASON::kDrAccess:
			VmmHandleDrAccess(GuestContext);
			break;
		case VMX_EXIT_REASON::kIoInstruction:
			VmmHandleIoPort(GuestContext);
			break;
		case VMX_EXIT_REASON::kMsrRead:
			VmmHandleMsrReadAccess(GuestContext);
			break;
		case VMX_EXIT_REASON::kMsrWrite:
			VmmHandleMsrWriteAccess(GuestContext);
			break;
		case VMX_EXIT_REASON::kMonitorTrapFlag:
			VmmHandleMonitorTrap(GuestContext);
			break;
		case VMX_EXIT_REASON::kGdtrOrIdtrAccess:
			VmmHandleGdtrOrIdtrAccess(GuestContext);
			break;
		case VMX_EXIT_REASON::kLdtrOrTrAccess:
			VmmHandleLdtrOrTrAccess(GuestContext);
			break;
		case VMX_EXIT_REASON::kEptViolation:
			VmmHandleEptViolation(GuestContext);
			break;	
		case VMX_EXIT_REASON::kEptMisconfig:
			VmmHandleEptMisconfig(GuestContext);
			break;
		case VMX_EXIT_REASON::kVmcall:
			VmmHandleVmCall(GuestContext);
			break;
		case VMX_EXIT_REASON::kVmclear:
		case VMX_EXIT_REASON::kVmlaunch:
		case VMX_EXIT_REASON::kVmptrld:
		case VMX_EXIT_REASON::kVmptrst:
		case VMX_EXIT_REASON::kVmread:
		case VMX_EXIT_REASON::kVmresume:
		case VMX_EXIT_REASON::kVmwrite:
		case VMX_EXIT_REASON::kVmoff:
		case VMX_EXIT_REASON::kVmon:
			VmmHandleVmx(GuestContext);
			break;
		case VMX_EXIT_REASON::kRdtscp:
			VmmHandleRdtscp(GuestContext);
			break;
		case VMX_EXIT_REASON::kXsetbv:
			VmmHandleXsetbv(GuestContext);
			break;
		default:
			VmmHandleUnexpectedExit(GuestContext);
			break;
	}
}

// VM 发生了中断
_Use_decl_annotations_ static void VmmHandleException(GUEST_CONTEXT* GuestContext)
{
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	// 读取中断信息
	// 3.10.2 直接向量事件类信息字段
	
	const VM_EXIT_INTERRUPTION_INFORMATION_FIELD VmExitInterruptionInformationField = { static_cast<ULONG32>(UtilVmRead(VMCS_FIELD::kVmExitIntrInfo)) };
	const auto InterruptionType = static_cast<INTERRUPTION_TYPE>(VmExitInterruptionInformationField.field.InterruptionType);
	const auto Vector = static_cast<INTERRUPTION_VECTOR>(VmExitInterruptionInformationField.field.Vector);

	if (InterruptionType == INTERRUPTION_TYPE::kHardwareException)
	{
		// 如果是硬件中断 - 一定要分发异常
		// 硬件终端
		if (Vector == INTERRUPTION_VECTOR::kPageFaultException)
		{
			// #PF 异常
			const PAGEFAULT_ERROR_CODE FaultCode = { static_cast<ULONG32>(UtilVmRead(VMCS_FIELD::kVmExitIntrErrorCode)) };
			const auto FaultAddress = UtilVmRead(VMCS_FIELD::kExitQualification);

			VmmInjectInterruption(InterruptionType, Vector, true, FaultCode.all);
			MYHYPERPLATFORM_LOG_INFO_SAFE("GuestIp= %016Ix, #PF Fault= %016Ix Code= 0x%2x", GuestContext->Ip, FaultAddress, FaultCode.all);
			// ???
			AsmWriteCR2(FaultAddress);
		}
		else if (Vector == INTERRUPTION_VECTOR::kGeneralProtectionException)
		{
			// #GP
			const auto ErrorCode = static_cast<ULONG32>(UtilVmRead(VMCS_FIELD::kVmExitIntrErrorCode));
			VmmInjectInterruption(InterruptionType, Vector, true, ErrorCode);
			MYHYPERPLATFORM_LOG_INFO_SAFE("GuestIp= %016Ix, #GP Code= 0x%2x", GuestContext->Ip, ErrorCode);
		}
		else
		{
			MYHYPERPLATFORM_COMMON_BUG_CHECK(HYPERPLATFORM_BUG_CHECK::kUnspecified, 0, 0, 0);
		}
			
	}
	else if (InterruptionType == INTERRUPTION_TYPE::kSoftwareException)
	{
		if (Vector == INTERRUPTION_VECTOR::kBreakpointException)
		{
			// #BP
			VmmInjectInterruption(InterruptionType, Vector, false, 0);
			MYHYPERPLATFORM_LOG_INFO_SAFE("GuestIp = %016Ix, #BP ", GuestContext->Ip);
			UtilVmWrite(VMCS_FIELD::kVmEntryInstructionLen, 1);
		}
		else
		{
			MYHYPERPLATFORM_COMMON_BUG_CHECK(HYPERPLATFORM_BUG_CHECK::kUnspecified, 0, 0, 0);
		}
			
	}
	else
	{
		MYHYPERPLATFORM_COMMON_BUG_CHECK(HYPERPLATFORM_BUG_CHECK::kUnspecified, 0, 0, 0);
	}
		
}

// 读取和输出 客户端的所有 VMCS Field
static void VmmDumpGuestState()
{
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest EsSelector   = %016Ix", UtilVmRead(VMCS_FIELD::kGuestEsSelector));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest CsSelector   = %016Ix", UtilVmRead(VMCS_FIELD::kGuestCsSelector));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest SsSelector   = %016Ix", UtilVmRead(VMCS_FIELD::kGuestSsSelector));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest DsSelector   = %016Ix", UtilVmRead(VMCS_FIELD::kGuestDsSelector));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest FsSelector   = %016Ix", UtilVmRead(VMCS_FIELD::kGuestFsSelector));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest GsSelector   = %016Ix", UtilVmRead(VMCS_FIELD::kGuestGsSelector));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest LdtrSelector = %016Ix", UtilVmRead(VMCS_FIELD::kGuestLdtrSelector));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest TrSelector   = %016Ix", UtilVmRead(VMCS_FIELD::kGuestTrSelector));

	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest Ia32Debugctl = %016llx", UtilVmRead64(VMCS_FIELD::kGuestIa32Debugctl));

	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest EsLimit      = %016Ix", UtilVmRead(VMCS_FIELD::kGuestEsLimit));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest CsLimit      = %016Ix", UtilVmRead(VMCS_FIELD::kGuestCsLimit));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest SsLimit      = %016Ix", UtilVmRead(VMCS_FIELD::kGuestSsLimit));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest DsLimit      = %016Ix", UtilVmRead(VMCS_FIELD::kGuestDsLimit));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest FsLimit      = %016Ix", UtilVmRead(VMCS_FIELD::kGuestFsLimit));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest GsLimit      = %016Ix", UtilVmRead(VMCS_FIELD::kGuestGsLimit));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest LdtrLimit    = %016Ix", UtilVmRead(VMCS_FIELD::kGuestLdtrLimit));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest TrLimit      = %016Ix", UtilVmRead(VMCS_FIELD::kGuestTrLimit));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest GdtrLimit    = %016Ix", UtilVmRead(VMCS_FIELD::kGuestGdtrLimit));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest IdtrLimit    = %016Ix", UtilVmRead(VMCS_FIELD::kGuestIdtrLimit));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest EsArBytes    = %016Ix", UtilVmRead(VMCS_FIELD::kGuestEsArBytes));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest CsArBytes    = %016Ix", UtilVmRead(VMCS_FIELD::kGuestCsArBytes));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest SsArBytes    = %016Ix", UtilVmRead(VMCS_FIELD::kGuestSsArBytes));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest DsArBytes    = %016Ix", UtilVmRead(VMCS_FIELD::kGuestDsArBytes));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest FsArBytes    = %016Ix", UtilVmRead(VMCS_FIELD::kGuestFsArBytes));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest GsArBytes    = %016Ix", UtilVmRead(VMCS_FIELD::kGuestGsArBytes));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest LdtrArBytes  = %016Ix", UtilVmRead(VMCS_FIELD::kGuestLdtrArBytes));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest TrArBytes    = %016Ix", UtilVmRead(VMCS_FIELD::kGuestTrArBytes));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest SysenterCs   = %016Ix", UtilVmRead(VMCS_FIELD::kGuestSysenterCs));

	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest Cr0          = %016Ix", UtilVmRead(VMCS_FIELD::kGuestCr0));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest Cr3          = %016Ix", UtilVmRead(VMCS_FIELD::kGuestCr3));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest Cr4          = %016Ix", UtilVmRead(VMCS_FIELD::kGuestCr4));

	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest EsBase       = %016Ix", UtilVmRead(VMCS_FIELD::kGuestEsBase));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest CsBase       = %016Ix", UtilVmRead(VMCS_FIELD::kGuestCsBase));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest SsBase       = %016Ix", UtilVmRead(VMCS_FIELD::kGuestSsBase));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest DsBase       = %016Ix", UtilVmRead(VMCS_FIELD::kGuestDsBase));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest FsBase       = %016Ix", UtilVmRead(VMCS_FIELD::kGuestFsBase));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest GsBase       = %016Ix", UtilVmRead(VMCS_FIELD::kGuestGsBase));

	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest LdtrBase     = %016Ix", UtilVmRead(VMCS_FIELD::kGuestLdtrBase));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest TrBase       = %016Ix", UtilVmRead(VMCS_FIELD::kGuestTrBase));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest GdtrBase     = %016Ix", UtilVmRead(VMCS_FIELD::kGuestGdtrBase));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest IdtrBase     = %016Ix", UtilVmRead(VMCS_FIELD::kGuestIdtrBase));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest Dr7          = %016Ix", UtilVmRead(VMCS_FIELD::kGuestDr7));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest Rsp          = %016Ix", UtilVmRead(VMCS_FIELD::kGuestRsp));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest Rip          = %016Ix", UtilVmRead(VMCS_FIELD::kGuestRip));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest Rflags       = %016Ix", UtilVmRead(VMCS_FIELD::kGuestRflags));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest SysenterEsp  = %016Ix", UtilVmRead(VMCS_FIELD::kGuestSysenterEsp));
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Guest SysenterEip  = %016Ix", UtilVmRead(VMCS_FIELD::kGuestSysenterEip));
}

// 调整 VM's EIP/RIP 到下一条指令
_Use_decl_annotations_ static void VmmAdjustGuestInstructionPointer(GUEST_CONTEXT* GuestContext)
{
	// 读取当前这条触发 VM-exit 指令的长度
	const auto ExitInstructionLength = UtilVmRead(VMCS_FIELD::kVmExitInstructionLen);
	UtilVmWrite(VMCS_FIELD::kGuestRip, GuestContext->Ip + ExitInstructionLength);		// 修改 EIP/RIP

	// 如果 TF 标志位被激活，注入中断 #DB
	if (GuestContext->Flag.fields.tf)
	{
		VmmInjectInterruption(INTERRUPTION_TYPE::kHardwareException, INTERRUPTION_VECTOR::kDebugException, false, 0);
		UtilVmWrite(VMCS_FIELD::kVmEntryInstructionLen, ExitInstructionLength);
	}
}

// 想客户机注入一个中断 - 4.4.3.3 P309 在VM-entry之前执行
_Use_decl_annotations_ static void VmmInjectInterruption(INTERRUPTION_TYPE InterruptionType, INTERRUPTION_VECTOR InterruptionVector, bool DeliverErrorCode, ULONG32 ErrorCode)
{
	// http://blog.csdn.net/u013358112/article/details/74530455 讲解
	VM_ENTRY_INTERRUPTION_INFORMATION_FIELD VmEntryIntrruptionInformationField = { 0 };
	VmEntryIntrruptionInformationField.fields.Valid = true;
	VmEntryIntrruptionInformationField.fields.InterruptionType = static_cast<ULONG32>(InterruptionType);
	VmEntryIntrruptionInformationField.fields.Vector = static_cast<ULONG32>(InterruptionVector);
	VmEntryIntrruptionInformationField.fields.DeliverErrorType = DeliverErrorCode;

	UtilVmWrite(VMCS_FIELD::kVmEntryIntrInfoField, VmEntryIntrruptionInformationField.all);

	// 如果分发异常码 - 将ErrorCode写回VM-entry
	if (VmEntryIntrruptionInformationField.fields.DeliverErrorType)
		UtilVmWrite(VMCS_FIELD::kVmEntryExceptionErrorCode, ErrorCode);
}

// Triple 导致的 VM-exit
_Use_decl_annotations_ static void VmmHandleTripleFault(GUEST_CONTEXT* GuestContext)
{
	VmmDumpGuestState();
	MYHYPERPLATFORM_COMMON_BUG_CHECK(HYPERPLATFORM_BUG_CHECK::kTripleFaultVmExit, reinterpret_cast<ULONG_PTR>(GuestContext), GuestContext->Ip, 0);
}

// Guest 调用 CPUID
_Use_decl_annotations_ static void VmmHandleCpuid(GUEST_CONTEXT* GuestContext)
{
	// 接管 VM 调用 CPUID
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	unsigned int CpuInfo[4] = { 0 };
	const auto FunctionId = static_cast<int>(GuestContext->GpRegister->ax);		// 读取客户端调用 CPUID 时，传入的 ax
	const auto SubFunctionId = static_cast<int>(GuestContext->GpRegister->cx);

	__cpuidex(reinterpret_cast<int*>(CpuInfo), FunctionId, SubFunctionId);
	if (FunctionId == 1)
	{
		// 显示 VMM 存在使用 HypervisorPresent bit
		CPU_FEATURES_ECX CpuFeatruesEcx = { static_cast<ULONG_PTR>(CpuInfo[2]) };
		CpuFeatruesEcx.fields.not_used = true;
		CpuInfo[2] = static_cast<int>(CpuFeatruesEcx.all);
	}
	else if (FunctionId == HyperVCpuidInterface)
		CpuInfo[0] = 'AazZ';		// 查询 HyperplatForm 是否存在

	// 写回执行结果
	GuestContext->GpRegister->ax = CpuInfo[0];
	GuestContext->GpRegister->bx = CpuInfo[1];
	GuestContext->GpRegister->cx = CpuInfo[2];
	GuestContext->GpRegister->dx = CpuInfo[3];
	// 调整 VM eip/rip
	VmmAdjustGuestInstructionPointer(GuestContext);
}

// 刷新CPU内置缓存
_Use_decl_annotations_ static void VmmHandleInvalidateInternalCaches(GUEST_CONTEXT* GuestContext)
{
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	AsmInvalidateInternalCaches();
	VmmAdjustGuestInstructionPointer(GuestContext);
}

// 刷新一块页表在转换缓存中的记录
_Use_decl_annotations_ static void VmmHandleInvalidateTlbEntry(GUEST_CONTEXT* GuestContext)
{
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

	const auto InvalidateAddress = reinterpret_cast<void*>(UtilVmRead(VMCS_FIELD::kExitQualification));
	__invlpg(InvalidateAddress);
	// 执行刷新
	UtilInvvpidIndividualAddress(static_cast<USHORT>(KeGetCurrentProcessorNumberEx(nullptr) + 1), InvalidateAddress);
	VmmAdjustGuestInstructionPointer(GuestContext);
}

// 执行 RDTSC
_Use_decl_annotations_ static void VmmHandleRdtsc(GUEST_CONTEXT* GuestContext)
{
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	ULARGE_INTEGER Tsc = { 0 };
	Tsc.QuadPart = __rdtsc();		// 得到处理器时间戳

	GuestContext->GpRegister->dx = Tsc.HighPart;
	GuestContext->GpRegister->ax = Tsc.LowPart;

	VmmAdjustGuestInstructionPointer(GuestContext);
}

// VM 尝试访问 CRx
_Use_decl_annotations_ static void VmmHandleCrAccess(GUEST_CONTEXT* GuestContext)
{
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

	const CR_ACCESS_QUALIFICATION ExitQualification = { UtilVmRead(VMCS_FIELD::kExitQualification) };

	const auto RegisterUsed = VmmSelectRegister(ExitQualification.fields.GpRegister, GuestContext);

	switch (static_cast<CR_ACCESS_TYPE>(ExitQualification.fields.AccessType))
	{
		case CR_ACCESS_TYPE::kMovToCr:
		{
			// 写入CR
			switch (ExitQualification.fields.ControlRegister)
			{
				case 0:
				{
					// mov CR0, 
					MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
					// 如果是 x86 PAE - 重新加载CR3
					if (UtilIsX86PAE())
						UtilLoadPdptes(UtilVmRead(VMCS_FIELD::kGuestCr3));

					// 重新设置CR0 - 就想初始化时那样
					const CR0 Cr0Fixed0 = { UtilReadMsr(MSR::kIa32VmxCr0Fixed0) };
					const CR0 Cr0Fixed1 = { UtilReadMsr(MSR::kIa32VmxCr0Fixed1) };

					CR0 Cr0 = { *RegisterUsed };
					Cr0.all &= Cr0Fixed1.all;
					Cr0.all |= Cr0Fixed0.all;

					UtilVmWrite(VMCS_FIELD::kGuestCr0, Cr0.all);
					UtilVmWrite(VMCS_FIELD::kCr0ReadShadow, Cr0.all);
					break;
				}
				case 3:
				{
					// mov CR3,
					MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
					if (UtilIsX86PAE())
						UtilLoadPdptes(UtilVmRead(VMCS_FIELD::kGuestCr3));

					UtilInvvpidSingleContextExceptGlobal(static_cast<USHORT>(KeGetCurrentProcessorNumberEx(nullptr) + 1));
					UtilVmWrite(VMCS_FIELD::kGuestCr3, *RegisterUsed);
					break;
				}
				case 4:
				{
					// mov CR4, 
					MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
					if (UtilIsX86PAE())
						UtilLoadPdptes(UtilVmRead(VMCS_FIELD::kGuestCr3));

					UtilInvvpidAllContext();
					const CR4 Cr4Fixed0 = { UtilReadMsr(MSR::kIa32VmxCr4Fixed0) };
					const CR4 Cr4Fixed1 = { UtilReadMsr(MSR::kIa32VmxCr4Fixed1) };
					CR4 Cr4 = { *RegisterUsed };
					Cr4.all &= Cr4Fixed1.all;
					Cr4.all |= Cr4Fixed0.all;
					UtilVmWrite(VMCS_FIELD::kGuestCr4, Cr4.all);
					UtilVmWrite(VMCS_FIELD::kCr4ReadShadow, Cr4.all);
					break;
				}
				case 8:
				{
					// mov cr8, 
					MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
					GuestContext->Cr8 = *RegisterUsed;
					break;;
				}
				default:
				{
					MYHYPERPLATFORM_COMMON_BUG_CHECK(HYPERPLATFORM_BUG_CHECK::kUnspecified, 0, 0, 0);
					break;
				}
			}
			break;	// CR_ACCESS_TYPE::kMovToCr
		}
		case CR_ACCESS_TYPE::kMovFromCr:
		{
			switch (ExitQualification.fields.ControlRegister)
			{
				case 3:
				{
					// mov ,cr3
					MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
					*RegisterUsed = UtilVmRead(VMCS_FIELD::kGuestCr3);
					break;
				}
				case 8:
				{
					// mov ,cr8
					MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
					*RegisterUsed = GuestContext->Cr8;
					break;
				}
				default:
				{
					MYHYPERPLATFORM_COMMON_BUG_CHECK(HYPERPLATFORM_BUG_CHECK::kUnspecified, 0, 0, 0);
					break;
				}				
			}
			break;	// CR_ACCESS_TYPE::kMovFromCr
		}
		case CR_ACCESS_TYPE::kClts:
		case CR_ACCESS_TYPE::kLmsw:
		default:
		{
			MYHYPERPLATFORM_COMMON_DBG_BREAK();
			break;
		}
	}

	VmmAdjustGuestInstructionPointer(GuestContext);
}

// VM 尝试访问 DRx
_Use_decl_annotations_ static void VmmHandleDrAccess(GUEST_CONTEXT* GuestContext)
{
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	const DR_ACCESS_QUALIFICATION ExitQualifaction = { UtilVmRead(VMCS_FIELD::kExitQualification) };
	const auto RegisterUsed = VmmSelectRegister(ExitQualifaction.fields.GpRegister, GuestContext);

	switch (static_cast<DR_DIRECTION_TYPE>(ExitQualifaction.fields.Direction))
	{
		case DR_DIRECTION_TYPE::kMoveToDr:
		{
			switch (ExitQualifaction.fields.DebugOneRegister)
			{
			case 0:
				__writedr(0, *RegisterUsed); break;
			case 1:
				__writedr(1, *RegisterUsed); break;
			case 2:
				__writedr(2, *RegisterUsed); break;
			case 3:
				__writedr(3, *RegisterUsed); break;
			case 4:
				__writedr(4, *RegisterUsed); break;
			case 5:
				__writedr(5, *RegisterUsed); break;
			case 6:
				__writedr(6, *RegisterUsed); break;
			case 7:
				UtilVmWrite(VMCS_FIELD::kGuestDr7, *RegisterUsed);
				break;
			}
			break;	// DR_DIRECTION_TYPE::kMoveToDr
		}
		case DR_DIRECTION_TYPE::kMoveFromDr:
		{
			switch (ExitQualifaction.fields.DebugOneRegister)
			{
				case 0:
					*RegisterUsed = __readdr(0); break;
				case 1:
					*RegisterUsed = __readdr(1); break;
				case 2:
					*RegisterUsed = __readdr(3); break;
				case 3:
					*RegisterUsed = __readdr(3); break;
				case 4:
					*RegisterUsed = __readdr(4); break;
				case 5:
					*RegisterUsed = __readdr(5); break;
				case 6:
					*RegisterUsed = __readdr(6); break;
				case 7:
					*RegisterUsed = UtilVmRead(VMCS_FIELD::kGuestDr7); break;
				default:
					break;
			}
			break;	// DR_DIRECTION_TYPE::kMoveFromDr
		}
		default:
			MYHYPERPLATFORM_COMMON_BUG_CHECK(HYPERPLATFORM_BUG_CHECK::kUnspecified, 0, 0, 0);
			break;
	}

	VmmAdjustGuestInstructionPointer(GuestContext);
}

// IN INS OUT OUTS
_Use_decl_annotations_ static void VmmHandleIoPort(GUEST_CONTEXT* GuestContext)
{
	const IO_INST_QUALIFICATION ExitQualification = { UtilVmRead(VMCS_FIELD::kExitQualification) };

	const auto IsIn = ExitQualification.fields.Direction == 1;
	const auto IsString = ExitQualification.fields.StringInstruction == 1;
	const auto IsRep = ExitQualification.fields.RepPrefixed == 1;
	const auto Port = static_cast<USHORT>(ExitQualification.fields.PortNumber);
	const auto StringAddress = reinterpret_cast<void*>((IsIn) ? GuestContext->GpRegister->di : GuestContext->GpRegister->si);
	const auto Count = static_cast<unsigned long>((IsRep) ? GuestContext->GpRegister->cx : 1);
	const auto Address = (IsString) ? StringAddress : &GuestContext->GpRegister->ax;

	SIZE_T SizeOfAccess = 0;
	const char* Suffix = "";
	switch (static_cast<IO_INST_SIZE_OF_ACCESS>(ExitQualification.fields.SizeOfAccess))
	{
		case IO_INST_SIZE_OF_ACCESS::k1Byte:
		{
			SizeOfAccess = 1;
			Suffix = "B";
			break;
		}
		case IO_INST_SIZE_OF_ACCESS::k2Byte:
		{
			SizeOfAccess = 2;
			Suffix = "W";
			break;
		}
		case IO_INST_SIZE_OF_ACCESS::k4Byte:
		{
			SizeOfAccess = 4;
			Suffix = "D";
			break;
		}
	}

	MYHYPERPLATFORM_LOG_DEBUG_SAFE("GuestIp= %016Ix, Port= %04x, %s%s%s", GuestContext->Ip, Port, (IsIn ? "IN" : "OUT"), (IsString ? "S" : ""), (IsString ? Suffix : ""));

	VmmIoWrapper(IsIn, IsString, SizeOfAccess, Port, Address, Count);

	// 更新 RCX RDI RSI
	if (IsString)
	{
		const auto UpdateCount = (IsRep) ? GuestContext->GpRegister->cx : 1;
		const auto UpdateSize = UpdateCount * SizeOfAccess;
		const auto UpdateRegister = (IsIn) ? &GuestContext->GpRegister->di : &GuestContext->GpRegister->si;

		if (GuestContext->Flag.fields.df)
			*UpdateRegister = *UpdateRegister - UpdateSize;
		else
			*UpdateRegister = *UpdateRegister + UpdateSize;

		if (IsRep)
			GuestContext->GpRegister->cx = 0;
	}

	VmmAdjustGuestInstructionPointer(GuestContext);
}

_Use_decl_annotations_ static void VmmIoWrapper(bool ToMemory, bool IsString, SIZE_T SizeOfAccess, unsigned short Port, void* Address, unsigned long Count)
{
	NT_ASSERT(SizeOfAccess == 1 || SizeOfAccess == 2 || SizeOfAccess == 4);

	// 更新 CR3 的值 - 因为下面的操作将要访问内存
	const auto GuestCr3 = UtilVmRead(VMCS_FIELD::kGuestCr3);
	const auto VmmCr3 = __readcr3();
	__writecr3(GuestCr3);

	if (ToMemory)
	{
		if (IsString)
		{
			// INS
			switch (SizeOfAccess)
			{
				case 1:
					__inbytestring(Port, reinterpret_cast<UCHAR*>(Address), Count); break;
				case 2:
					__inwordstring(Port, reinterpret_cast<USHORT*>(Address), Count); break;
				case 4:
					__indwordstring(Port, reinterpret_cast<ULONG*>(Address), Count); break;
			}
		}
		else
		{
			// IN
			switch (SizeOfAccess)
			{
				case 1:
					*reinterpret_cast<UCHAR*>(Address) = __inbyte(Port); break;
				case 2:
					*reinterpret_cast<USHORT*>(Address) = __inword(Port); break;
				case 4:
					*reinterpret_cast<ULONG*>(Address) = __indword(Port); break;
			}
		}
	}
	else
	{
		if (IsString)
		{
			// OUTS
			switch (SizeOfAccess) 
			{
				case 1: 
					__outbytestring(Port, reinterpret_cast<UCHAR*>(Address), Count); break;
				case 2: 
					__outwordstring(Port, reinterpret_cast<USHORT*>(Address), Count); break;
				case 4: 
					__outdwordstring(Port, reinterpret_cast<ULONG*>(Address), Count); break;
			}
		}
		else
		{
			// OUT
			switch (SizeOfAccess) 
			{
				case 1: 
					__outbyte(Port, *reinterpret_cast<UCHAR*>(Address)); break;
				case 2:
					__outword(Port, *reinterpret_cast<USHORT*>(Address)); break;
				case 4: 
					__outdword(Port, *reinterpret_cast<ULONG*>(Address)); break;
			}
		}
	}

	__writecr3(VmmCr3);
}

// 选择一个寄存器
_Use_decl_annotations_ static ULONG_PTR* VmmSelectRegister(ULONG Index, GUEST_CONTEXT* GuestContext)
{
	ULONG_PTR* RegisterUsed = nullptr;

	switch (Index)
	{
		case 0: 
			RegisterUsed = &GuestContext->GpRegister->ax; break;
		case 1: 
			RegisterUsed = &GuestContext->GpRegister->cx; break;
		case 2: 
			RegisterUsed = &GuestContext->GpRegister->dx; break;
		case 3: 
			RegisterUsed = &GuestContext->GpRegister->bx; break;
		case 4: 
			RegisterUsed = &GuestContext->GpRegister->sp; break;
		case 5: 
			RegisterUsed = &GuestContext->GpRegister->bp; break;
		case 6: 
			RegisterUsed = &GuestContext->GpRegister->si; break;
		case 7: 
			RegisterUsed = &GuestContext->GpRegister->di; break;
#if defined(_AMD64_)
		case 8: 
			RegisterUsed = &GuestContext->GpRegister->r8; break;
		case 9: 
			RegisterUsed = &GuestContext->GpRegister->r9; break;
		case 10: 
			RegisterUsed = &GuestContext->GpRegister->r10; break;
		case 11: 
			RegisterUsed = &GuestContext->GpRegister->r11; break;
		case 12: 
			RegisterUsed = &GuestContext->GpRegister->r12; break;
		case 13: 
			RegisterUsed = &GuestContext->GpRegister->r13; break;
		case 14: 
			RegisterUsed = &GuestContext->GpRegister->r14; break;
		case 15: 
			RegisterUsed = &GuestContext->GpRegister->r15; break;
#endif
		default: 
			MYHYPERPLATFORM_COMMON_DBG_BREAK(); break;
	}

	return RegisterUsed;
}

// RDMSR
_Use_decl_annotations_ static void VmmHandleMsrReadAccess(GUEST_CONTEXT* GuestContext)
{
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	VmmHandleMsrAccess(GuestContext, true);
}

// WRMSR
_Use_decl_annotations_ static void VmmHandleMsrWriteAccess(GUEST_CONTEXT* GuestContext)
{
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	VmmHandleMsrAccess(GuestContext, false);
}

_Use_decl_annotations_ static void VmmHandleMsrAccess(GUEST_CONTEXT* GuestContext, bool ReadAccess)
{
	const auto MsrIndex = static_cast<MSR>(GuestContext->GpRegister->cx);

	// 拦截 VM 对于指定MSR指定寄存器的访问 - 从 VMCS_FIELD 区域读取，返回给VM
	// 如果不属于拦截范围，直接读取
	bool TransferToVmcs = false;
	VMCS_FIELD VmcsField = {  };
	switch (MsrIndex)
	{
		case MSR::kIa32SysenterCs:
		{
			VmcsField = VMCS_FIELD::kGuestSysenterCs;
			TransferToVmcs = true;
			break;
		}
		case MSR::kIa32SysenterEsp:
		{
			VmcsField = VMCS_FIELD::kGuestSysenterEsp;
			TransferToVmcs = true;
			break;
		}
		case MSR::kIa32SysenterEip:
		{
			VmcsField = VMCS_FIELD::kGuestSysenterEip;
			TransferToVmcs = true;
			break;
		}
		case MSR::kIa32Debugctl:
		{
			VmcsField = VMCS_FIELD::kGuestIa32Debugctl;
			TransferToVmcs = true;
			break;
		}
		case MSR::kIa32GsBase:
		{
			VmcsField = VMCS_FIELD::kGuestGsBase;
			TransferToVmcs = true;
			break;
		}
		case MSR::kIa32FsBase:
		{
			VmcsField = VMCS_FIELD::kGuestFsBase;
			TransferToVmcs = true;
			break;
		}
		default:
			break;
	}

	// 判断 index 是否是在 64 bit编号范围内
	const auto Is64BitVmcs = UtilIsInBounds(VmcsField, VMCS_FIELD::kIoBitmapA, VMCS_FIELD::kHostIa32PerfGlobalCtrlHigh);

	LARGE_INTEGER MsrValue = { 0 };
	if (ReadAccess)	// RDMSR
	{
		// 如果拦截寄存器
		if (TransferToVmcs)
		{
			if (Is64BitVmcs)
				MsrValue.QuadPart = UtilVmRead64(VmcsField);
			else
				MsrValue.QuadPart = UtilVmRead(VmcsField);
		}
		else
			MsrValue.QuadPart = UtilReadMsr64(MsrIndex);

		GuestContext->GpRegister->ax = MsrValue.LowPart;
		GuestContext->GpRegister->dx = MsrValue.HighPart;
	}
	else // WRMSR
	{
		MsrValue.LowPart = static_cast<ULONG>(GuestContext->GpRegister->ax);
		MsrValue.HighPart = static_cast<ULONG>(GuestContext->GpRegister->dx);

		if (TransferToVmcs)
		{
			if (Is64BitVmcs)
				UtilVmWrite64(VmcsField, static_cast<ULONG64>(MsrValue.QuadPart));
			else
				UtilVmWrite(VmcsField, static_cast<ULONG_PTR>(MsrValue.QuadPart));
		}
		else
			UtilWriteMsr64(MsrIndex, MsrValue.QuadPart);
	}

	VmmAdjustGuestInstructionPointer(GuestContext);
}

// MTF VM-ext
_Use_decl_annotations_ static void VmmHandleMonitorTrap(GUEST_CONTEXT* GuestContext)
{
	VmmDumpGuestState();
	MYHYPERPLATFORM_COMMON_BUG_CHECK(HYPERPLATFORM_BUG_CHECK::kUnexpectedVmExit, reinterpret_cast<ULONG_PTR>(GuestContext), GuestContext->Ip, 0);
}

// LIDT SIDT LGDT SGDT
_Use_decl_annotations_ static void VmmHandleGdtrOrIdtrAccess(GUEST_CONTEXT* GuestContext)
{
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

	const GDTR_IDTR_INST_INFORMATION ExitQualification = { static_cast<ULONG32>(UtilVmRead(VMCS_FIELD::kVmxInstructionInfo)) };
	// 计算当前指令使用的地址
	const auto Displacement = UtilVmRead(VMCS_FIELD::kExitQualification);

	// 得到想要访问的段描述符的基地址和索引
	ULONG_PTR Base = 0;
	if (!ExitQualification.fields.BaseRegisterInvalid)
	{
		const auto RegisterUsed = VmmSelectRegister(ExitQualification.fields.BaseRegister, GuestContext);
		Base = *RegisterUsed;
	}

	ULONG_PTR Index = 0;
	if (!ExitQualification.fields.IndexRegisterInvalid)
	{
		const auto RegisterUsed = VmmSelectRegister(ExitQualification.fields.IndexRegister, GuestContext);
		Index = *RegisterUsed;

		switch (static_cast<SCALING>(ExitQualification.fields.Scalling))
		{
			case SCALING::kNoScaling:
				break;
			case SCALING::kScaleBy2:
				Index *= 2;
				break;
			case SCALING::kScaleBy4:
				Index *= 4;
				break;
			case SCALING::kScaleBy8:
				Index *= 8;
				break;
			default:
				break;
		}
	}

	auto OperationAddress = Base + Index + Displacement;
	if (static_cast<ADDRESS_SIZE>(ExitQualification.fields.AddressSize) == ADDRESS_SIZE::k32bit)
		OperationAddress &= MAXULONG;

	// 更新 CR3 准备访问内存
	const auto GuestCr3 = UtilVmRead(VMCS_FIELD::kGuestCr3);
	const auto VmmCr3 = __readcr3();
	__writecr3(GuestCr3);

	// 自己模拟指令的运行
	auto DescriptorTableRegister = reinterpret_cast<IDTR*>(OperationAddress);
	switch (static_cast<GDTR_IDTR_INST_IDENTIFY>(ExitQualification.fields.InstructionIdentity))
	{
		case GDTR_IDTR_INST_IDENTIFY::kSgdt:
			DescriptorTableRegister->Base = UtilVmRead(VMCS_FIELD::kGuestGdtrBase);
			DescriptorTableRegister->Limit = static_cast<unsigned short>(UtilVmRead(VMCS_FIELD::kGuestGdtrBase));
			break;
		case GDTR_IDTR_INST_IDENTIFY::kSidt:
			DescriptorTableRegister->Base = UtilVmRead(VMCS_FIELD::kGuestIdtrBase);
			DescriptorTableRegister->Limit = static_cast<unsigned short>(UtilVmRead(VMCS_FIELD::kGuestIdtrBase));
			break;
		case GDTR_IDTR_INST_IDENTIFY::kLgdt:
			UtilVmWrite(VMCS_FIELD::kGuestGdtrBase, DescriptorTableRegister->Base);
			UtilVmWrite(VMCS_FIELD::kGuestGdtrLimit, DescriptorTableRegister->Limit);
			break;
		case GDTR_IDTR_INST_IDENTIFY::kLidt:
			UtilVmWrite(VMCS_FIELD::kGuestIdtrBase, DescriptorTableRegister->Base);
			UtilVmWrite(VMCS_FIELD::kGuestIdtrLimit, DescriptorTableRegister->Limit);
			break;
	}

	__writecr3(VmmCr3);
	VmmAdjustGuestInstructionPointer(GuestContext);
}

// LLDT LTR SLDT STR
_Use_decl_annotations_ static void VmmHandleLdtrOrTrAccess(GUEST_CONTEXT* GuestContext)
{
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

	const LDTR_TR_INST_INFORMATION ExitQualification = { static_cast<ULONG32>(UtilVmRead(VMCS_FIELD::kVmxInstructionInfo)) };

	// 计算指令使用的地址或者寄存器
	const auto Displacement = UtilVmRead(VMCS_FIELD::kExitQualification);

	ULONG_PTR OperationAddress = 0;
	if (ExitQualification.fields.RegisterAccess)
	{
		// Register
		const auto RegisterUsed = VmmSelectRegister(ExitQualification.fields.Register1, GuestContext);
		OperationAddress = reinterpret_cast<ULONG_PTR>(RegisterUsed);
	}
	else
	{
		// 计算地址
		ULONG_PTR Base = 0;
		if (!ExitQualification.fields.BaseRegisterInvalid)
		{
			const auto RegisterUsed = VmmSelectRegister(ExitQualification.fields.BaseRegister, GuestContext);
			Base = *RegisterUsed;
		}

		ULONG_PTR Index = 0;
		if (!ExitQualification.fields.IndexRegisterInvalid)
		{
			const auto RegisterUsed = VmmSelectRegister(ExitQualification.fields.IndexRegister, GuestContext);
			Index = *RegisterUsed;

			switch (static_cast<SCALING>(ExitQualification.fields.Scalling))
			{
				case SCALING::kNoScaling:
					break;
				case SCALING::kScaleBy2:
					Index *= 2;
					break;
				case SCALING::kScaleBy4:
					Index *= 4;
					break;
				case SCALING::kScaleBy8:
					Index *= 8;
					break;
				default:
					break;
			}
		}

		OperationAddress = Base + Index + Displacement;
		if (static_cast<ADDRESS_SIZE>(ExitQualification.fields.AddressSize) == ADDRESS_SIZE::k32bit)
			OperationAddress &= MAXULONG;
	}

	// 切换 CR3
	const auto GuestCr3 = UtilVmRead(VMCS_FIELD::kGuestCr3);
	const auto VmmCr3 = __readcr3();
	__writecr3(GuestCr3);
	// 模拟指令的运行
	auto Selector = reinterpret_cast<USHORT*>(OperationAddress);
	switch (static_cast<LDTR_TR_INST_IDENTITY>(ExitQualification.fields.InstructionIdentity))
	{
		case LDTR_TR_INST_IDENTITY::kSldt:
			*Selector = static_cast<USHORT>(UtilVmRead(VMCS_FIELD::kGuestLdtrSelector));
			break;
		case LDTR_TR_INST_IDENTITY::kStr:
			*Selector = static_cast<USHORT>(UtilVmRead(VMCS_FIELD::kGuestTrSelector));
			break;
		case LDTR_TR_INST_IDENTITY::kLldt:
			UtilVmWrite(VMCS_FIELD::kGuestLdtrSelector, *Selector);
			break;
		case LDTR_TR_INST_IDENTITY::kLtr:
			UtilVmWrite(VMCS_FIELD::kGuestTrSelector, *Selector);
			break;
	}
	

	__writecr3(VmmCr3);
	VmmAdjustGuestInstructionPointer(GuestContext);
}

// 3.10.1.14 P286
_Use_decl_annotations_ static void VmmHandleEptViolation(GUEST_CONTEXT* GuestContext)
{
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	auto ProcessorData = GuestContext->Stack->ProcessorData;

	EptHandleEptViolation(ProcessorData->EptData);
}

// EXIT_REASON_EPT_MISCONFIG ??? 
_Use_decl_annotations_ static void VmmHandleEptMisconfig(GUEST_CONTEXT* GuestContext)
{
	const auto FaultAddress = UtilVmRead(VMCS_FIELD::kGuestPhysicalAddress);
	const auto EptPtEntry = EptGetEptPtEntry(GuestContext->Stack->ProcessorData->EptData, FaultAddress);

	MYHYPERPLATFORM_COMMON_BUG_CHECK(HYPERPLATFORM_BUG_CHECK::kEptMisconfigVmExit, FaultAddress, reinterpret_cast<ULONG_PTR>(EptPtEntry), 0);
}

// VMCALL
_Use_decl_annotations_ static void VmmHandleVmCall(GUEST_CONTEXT* GuestContext)
{
	// VM 调用 VMCALL 
	// ecx 保存 功能号
	// edx 参数指针

	const auto HypercallNumber = static_cast<HYPERCALL_NUMBER>(GuestContext->GpRegister->cx);
	const auto Context = reinterpret_cast<void*>(GuestContext->GpRegister->dx);

	switch (HypercallNumber)
	{
		case HYPERCALL_NUMBER::kTerminateVmm:
		{
			if (VmmGetGuestCpl() == 0)
				VmmHandleVmCallTermination(GuestContext, Context);
			else
				VmmIndicateUnsuccessfulVmcall(GuestContext);
			
			break;
		}
		case HYPERCALL_NUMBER::kPingVmm:
		{
			MYHYPERPLATFORM_LOG_INFO_SAFE("Ping by VMM! (context = %p)", Context);
			VmmIndicateSuccessfulVmcall(GuestContext);
		}
		case HYPERCALL_NUMBER::kGetSharedProcessorData:
		{
			*reinterpret_cast<void**>(Context) = GuestContext->Stack->ProcessorData->SharedData;
			VmmIndicateSuccessfulVmcall(GuestContext);
			break;
		}
		default:
			VmmIndicateUnsuccessfulVmcall(GuestContext);
			break;
	}
}

// 得到 Guest's CPL 
static UCHAR VmmGetGuestCpl()
{
	VMX_REGMENT_DESCRIPTOR_ACCESS_RIGHT AccessRight = { static_cast<unsigned int>(UtilVmRead(VMCS_FIELD::kGuestSsArBytes)) };
	return AccessRight.fields.Dpl;
}

// 处理 unloading 请求
_Use_decl_annotations_ static void VmmHandleVmCallTermination(GUEST_CONTEXT* GuestContext, void* Context)
{
	// 当VM-exit发生时，处理器将 IDT 和 GDT 的Limit设置为0xffff。但是当你调用 vmresume 指令时，它会修正值
	// 但是由于这里我们要跳过 vmresume。所以我们需要手动修正值，并直接返回到 VMCALL 执行的地方

	const auto GdtLimit = UtilVmRead(VMCS_FIELD::kGuestGdtrLimit);
	const auto GdtBase = UtilVmRead(VMCS_FIELD::kGuestGdtrBase);
	const auto IdtLimit = UtilVmRead(VMCS_FIELD::kGuestIdtrLimit);
	const auto IdtBase = UtilVmRead(VMCS_FIELD::kGuestIdtrBase);

	GDTR Gdtr = { static_cast<USHORT>(GdtLimit), GdtBase };
	IDTR Idtr = { static_cast<USHORT>(IdtLimit), IdtBase };
	__lgdt(&Gdtr);
	__lidt(&Idtr);

	// 存储执行结构体的地址 
	const auto ResultPtr = reinterpret_cast<PROCESSOR_DATA**>(Context);
	*ResultPtr = GuestContext->Stack->ProcessorData;
	MYHYPERPLATFORM_LOG_DEBUG_SAFE("Context at %p %p", Context, GuestContext->Stack->ProcessorData);

	// 设置RIP到VMCALL的下一个指令上
	const auto ExitInstructionLength = UtilVmRead(VMCS_FIELD::kVmExitInstructionLen);
	const auto ReturnAddress = GuestContext->Ip + ExitInstructionLength;
	
	// 指示 VMCALL 成功执行
	GuestContext->Flag.fields.cf = false;
	GuestContext->Flag.fields.pf = false;
	GuestContext->Flag.fields.af = false;
	GuestContext->Flag.fields.zf = false;
	GuestContext->Flag.fields.sf = false;
	GuestContext->Flag.fields.of = false;
	GuestContext->Flag.fields.cf = false;
	GuestContext->Flag.fields.zf = false;

	// 给 VMXOFF 指令传递参数
	GuestContext->GpRegister->cx = ReturnAddress;
	GuestContext->GpRegister->dx = GuestContext->GpRegister->sp;
	GuestContext->GpRegister->ax = GuestContext->Flag.all;
	GuestContext->VmContinue = false;
}

// 表明 VMCALL 失败
_Use_decl_annotations_ static void VmmIndicateUnsuccessfulVmcall(GUEST_CONTEXT* GuestContext)
{
	UNREFERENCED_PARAMETER(GuestContext);
	VmmInjectInterruption(INTERRUPTION_TYPE::kHardwareException, INTERRUPTION_VECTOR::kInvalidOpcodeException, false, 0);
	UtilVmWrite(VMCS_FIELD::kVmEntryInstructionLen, 3);	// VMCALL 长度是 3
}

// 表明 VMCALL 成功
_Use_decl_annotations_ static void VmmIndicateSuccessfulVmcall(GUEST_CONTEXT* GuestContext)
{
	GuestContext->Flag.fields.cf = false;
	GuestContext->Flag.fields.pf = false;
	GuestContext->Flag.fields.af = false;
	GuestContext->Flag.fields.zf = false;
	GuestContext->Flag.fields.sf = false;
	GuestContext->Flag.fields.of = false;
	GuestContext->Flag.fields.cf = false;
	GuestContext->Flag.fields.zf = false;

	UtilVmWrite(VMCS_FIELD::kGuestRflags, GuestContext->Flag.all);
	VmmAdjustGuestInstructionPointer(GuestContext);
}

// VMX 操作 (除了 VMCALL
_Use_decl_annotations_ static void VmmHandleVmx(GUEST_CONTEXT* GuestContext)
{
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

	GuestContext->Flag.fields.cf = true;
	GuestContext->Flag.fields.pf = false;
	GuestContext->Flag.fields.af = false;
	GuestContext->Flag.fields.zf = false;  // Error without status
	GuestContext->Flag.fields.sf = false;
	GuestContext->Flag.fields.of = false;
	UtilVmWrite(VMCS_FIELD::kGuestRflags, GuestContext->Flag.all);
	VmmAdjustGuestInstructionPointer(GuestContext);
}

// RDTSCP - 读取时间戳
_Use_decl_annotations_ static void VmmHandleRdtscp(GUEST_CONTEXT* GuestContext)
{
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	unsigned int TscAux = 0;
	ULARGE_INTEGER Tsc = { 0 };
	Tsc.QuadPart = __rdtscp(&TscAux);

	GuestContext->GpRegister->dx = Tsc.HighPart;
	GuestContext->GpRegister->ax = Tsc.LowPart;
	GuestContext->GpRegister->cx = TscAux;

	VmmAdjustGuestInstructionPointer(GuestContext);
}

// XSETBV - Set Extended Control Register
// http://www.felixcloutier.com/x86/XSETBV.html
_Use_decl_annotations_ static void VmmHandleXsetbv(GUEST_CONTEXT* GuestContext)
{
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	ULARGE_INTEGER Value = { 0 };
	Value.LowPart = static_cast<ULONG>(GuestContext->GpRegister->ax);
	Value.HighPart = static_cast<ULONG>(GuestContext->GpRegister->dx);
	_xsetbv(static_cast<ULONG>(GuestContext->GpRegister->cx), Value.QuadPart);

	VmmAdjustGuestInstructionPointer(GuestContext);
}

// 异常 VM-exit
_Use_decl_annotations_ static void VmmHandleUnexpectedExit(GUEST_CONTEXT* GuestContext)
{
	UNREFERENCED_PARAMETER(GuestContext);
	VmmDumpGuestState();
	const auto Qualification = UtilVmRead(VMCS_FIELD::kExitQualification);
	MYHYPERPLATFORM_COMMON_BUG_CHECK(HYPERPLATFORM_BUG_CHECK::kUnexpectedVmExit, reinterpret_cast<ULONG_PTR>(GuestContext), GuestContext->Ip, Qualification);
}

EXTERN_C_END



