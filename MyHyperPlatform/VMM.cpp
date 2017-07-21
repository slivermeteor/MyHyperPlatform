#include "VMM.h"
#include <intrin.h>
#include "ASM.h"
#include "Common.h"
#include "EPT.h"
#include "Log.h"
#include "Util.h"
#include "Performance.h"


EXTERN_C_START


// 决定是否记录 VM-Exit
static const long kVmmEnableRecordVmExit = false;
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
	UNREFERENCED_PARAMETER(AllRegisters);
	
}

//  分发 VM-exit 给具体的处理函数
// 3.10 P247 VM-exit 信息类字段
_Use_decl_annotations_ static void VmmHandleVmExit(GUEST_CONTEXT* GuestContext)
{
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

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
			VmmpHandleDrAccess(GuestContext);
			break;
		case VMX_EXIT_REASON::kIoInstruction:
			VmmpHandleIoPort(GuestContext);
			break;
		case VMX_EXIT_REASON::kMsrRead:
			VmmpHandleMsrReadAccess(GuestContext);
			break;
		case VMX_EXIT_REASON::kMsrWrite:
			VmmpHandleMsrWriteAccess(GuestContext);
			break;
		case VMX_EXIT_REASON::kMonitorTrapFlag:
			VmmpHandleMonitorTrap(GuestContext);
			break;
		case VMX_EXIT_REASON::kGdtrOrIdtrAccess:
			VmmpHandleGdtrOrIdtrAccess(GuestContext);
			break;
		case VMX_EXIT_REASON::kLdtrOrTrAccess:
			VmmpHandleLdtrOrTrAccess(GuestContext);
			break;
		case VMX_EXIT_REASON::kEptViolation:
			VmmpHandleEptViolation(GuestContext);
			break;
		case VMX_EXIT_REASON::kEptMisconfig:
			VmmpHandleEptMisconfig(GuestContext);
			break;
		case VMX_EXIT_REASON::kVmcall:
			VmmpHandleVmCall(GuestContext);
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
			VmmpHandleRdtscp(GuestContext);
			break;
		case VMX_EXIT_REASON::kXsetbv:
			VmmpHandleXsetbv(GuestContext);
			break;
		default:
			VmmpHandleUnexpectedExit(GuestContext);
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
			MYHYPERPLATFORM_COMMON_BUG_CHECK(HYPERPLATFORM_BUG_CHECK::kUnspecified, 0, 0, 0);
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
			MYHYPERPLATFORM_COMMON_BUG_CHECK(HYPERPLATFORM_BUG_CHECK::kUnspecified, 0, 0, 0);
	}
	else
		MYHYPERPLATFORM_COMMON_BUG_CHECK(HYPERPLATFORM_BUG_CHECK::kUnspecified, 0, 0, 0);
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

EXTERN_C_END



