#include "VM.h"
#include <limits.h>
#include <intrin.h>
#include "Common.h"
#include "Util.h"
#include "Log.h"
#include <intrin.h>	// 编译器内部函数
#include "ASM.h"
#include "EPT.h"
#include "VMM.h"

EXTERN_C_START

_IRQL_requires_max_(PASSIVE_LEVEL) static bool VmIsMyHyperPlatformIsInstalled();
_IRQL_requires_max_(PASSIVE_LEVEL) static bool VmIsVmxAvailable();
_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS VmSetLockBitCallback(_In_opt_ void* Context);
_IRQL_requires_max_(PASSIVE_LEVEL) static SHARED_PROCESSOR_DATA* VmInitializeSharedData();
_IRQL_requires_max_(PASSIVE_LEVEL) static void* VmBuildMsrBitmap();
_IRQL_requires_max_(PASSIVE_LEVEL) static PUCHAR VmBuildIoBitmaps();

_IRQL_requires_max_(PASSIVE_LEVEL) static bool VmEnterVmxMode(_Inout_ PROCESSOR_DATA* ProcessorData);

_IRQL_requires_max_(PASSIVE_LEVEL) static bool VmSetupVmcs(_In_ const PROCESSOR_DATA* ProcessorData, _In_ ULONG_PTR GuestStackPointer, _In_ ULONG_PTR GuestInstructionPointer, _In_ ULONG_PTR VmmStackPoinetr);
_IRQL_requires_max_(PASSIVE_LEVEL) static bool VmInitializeVmcs(_Inout_ PROCESSOR_DATA* ProcessorData);

_IRQL_requires_max_(PASSIVE_LEVEL) static ULONG VmAdjustControlValue(_In_ MSR Msr, _In_ ULONG RequestedValue);

_IRQL_requires_max_(PASSIVE_LEVEL) static ULONG VmGetSegmentAccessRight(_In_ USHORT _SegmentSelector);

// 得到段选择符
_IRQL_requires_max_(PASSIVE_LEVEL) static SEGMENT_DESCRIPTOR* VmGetSegmentDescriptor(_In_ ULONG_PTR DescriptorTableBase, _In_ USHORT _SegmentSelector);
_IRQL_requires_max_(PASSIVE_LEVEL) static ULONG_PTR VmGetSegmentBaseByDescriptor(_In_ const SEGMENT_DESCRIPTOR* SegmentDescriptor);
// 根据段选择符得到基地址
_IRQL_requires_max_(PASSIVE_LEVEL) static ULONG_PTR VmGetSegmentBase(_In_ ULONG_PTR GdtBase, _In_ USHORT SegmentSelector);

_IRQL_requires_max_(PASSIVE_LEVEL) static void VmLaunchVm();

_IRQL_requires_max_(PASSIVE_LEVEL) static void VmFreeProcessorData(_In_opt_ PROCESSOR_DATA* ProcessorData);
_IRQL_requires_max_(PASSIVE_LEVEL) static void VmFreeSharedData(_In_ PROCESSOR_DATA* ProcessorData);

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS VmStartVm(_In_opt_ void* Context);
_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS VmStopVm(_In_opt_ void* Context);

_IRQL_requires_max_(PASSIVE_LEVEL) static void VmInitializeVm(_In_ ULONG_PTR GuestInstruction, _In_ ULONG_PTR GuestInstructionPointer, _In_opt_ void *Context);

_IRQL_requires_max_(PASSIVE_LEVEL) static bool VmIsHyperPlatformInstalled();

// 自己定义 GetSegmentLimit - x64自带定义
#if !defined(GetSegmentLimit)
inline ULONG GetSegmentLimit(_In_ ULONG selector) {
	return __segmentlimit(selector);
}
#endif

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(PAGE, VmInitialization)
#pragma alloc_text(PAGE, VmTermination)
#pragma alloc_text(PAGE, VmIsVmxAvailable)
#pragma alloc_text(PAGE, VmSetLockBitCallback)
#pragma alloc_text(PAGE, VmInitializeSharedData)
#pragma alloc_text(PAGE, VmBuildMsrBitmap)
#pragma alloc_text(PAGE, VmBuildIoBitmaps)
#pragma alloc_text(PAGE, VmStartVm)
#pragma alloc_text(PAGE, VmInitializeVm)
#pragma alloc_text(PAGE, VmEnterVmxMode)
#pragma alloc_text(PAGE, VmInitializeVmcs)
#pragma alloc_text(PAGE, VmSetupVmcs)
#pragma alloc_text(PAGE, VmLaunchVm)
#pragma alloc_text(PAGE, VmGetSegmentAccessRight)
#pragma alloc_text(PAGE, VmGetSegmentBase)
#pragma alloc_text(PAGE, VmGetSegmentDescriptor)
#pragma alloc_text(PAGE, VmGetSegmentBaseByDescriptor)
#pragma alloc_text(PAGE, VmAdjustControlValue)
#pragma alloc_text(PAGE, VmStopVm)
#pragma alloc_text(PAGE, VmFreeProcessorData)
#pragma alloc_text(PAGE, VmFreeSharedData)
#pragma alloc_text(PAGE, VmIsHyperPlatformInstalled)
#pragma alloc_text(PAGE, VmHotplugCallback)
#endif

//////////////////////////////////////////////////////////////////////////
//	函数实现

//  检查 VMM 是否可以安装 - 检查CPUID标志位
_Use_decl_annotations_ NTSTATUS VmInitialization()
{
	PAGED_CODE();

	// 检查是否已经安装 HyperPlatform
	if (VmIsMyHyperPlatformIsInstalled())
		return STATUS_CANCELLED;

	// 检查当前处理器是否支持VMX
	if (!VmIsVmxAvailable())
		return STATUS_HV_FEATURE_UNAVAILABLE;

	// 初始化共享数据段 - 主要是 IO map 和 MSR map
	const auto SharedData = VmInitializeSharedData();
	if (!SharedData)
		return STATUS_MEMORY_NOT_ALLOCATED;

	// 读取和存储所有 MTRR 寄存器， 用来纠正 EPT 内存类型
	EptInitializeMtrrEntries();

	// 虚拟化所有的处理器
	auto NtStatus = UtilForEachProcessor(VmStartVm, SharedData);
	if (!NT_SUCCESS(NtStatus))
	{
		UtilForEachProcessor(VmStopVm, nullptr);
		return NtStatus;
	}

	return NtStatus;
}

// 检查 MyHyperPlatform 是否已经安装
_Use_decl_annotations_ static bool VmIsMyHyperPlatformIsInstalled()
{
	PAGED_CODE();

	int CpuInfo[4] = { 0 };
	// _cpuid 这个函数往往用来查询系统对某些功能是否支持 以及开启的情况 - 比如以前用来查询当前系统的分页模式 
	// 具体查看intel指令集手册 第二卷 CPUID 指令 P760
	__cpuid(CpuInfo, 1);
	// 当FuntionIndex = 1时
	// eax = Version Information
	// ebx = Bits 07 - 00: Brand Index.
	//		 Bits 15 - 08: CLFLUSH line size(Value ∗ 8 = cache line size in bytes; used also by CLFLUSHOPT).
	//		 Bits 23 - 16 : Maximum number of addressable IDs for logical processors in this physical package*.
	//		 Bits 31 - 24 : Initial APIC ID.
	// ecx edx 每一位都由具体的含义 - 具体见intel手册
	const CPU_FEATURES_ECX CpuFeaturesEcx = { static_cast<ULONG_PTR>(CpuInfo[2]) };
	if (!CpuFeaturesEcx.fields.not_used)
		return false;

	__cpuid(CpuInfo, HyperVCpuidInterface);
	return CpuInfo[0] == 'AazZ';	// eax 返回值
}

// 检查系统是否支持VMX - 以及VMX各项功能的监测
_Use_decl_annotations_ static bool VmIsVmxAvailable()
{
	PAGED_CODE();

	// 检查标志位 CPUID.01H:ECX[5].VMX 1 - support
	int CpuInfo[4] = { 0 };
	__cpuid(CpuInfo, 1);
	CPU_FEATURES_ECX CpuFeaturesEcx = { static_cast<ULONG_PTR>(CpuInfo[2]) };
	if (!CpuFeaturesEcx.fields.vmx)
	{
		MYHYPERPLATFORM_LOG_ERROR("VMX features are not supported.");
		return false;
	}

	// 检查 VMX 其它基本能力 - 查看是否支持 write-back 
	const IA32_VMX_BASIC_MSR VmxBasicMsr = { UtilReadMsr64(MSR::kIa32VmxBasic) };
	if (static_cast<MemoryType>(VmxBasicMsr.fields.memory_type) != MemoryType::kWriteBack)
	{
		MYHYPERPLATFORM_LOG_ERROR("Write-back cache type is not supported.");
		return false;
	}

	// 有效化 VMX 并开启 VMX 
	IA32_FEATURE_CONTROL_MSR VmxFeatureControlMsr = { UtilReadMsr64(MSR::kIa32FeatureControl) };
	if (!VmxFeatureControlMsr.fields.lock)
	{
		// 如果 IA32_FEATURE_CONTROL_MSR 的lock没有上锁 - 尝试上锁
		MYHYPERPLATFORM_LOG_INFO("The IA32_FEATURE_CONTROL_MSR lock (bit 1) is 0. Attempting to set 1.");
		const NTSTATUS NtStatus = UtilForEachProcessor(VmSetLockBitCallback, nullptr);
		if (!NT_SUCCESS(NtStatus))
			return false;
	}
										   
	if (!VmxFeatureControlMsr.fields.enable_vmxon)
	{
		MYHYPERPLATFORM_LOG_ERROR("VMX features are not enabled.");
		return false;
	}

	// 检查EPT机制是否有效
	if (!EptIsEptAvailable())
	{
		MYHYPERPLATFORM_LOG_ERROR("EPT features are not enabled.");
		return false;
	}
		
	return true;
}

// 将lock的值 设置为1 锁上 IA32_FEATURE_CONTROL_MSR
_Use_decl_annotations_ static NTSTATUS VmSetLockBitCallback(void* Context)
{
	UNREFERENCED_PARAMETER(Context);
	PAGED_CODE();

	IA32_FEATURE_CONTROL_MSR Ia32FeatureControlMsr = { UtilReadMsr64(MSR::kIa32FeatureControl) };
	if (Ia32FeatureControlMsr.fields.lock)
		return STATUS_SUCCESS;

	// 读值 修改 写回
	Ia32FeatureControlMsr.fields.lock = true;
	UtilWriteMsr64(MSR::kIa32FeatureControl, Ia32FeatureControlMsr.all);
	// 重新读取 判断是否写入成功
	Ia32FeatureControlMsr.all = UtilReadMsr64(MSR::kIa32FeatureControl);
	if (!Ia32FeatureControlMsr.fields.lock)
	{
		MYHYPERPLATFORM_LOG_ERROR("IA32_FEATURE_CONTROL_MSR lock bit is still 0.");
		return STATUS_DEVICE_CONFIGURATION_ERROR;
	}

	return STATUS_SUCCESS;
}

// 初始化处理器共享数据
_Use_decl_annotations_ static SHARED_PROCESSOR_DATA* VmInitializeSharedData()
{
	PAGED_CODE();

	// 申请内存
	const auto SharedData = reinterpret_cast<SHARED_PROCESSOR_DATA*>(ExAllocatePoolWithTag(NonPagedPool, sizeof(SHARED_PROCESSOR_DATA), HyperPlatformCommonPoolTag));
	if (!SharedData)
		return nullptr;

	RtlZeroMemory(SharedData, sizeof(SHARED_PROCESSOR_DATA));
	MYHYPERPLATFORM_LOG_DEBUG("SharedData		= %p", SharedData);

	// 启动 MSR bitmap
	SharedData->MsrBitmap = VmBuildMsrBitmap();
	if (!SharedData->MsrBitmap)
	{
		ExFreePoolWithTag(SharedData, HyperPlatformCommonPoolTag);
		return nullptr;
	}

	// 启动 IO bitmap
	const auto IoBitmaps = VmBuildIoBitmaps();
	if (!IoBitmaps)
	{
		ExFreePoolWithTag(SharedData->MsrBitmap, HyperPlatformCommonPoolTag);
		ExFreePoolWithTag(SharedData, HyperPlatformCommonPoolTag);
		return nullptr;
	}

	SharedData->IoBitmapA = IoBitmaps;
	SharedData->IoBitmapB = IoBitmaps + PAGE_SIZE;

	return SharedData;
}

// 3.5.15 - MSR bitmap address 字段 - 当字段为1时，访问对应的MSR，将产生 VM-exit。address字段长度为64位。
// MSR bitmap 区域长度为 4K 大小。 分别对应低半部分和高半部分MSR的读及写访问。前2k 控制读， 后2k 控制写
// 低半部分 MSR read map 对应MSR范围 0-1FFF 用来控制这些MSR的读访问
// 高半部分 MSR read map 对应MSR范围 C0000000 - C0001FFF。用来控制这些MSR寄存器的读
// 下面又是两个跟上面一样的map - 只不过控制的是写，每个map对应的寄存器是不变的。
// 当对应的 MSR bitmap 为 0 时，对该位的MSR进行读写的时候，不会触发 VM-exit
_Use_decl_annotations_ static void* VmBuildMsrBitmap()
{
	PAGED_CODE();

	const auto MsrBitmap = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, HyperPlatformCommonPoolTag);
	if (!MsrBitmap)
		return nullptr;

	RtlZeroMemory(MsrBitmap, PAGE_SIZE);

	// 当 _readmsr 读取所有MSR 时，都进行VM-exit
	const auto BitmapReadLow = reinterpret_cast<ULONG*>(MsrBitmap);
	const auto BitmapReadHigh = BitmapReadLow + 1024;
	RtlFillMemory(BitmapReadLow, 1024, 0xFF);		// 全部填充 1
	RtlFillMemory(BitmapReadHigh, 1024, 0xFF);

	// 四个特殊MSR寄存器 不进行 VM-exit
	// 清空两个 IA32_MPETF 和 IA32_APERF -  对这两个不进行操作
	RTL_BITMAP BitmapReadLowHeader = { 0 };
	RtlInitializeBitMap(&BitmapReadLowHeader, reinterpret_cast<PULONG>(BitmapReadLow), 1024 * 8);
	RtlClearBits(&BitmapReadLowHeader, 0xE7, 2);
	
	// 尝试阅读 MSR寄存器 0 - FFFF - 如果发生 #GP 异常 清空标志位
	for (auto i = 0ul; i < 0x1000; i++)
	{
		__try
		{
			UtilReadMsr(static_cast<MSR>(i));
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			RtlClearBits(&BitmapReadLowHeader, i, 1);
		}
	}

	// 清空 IA32_GS_BASE (c0000101) IA32_KERNEL_GS_BASE (c0000102) 标志位
	RTL_BITMAP BitmapReadHighHeader = { 0 };
	RtlInitializeBitMap(&BitmapReadHighHeader, reinterpret_cast<PULONG>(BitmapReadHigh), 1024 * CHAR_BIT);
	RtlClearBits(&BitmapReadHighHeader, 0x101, 2);

	return MsrBitmap;
}

// 3.5.5  - 自己构造 IO bitmap
// IO bitmap 来控制IO指令对IO地址的访问。 IO map的每个位对应一个IO地址。当为1，访问对应的地址将产生 VM-exit. VMM 在 IO bitmap address字段中提供 IO bitmap 物理地址。
// 一共有 64K IO 空间，地址从 0000H 到 FFFFH。 64Kbyte = 8Kbit
// VMX 框架提供了 两个IO bitmap address字段。A 对应 0-7FFF B 对应 8000-FFFF
_Use_decl_annotations_ static UCHAR* VmBuildIoBitmaps()
{
	PAGED_CODE();

	// 申请两页 分别是 A B
	const auto IoBitmaps = reinterpret_cast<PUCHAR>(ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 2, HyperPlatformCommonPoolTag));
	if (!IoBitmaps)
		return nullptr;

	// 两块map 分别控制两段的访问
	const auto IoBitmapA = IoBitmaps;					// 0x0    - 0x7fff
	const auto IoBitmapB = IoBitmaps + PAGE_SIZE;	    // 0x8000 - 0xffff
	RtlZeroMemory(IoBitmapA, PAGE_SIZE);
	RtlZeroMemory(IoBitmapB, PAGE_SIZE);

	// 激活 VM-exit 在 0x10 - 0x2010  0x4010 - 0x6010 作为例子
	RTL_BITMAP BitmapAHeader = { 0 };
	RtlInitializeBitMap(&BitmapAHeader, reinterpret_cast<PULONG>(IoBitmapA), PAGE_SIZE * CHAR_BIT);
	//RtlSetBits(&BitmapAHeader, 0x10, 0x2000);

	RTL_BITMAP BitmapBHeader = { 0 };
	RtlInitializeBitMap(&BitmapBHeader, reinterpret_cast<PULONG>(IoBitmapB), PAGE_SIZE * CHAR_BIT);
	//RtlSetBits(&BitmapBHeader, 0x10, 0x2000);

	return IoBitmaps;
}


// 虚拟化当前处理器
_Use_decl_annotations_ static NTSTATUS VmStartVm(void* Context)
{
	PAGED_CODE();

	MYHYPERPLATFORM_LOG_INFO("Initializing VMX for the processor %d.", KeGetCurrentProcessorNumberEx(nullptr));
	const auto Ret = AsmInitializeVm(VmInitializeVm, Context);
	NT_ASSERT(VmIsHyperPlatformInstalled() == Ret);

	if (!Ret)
		return STATUS_UNSUCCESSFUL;

	MYHYPERPLATFORM_LOG_INFO("Initialized successfully.");
	return STATUS_SUCCESS;
}

// 申请虚拟化结构体，初始化VMCS区域并且虚拟化当前处理器
// @param GuestStackPointer	VM的栈区
// @param GuestInstructionPointer VM代码的首地址
_Use_decl_annotations_ static void VmInitializeVm(ULONG_PTR GuestStackPointer, ULONG_PTR GuestInstructionPointer, void* Context)
{
	PAGED_CODE();

	const auto SharedData = reinterpret_cast<SHARED_PROCESSOR_DATA*>(Context);
	if (!SharedData)
		return;

	// 申请相关的结构体
	const auto ProcessorData = reinterpret_cast<PROCESSOR_DATA*>(ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESSOR_DATA), HyperPlatformCommonPoolTag));
	if (!ProcessorData)
		return;
	RtlZeroMemory(ProcessorData, sizeof(PROCESSOR_DATA));
	ProcessorData->SharedData = SharedData;
	InterlockedIncrement(&ProcessorData->SharedData->ReferenceCount);

	// 启动 EPT
	ProcessorData->EptData = EptInitialization();
	if (!ProcessorData->EptData)
		goto RETURN_FALSE;
	
	// 申请其它处理器数据域
	ProcessorData->VmmStackLimit = UtilAllocateContiguousMemory(KERNEL_STACK_SIZE);
	if (!ProcessorData->VmmStackLimit)
		goto RETURN_FALSE;
	RtlZeroMemory(ProcessorData->VmmStackLimit, KERNEL_STACK_SIZE);

	ProcessorData->VmcsRegion = reinterpret_cast<VM_CONTROL_STRUCTURE*>(ExAllocatePoolWithTag(NonPagedPool, kVmxMaxVmcsSize, HyperPlatformCommonPoolTag));
	if (!ProcessorData->VmcsRegion)
		goto RETURN_FALSE;
	RtlZeroMemory(ProcessorData->VmcsRegion, kVmxMaxVmcsSize);

	ProcessorData->VmxonRegion = reinterpret_cast<VM_CONTROL_STRUCTURE*>(ExAllocatePoolWithTag(NonPagedPool, kVmxMaxVmcsSize, HyperPlatformCommonPoolTag));
	if (!ProcessorData->VmxonRegion)
		goto RETURN_FALSE;
	RtlZeroMemory(ProcessorData->VmxonRegion, kVmxMaxVmcsSize);

	// 初始化 VMM 的栈内存
	// (High)
	// +------------------+  <- vmm_stack_region_base      (eg, AED37000)
	// | processor_data   |  <- vmm_stack_data             (eg, AED36FFC)
	// +------------------+
	// | MAXULONG_PTR     |  <- vmm_stack_base (initial SP)(eg, AED36FF8)
	// +------------------+    v
	// |                  |    v
	// | (VMM Stack)      |    v (grow)
	// |                  |    v
	// +------------------+  <- vmm_stack_limit            (eg, AED34000)
	// (Low)
	const auto VmmStackRegionBase = reinterpret_cast<ULONG_PTR>(ProcessorData->VmmStackLimit) + KERNEL_STACK_SIZE;
	const auto VmmStackData = VmmStackRegionBase - sizeof(void*);
	const auto VmmStackBase = VmmStackData - sizeof(void*);

	// 输出申请结果 - 查看内存排序是否正确
	MYHYPERPLATFORM_LOG_DEBUG("VmmStackLimit           = \t%p", ProcessorData->VmmStackLimit);
	MYHYPERPLATFORM_LOG_DEBUG("VmmStackRegionBase      = \t%016Ix", VmmStackRegionBase);
	MYHYPERPLATFORM_LOG_DEBUG("VmmStackData            = \t%016Ix", VmmStackData);
	MYHYPERPLATFORM_LOG_DEBUG("VmmStackBase            = \t%016Ix", VmmStackBase);
	MYHYPERPLATFORM_LOG_DEBUG("ProcessorData           = \t%p stored at %016Ix", ProcessorData, VmmStackData);
	MYHYPERPLATFORM_LOG_DEBUG("GuestStackPointer       = \t%016Ix", GuestStackPointer);
	MYHYPERPLATFORM_LOG_DEBUG("GuestInstructionPointer = \t%016Ix", GuestInstructionPointer);

	*reinterpret_cast<ULONG_PTR*>(VmmStackBase) = MAXULONG_PTR;
	*reinterpret_cast<PROCESSOR_DATA**>(VmmStackData) = ProcessorData;

	// 进入 VMX Mode
	if (!VmEnterVmxMode(ProcessorData))
		goto RETURN_FALSE;

	// 初始化 VMCS
	if (!VmInitializeVmcs(ProcessorData))
		goto RETURN_FALSE;

	// 启动 VMCS
	if (!VmSetupVmcs(ProcessorData, GuestStackPointer, GuestInstructionPointer, VmmStackBase))
	{
		goto RETURN_FALSE_WITH_VMX_OFF;
	}

	// 开始虚拟化处理器
	VmLaunchVm();	// 如果 VmLaunch 成功，则驱动会进入 VM 中，这个函数也就不会得到返回。

	// 错误处理 - 正确执行不会进入这里
RETURN_FALSE_WITH_VMX_OFF:
	__vmx_off();
RETURN_FALSE:
	VmFreeProcessorData(ProcessorData);
}

// 进入 VMX 模式
_Use_decl_annotations_ static bool VmEnterVmxMode(PROCESSOR_DATA* ProcessorData)
{
	PAGED_CODE();

	// 2.5.10 CR0与CR4的固定位 - 进入VMX operation模式要求
	// CR0				   CR4
	// IA32_VMX_CRX_FIXED0 IA32_VMX_CRX_FIXED1 四个寄存器用来表示CR0 CR4 对应位的值
	// 当 FIXED0 寄存器的位为 1 ,CR0 CR4 对应位必须为 1
	// 当 FIXED1 寄存器的位为 0 ,CR0 CR4 对应位必须为 0
	// 同时 FIXED0 FIXED1 之间 如果 FIXED1 为 0， FIXED0 必为 1
	//						   如果 FIXED0 为 1， FIXED1 必为 0

	// 修正CR0
	const CR0 IA32_VMX_CR0_FIXED0 = { UtilReadMsr(MSR::kIa32VmxCr0Fixed0) };
	const CR0 IA32_VMX_CR0_FIXED1 = { UtilReadMsr(MSR::kIa32VmxCr0Fixed1) };

	CR0 Cr0 = { __readcr0() };
	CR0 Cr0Origin = Cr0;
	Cr0.all &= IA32_VMX_CR0_FIXED1.all;
	Cr0.all |= IA32_VMX_CR0_FIXED0.all;
	__writecr0(Cr0.all);


	MYHYPERPLATFORM_LOG_DEBUG("IA32_VMX_CR0_FIXED0   = %08Ix", IA32_VMX_CR0_FIXED0.all);
	MYHYPERPLATFORM_LOG_DEBUG("IA32_VMX_CR0_FIXED1   = %08Ix", IA32_VMX_CR0_FIXED1.all);
	MYHYPERPLATFORM_LOG_DEBUG("Original CR0          = %08Ix", Cr0Origin.all);
	MYHYPERPLATFORM_LOG_DEBUG("Fixed CR0             = %08Ix", Cr0.all);

	// 修正CR4
	const CR4 IA32_VMX_CR4_FIXED0 = { UtilReadMsr(MSR::kIa32VmxCr4Fixed0) };
	const CR4 IA32_VMX_CR4_FIXED1 = { UtilReadMsr(MSR::kIa32VmxCr4Fixed1) };
	CR4 Cr4 = { __readcr4() };
	CR4 Cr4Origin = Cr4;
	Cr4.all &= IA32_VMX_CR4_FIXED1.all;
	Cr4.all |= IA32_VMX_CR4_FIXED0.all;
	__writecr4(Cr4.all);

	MYHYPERPLATFORM_LOG_DEBUG("IA32_VMX_CR4_FIXED0   = %08Ix", IA32_VMX_CR4_FIXED0.all);
	MYHYPERPLATFORM_LOG_DEBUG("IA32_VMX_CR4_FIXED1   = %08Ix", IA32_VMX_CR4_FIXED1.all);
	MYHYPERPLATFORM_LOG_DEBUG("Original CR4          = %08Ix", Cr4Origin.all);
	MYHYPERPLATFORM_LOG_DEBUG("Fixed CR4             = %08Ix", Cr4.all);

	// VMM本身申请VMXON区域 - 从 IA32_VMX_BASIC 得到信息
	const IA32_VMX_BASIC_MSR Ia32VmxBasicMsr = { UtilReadMsr64(MSR::kIa32VmxBasic) };
	ProcessorData->VmxonRegion->RevisionIdentifier = Ia32VmxBasicMsr.fields.revision_identifier;

	auto VmxonRegionPhysicalAddr = UtilPaFromVa(ProcessorData->VmxonRegion);
	if (__vmx_on(&VmxonRegionPhysicalAddr))	// 激活 VMX
		return false;

	// cache 刷新 EPT 转换缓存
	// INVVPID
	// INVEPT
	UtilInveptGlobal();
	UtilInvvpidAllContext();

	return true;
}

// 初始化 VMCS 区域，并加载
_Use_decl_annotations_ static bool VmInitializeVmcs(PROCESSOR_DATA* ProcessodData)
{
	PAGED_CODE();

	// 写入 VMCS revison identifier
	const IA32_VMX_BASIC_MSR Ia32VmxBasicMsr = { UtilReadMsr64(MSR::kIa32VmxBasic) };
	ProcessodData->VmcsRegion->RevisionIdentifier = Ia32VmxBasicMsr.fields.revision_identifier;
	
	// 初始化 VMCS 区域，并加载
	auto VmcsRegionPhysicalAddress = UtilPaFromVa(ProcessodData->VmcsRegion);
	if (__vmx_vmclear(&VmcsRegionPhysicalAddress))
		return false;

	if (__vmx_vmptrld(&VmcsRegionPhysicalAddress))
		return false;

	return true;
}

// 准备并开启一个虚拟机
_Use_decl_annotations_ static bool VmSetupVmcs(const PROCESSOR_DATA* ProcessorData, ULONG_PTR GuestStackPointer, ULONG_PTR GuestInstructionPointer, ULONG_PTR VmmStackPoinetr)
{
	PAGED_CODE();

	// 读取 GDTR LDTR
	GDTR Gdtr = { 0 };
	__sgdt(&Gdtr);

	IDTR Idtr = { 0 };
	__sidt(&Idtr);

	// 读取 VMX 寄存器值 - 判断功能
	// 是否使用 TRUE MSR 寄存器
	const auto UseTrueMsrs = IA32_VMX_BASIC_MSR{ UtilReadMsr64(MSR::kIa32VmxBasic) }.fields.vmx_capability_hint; // [55] 字节 - 决定是否使用 TRUE 寄存器

	// 设置 VM-Entry control 字段
	VMX_VMENTRY_CONTROLS VmEntryctlRequested = { 0 };
	VmEntryctlRequested.fields.LoadDebugControls = true;
	VmEntryctlRequested.fields.Ia32eModeGuest = IsX64();
	VMX_VMENTRY_CONTROLS VmEntryctl = { VmAdjustControlValue((UseTrueMsrs) ? MSR::kIa32VmxTrueEntryCtls : MSR::kIa32VmxEntryCtls, VmEntryctlRequested.all) };

	// 设置 VM-Exit control 字段
	VMX_VMEXIT_CONTROLS VmExitctlRequested = { 0 };
	VmExitctlRequested.fields.HostAddressSpaceSize = IsX64();
	VmExitctlRequested.fields.AcknowledgeInterruptOnExit = true;
	VMX_VMEXIT_CONTROLS VmExitctl = { VmAdjustControlValue((UseTrueMsrs) ? MSR::kIa32VmxTrueExitCtls : MSR::kIa32VmxExitCtls, VmExitctlRequested.all) };

	// 设置 VM-Execution Control 字段
	VMX_PINBASED_CONTROLS VmPinctlRequested = {  };
	VMX_PINBASED_CONTROLS VmPinctl = { VmAdjustControlValue((UseTrueMsrs) ? MSR::kIa32VmxTruePinbasedCtls : MSR::kIa32VmxPinbasedCtls, VmPinctlRequested.all) };
	
	
	VMX_PROCESSOR_BASED_CONTROLS VmProcctlRequested = { };
	VmProcctlRequested.fields.Cr3LoadExiting = true;
	VmProcctlRequested.fields.MovDrExiting = true;
	VmProcctlRequested.fields.UseIoBitmap = true;
	VmProcctlRequested.fields.UseMsrBitmaps = true;
	VmProcctlRequested.fields.ActivateSecondaryControl = true;
	VMX_PROCESSOR_BASED_CONTROLS VmProcctl = { VmAdjustControlValue((UseTrueMsrs) ? MSR::kIa32VmxTrueProcBasedCtls : MSR::kIa32VmxProcBasedCtls, VmProcctlRequested.all) };

	
	VMX_SECONDARY_PROCESSOR_BASED_CONTROLS VmSeconProcctlRequested = { 0 };
	VmSeconProcctlRequested.fields.EnableEpt = true;
	VmSeconProcctlRequested.fields.DescriptorTableExiting = true;
	VmSeconProcctlRequested.fields.EnableRdtscap = true;
	VmSeconProcctlRequested.fields.EnableVpid = true;
	VmSeconProcctlRequested.fields.EnableXsavedXstors = true;
	VMX_SECONDARY_PROCESSOR_BASED_CONTROLS VmSeconProcctl = { VmAdjustControlValue(MSR::kIa32VmxProcBasedCtls2, VmSeconProcctlRequested.all) };

	// 输出设置结果
	MYHYPERPLATFORM_LOG_DEBUG("VmEntryControls                  = %08x", VmEntryctl.all);
	MYHYPERPLATFORM_LOG_DEBUG("VmExitControls                   = %08x", VmExitctl.all);
	MYHYPERPLATFORM_LOG_DEBUG("PinBasedControls                 = %08x", VmPinctl.all);
	MYHYPERPLATFORM_LOG_DEBUG("ProcessorBasedControls           = %08x", VmProcctl.all);
	MYHYPERPLATFORM_LOG_DEBUG("SecondaryProcessorBasedControls  = %08x", VmSeconProcctl.all);

	// 
	const auto ExceptionBitmap = 
		 1 << static_cast<unsigned int>(INTERRUPTION_VECTOR::kBreakpointException) |
		 1 << static_cast<unsigned int>(INTERRUPTION_VECTOR::kGeneralProtectionException) |
		 1 << static_cast<unsigned int>(INTERRUPTION_VECTOR::kPageFaultException) |
		 0;

	// 启动 CR0 和 CR4 bitmaps
	CR0 Cr0Mask = { 0 };
	CR0 Cr0Shadow = { __readcr0() };

	CR4 Cr4Mask = { 0 };
	CR4 Cr4Shadow = { __readcr4() };
	// 如果我们不想要 guest 知道 CR4.VMXE 情况，就应该注释下面
	//Cr4Mask.fields.vmxe = true;
	//Cr4Shadow.fields.vmxe = false;

	// 在 PAE 模式下，进行下列操作的时候是，PDPTE应该重新从CR3加载
	// mov cr0, x | mov cr4, x | 修改 cr0.cd cr0.nw cr0.pg cr4.pae cr4.pge cr4.pse cr4.smep
	if (UtilIsX86PAE())
	{
		Cr0Mask.fields.pg = true;
		Cr0Mask.fields.cd = true;
		Cr0Mask.fields.nw = true;

		Cr4Mask.fields.pae = true;
		Cr4Mask.fields.pge = true;
		Cr4Mask.fields.pse = true;
		Cr4Mask.fields.smep = true;
	}

	// 初始化标志位 
	auto Error = VMX_STATUS::kOk;

	// 开始 guest-state 字段 host-state 字段的赋值
	// 16 bit Control Field
	Error |= UtilVmWrite(VMCS_FIELD::kVirtualProcessorId, KeGetCurrentProcessorNumberEx(nullptr) + 1);

	// 16 Bit guest-state field
	Error |= UtilVmWrite(VMCS_FIELD::kGuestEsSelector, AsmReadES());
	Error |= UtilVmWrite(VMCS_FIELD::kGuestCsSelector, AsmReadCS());
	Error |= UtilVmWrite(VMCS_FIELD::kGuestSsSelector, AsmReadSS());
	Error |= UtilVmWrite(VMCS_FIELD::kGuestDsSelector, AsmReadDS());
	Error |= UtilVmWrite(VMCS_FIELD::kGuestFsSelector, AsmReadFS());
	Error |= UtilVmWrite(VMCS_FIELD::kGuestGsSelector, AsmReadGS());
	Error |= UtilVmWrite(VMCS_FIELD::kGuestLdtrSelector, AsmReadLDTR());
	Error |= UtilVmWrite(VMCS_FIELD::kGuestTrSelector, AsmReadTR());
	
	// 16 bit host-state field
	Error |= UtilVmWrite(VMCS_FIELD::kHostEsSelector, AsmReadES() & 0xf8);
	Error |= UtilVmWrite(VMCS_FIELD::kHostCsSelector, AsmReadCS() & 0xf8);
	Error |= UtilVmWrite(VMCS_FIELD::kHostSsSelector, AsmReadSS() & 0xf8);
	Error |= UtilVmWrite(VMCS_FIELD::kHostDsSelector, AsmReadDS() & 0xf8);
	Error |= UtilVmWrite(VMCS_FIELD::kHostFsSelector, AsmReadFS() & 0xf8);
	Error |= UtilVmWrite(VMCS_FIELD::kHostGsSelector, AsmReadGS() & 0xf8);
	Error |= UtilVmWrite(VMCS_FIELD::kHostTrSelector, AsmReadTR() & 0xf8);

	// 64 bit control-field
	Error |= UtilVmWrite64(VMCS_FIELD::kIoBitmapA, UtilPaFromVa(ProcessorData->SharedData->IoBitmapA));
	Error |= UtilVmWrite64(VMCS_FIELD::kIoBitmapB, UtilPaFromVa(ProcessorData->SharedData->IoBitmapB));
	Error |= UtilVmWrite64(VMCS_FIELD::kMsrBitmap, UtilPaFromVa(ProcessorData->SharedData->MsrBitmap));
	Error |= UtilVmWrite64(VMCS_FIELD::kEptPointer, EptGetEptPointer(ProcessorData->EptData));

	// 64-Bit Guest-State Fields 
	Error |= UtilVmWrite64(VMCS_FIELD::kVmcsLinkPointer, MAXULONG64);
	Error |= UtilVmWrite64(VMCS_FIELD::kGuestIa32Debugctl, UtilReadMsr64(MSR::kIa32Debugctl));
	if (UtilIsX86PAE()) 
	{
		UtilLoadPdptes(__readcr3());
	}

	// 32 bit control fields 
	Error |= UtilVmWrite(VMCS_FIELD::kPinBasedVmExecControl, VmPinctl.all);
	Error |= UtilVmWrite(VMCS_FIELD::kCpuBasedVmExecControl, VmProcctl.all);
	Error |= UtilVmWrite(VMCS_FIELD::kExceptionBitmap, ExceptionBitmap);
	Error |= UtilVmWrite(VMCS_FIELD::kVmExitControls, VmExitctl.all);
	Error |= UtilVmWrite(VMCS_FIELD::kVmEntryControls, VmEntryctl.all);
	Error |= UtilVmWrite(VMCS_FIELD::kSecondaryVmExecControl, VmSeconProcctl.all);

	// 32 bit guest-state-fields
	Error |= UtilVmWrite(VMCS_FIELD::kGuestEsLimit, GetSegmentLimit(AsmReadES()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestCsLimit, GetSegmentLimit(AsmReadCS()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestSsLimit, GetSegmentLimit(AsmReadSS()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestDsLimit, GetSegmentLimit(AsmReadDS()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestFsLimit, GetSegmentLimit(AsmReadFS()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestGsLimit, GetSegmentLimit(AsmReadGS()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestLdtrLimit, GetSegmentLimit(AsmReadLDTR()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestTrLimit, GetSegmentLimit(AsmReadTR()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestGdtrLimit, Gdtr.Limit);
	Error |= UtilVmWrite(VMCS_FIELD::kGuestIdtrLimit, Idtr.Limit);
	Error |= UtilVmWrite(VMCS_FIELD::kGuestEsArBytes, VmGetSegmentAccessRight(AsmReadES()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestCsArBytes, VmGetSegmentAccessRight(AsmReadCS()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestSsArBytes, VmGetSegmentAccessRight(AsmReadSS()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestDsArBytes, VmGetSegmentAccessRight(AsmReadDS()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestFsArBytes, VmGetSegmentAccessRight(AsmReadFS()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestGsArBytes, VmGetSegmentAccessRight(AsmReadGS()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestLdtrArBytes, VmGetSegmentAccessRight(AsmReadLDTR()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestTrArBytes, VmGetSegmentAccessRight(AsmReadTR()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestSysenterCs, UtilReadMsr(MSR::kIa32SysenterCs));

	// 32 bit Host-state field
	Error |= UtilVmWrite(VMCS_FIELD::kHostIa32SysenterCs, UtilReadMsr(MSR::kIa32SysenterCs));

	// Natural-width control fields
	Error |= UtilVmWrite(VMCS_FIELD::kCr0GuestHostMask, Cr0Mask.all);
	Error |= UtilVmWrite(VMCS_FIELD::kCr4GuestHostMask, Cr4Mask.all);
	Error |= UtilVmWrite(VMCS_FIELD::kCr0ReadShadow, Cr0Shadow.all);
	Error |= UtilVmWrite(VMCS_FIELD::kCr4ReadShadow, Cr4Shadow.all);

	/* Natural-Width Guest-State Fields */
	Error |= UtilVmWrite(VMCS_FIELD::kGuestCr0, __readcr0());
	Error |= UtilVmWrite(VMCS_FIELD::kGuestCr3, __readcr3());
	Error |= UtilVmWrite(VMCS_FIELD::kGuestCr4, __readcr4());
#if defined(_AMD64_)
	Error |= UtilVmWrite(VMCS_FIELD::kGuestEsBase, 0);
	Error |= UtilVmWrite(VMCS_FIELD::kGuestCsBase, 0);
	Error |= UtilVmWrite(VMCS_FIELD::kGuestSsBase, 0);
	Error |= UtilVmWrite(VMCS_FIELD::kGuestDsBase, 0);
	Error |= UtilVmWrite(VMCS_FIELD::kGuestFsBase, UtilReadMsr(Msr::kIa32FsBase));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestGsBase, UtilReadMsr(Msr::kIa32GsBase));
#else
	Error |= UtilVmWrite(VMCS_FIELD::kGuestEsBase, VmGetSegmentBase(Gdtr.Base, AsmReadES()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestCsBase, VmGetSegmentBase(Gdtr.Base, AsmReadCS()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestSsBase, VmGetSegmentBase(Gdtr.Base, AsmReadSS()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestDsBase, VmGetSegmentBase(Gdtr.Base, AsmReadDS()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestFsBase, VmGetSegmentBase(Gdtr.Base, AsmReadFS()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestGsBase, VmGetSegmentBase(Gdtr.Base, AsmReadGS()));
#endif
	Error |= UtilVmWrite(VMCS_FIELD::kGuestLdtrBase, VmGetSegmentBase(Gdtr.Base, AsmReadLDTR()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestTrBase, VmGetSegmentBase(Gdtr.Base, AsmReadTR()));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestGdtrBase, Gdtr.Base);
	Error |= UtilVmWrite(VMCS_FIELD::kGuestIdtrBase, Idtr.Base);
	Error |= UtilVmWrite(VMCS_FIELD::kGuestDr7, __readdr(7));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestRsp, GuestStackPointer);
	Error |= UtilVmWrite(VMCS_FIELD::kGuestRip, GuestInstructionPointer);		// VM 入口
	Error |= UtilVmWrite(VMCS_FIELD::kGuestRflags, __readeflags());
	Error |= UtilVmWrite(VMCS_FIELD::kGuestSysenterEsp, UtilReadMsr(MSR::kIa32SysenterEsp));
	Error |= UtilVmWrite(VMCS_FIELD::kGuestSysenterEip, UtilReadMsr(MSR::kIa32SysenterEip));

	// Natural-width Host state field
	Error |= UtilVmWrite(VMCS_FIELD::kHostCr0, __readcr0());
	Error |= UtilVmWrite(VMCS_FIELD::kHostCr3, __readcr3());
	Error |= UtilVmWrite(VMCS_FIELD::kHostCr4, __readcr4());
#if defined(_AMD64_)
	Error |= UtilVmWrite(VMCS_FIELD::kHostFsBase, UtilReadMsr(Msr::kIa32FsBase));
	Error |= UtilVmWrite(VMCS_FIELD::kHostGsBase, UtilReadMsr(Msr::kIa32GsBase));
#else
	Error |= UtilVmWrite(VMCS_FIELD::kHostFsBase, VmGetSegmentBase(Gdtr.Base, AsmReadFS()));
	Error |= UtilVmWrite(VMCS_FIELD::kHostGsBase, VmGetSegmentBase(Gdtr.Base, AsmReadGS()));
#endif
	Error |= UtilVmWrite(VMCS_FIELD::kHostTrBase, VmGetSegmentBase(Gdtr.Base, AsmReadTR()));
	Error |= UtilVmWrite(VMCS_FIELD::kHostGdtrBase, Gdtr.Base);
	Error |= UtilVmWrite(VMCS_FIELD::kHostIdtrBase, Idtr.Base);
	Error |= UtilVmWrite(VMCS_FIELD::kHostIa32SysenterEsp, UtilReadMsr(MSR::kIa32SysenterEsp));
	Error |= UtilVmWrite(VMCS_FIELD::kHostIa32SysenterEip, UtilReadMsr(MSR::kIa32SysenterEip));
	Error |= UtilVmWrite(VMCS_FIELD::kHostRsp, VmmStackPoinetr);
	Error |= UtilVmWrite(VMCS_FIELD::kHostRip, reinterpret_cast<ULONG_PTR>(AsmVmmEntryPoint));			// VMM 入口

	const auto VmxStatus = static_cast<VMX_STATUS>(Error);
	
	return VmxStatus == VMX_STATUS::kOk;
}

// 根据对应的寄存器 调整 对应的控制字段
// VM-entry VM-exit VM-function control 字段有特定的寄存器来决定它们的值。这里就是根据那些寄存器的值来调整
// 2.5.6/7/8
_Use_decl_annotations_ static ULONG VmAdjustControlValue(MSR Msr, ULONG RequestedValue)
{
	PAGED_CODE();

	LARGE_INTEGER MsrValue = { 0 };
	MsrValue.QuadPart = UtilReadMsr64(Msr);
	auto AdjustedValue = RequestedValue;

	// 高32位，允许值0 - 当寄存器为0，控制位为0
	AdjustedValue &= MsrValue.HighPart;
	// 低32位，允许值1 - 当寄存器为0，控制位为1
	AdjustedValue |= MsrValue.LowPart;

	return AdjustedValue;
}

//  得到对应段的访问权限 - 通过VMX的端选择符
_Use_decl_annotations_ static ULONG VmGetSegmentAccessRight(USHORT _SegmentSelector)
{
	PAGED_CODE();

	VMX_REGMENT_DESCRIPTOR_ACCESS_RIGHT AccessRight = { 0 };
	const SEGMENT_SELECTOR SegmentSelector = { _SegmentSelector };

	if (_SegmentSelector)
	{
		auto NativeAccessRight = AsmLoadAccessRightsByte(SegmentSelector.all);
		NativeAccessRight >>= 8;	// ???
		AccessRight.all = static_cast<ULONG>(NativeAccessRight);
		AccessRight.fields.Reserved1 = 0;
		AccessRight.fields.Reserved2 = 0;
		AccessRight.fields.Unusable = false;
	}
	else
		AccessRight.fields.Unusable = true;

	return AccessRight.all;
}

_Use_decl_annotations_ static ULONG_PTR VmGetSegmentBase(ULONG_PTR GdtBase, USHORT _SegmentSelector)
{
	PAGED_CODE();

	// 将传入的 段选择符强转类型
	const SEGMENT_SELECTOR SegmentSelector = { _SegmentSelector };
	if (!SegmentSelector.all)
		return 0;

	// 如果有 Table Index - 说明是 IDT 表项
	if (SegmentSelector.fields.Ti)
	{
		// 得到 Local Descriptor Table 所在的 GDT 表项 - 再根据表项得到 IdtBase
		const auto LocalSegmentDescriptor = VmGetSegmentDescriptor(GdtBase, AsmReadLDTR());
		const auto IdtBase = VmGetSegmentBaseByDescriptor(LocalSegmentDescriptor);

		// 得到传入的段描述符在 IDT 中的表项 - 再得到基地址
		const auto SegmentDescriptor = VmGetSegmentDescriptor(IdtBase, _SegmentSelector);
		return VmGetSegmentBaseByDescriptor(SegmentDescriptor);
	}
	else
	{
		const auto SegmentDescriptor = VmGetSegmentDescriptor(GdtBase, _SegmentSelector);
		return VmGetSegmentBaseByDescriptor(SegmentDescriptor);
	}
}

// 根据 段选择符 得到 端描述符
_Use_decl_annotations_ static SEGMENT_DESCRIPTOR* VmGetSegmentDescriptor(ULONG_PTR DescriptorTableBase, USHORT _SegmentSelector)
{
	PAGED_CODE();

	const SEGMENT_SELECTOR SegmentSelector = { _SegmentSelector };
	return reinterpret_cast<SEGMENT_DESCRIPTOR*>(DescriptorTableBase + SegmentSelector.fields.Index * sizeof(SEGMENT_DESCRIPTOR));
}

// 根据段描述符得到基地址
_Use_decl_annotations_ static ULONG_PTR VmGetSegmentBaseByDescriptor(const SEGMENT_DESCRIPTOR* SegmentDescriptor)
{
	PAGED_CODE();

	// 计算 32 bit 基地址
	const auto BaseHigh = SegmentDescriptor->fields.BaseHigh << (6 * 4);
	const auto BaseMiddle = SegmentDescriptor->fields.BaseMid << (4 * 4);
	const auto BaseLow = SegmentDescriptor->fields.BaseLow;
	ULONG_PTR Base = (BaseHigh | BaseMiddle | BaseLow) & MAXULONG;

	// 如果需要得到基地址的高 32 bit 
	if (IsX64() && !SegmentDescriptor->fields.System)
	{
		// 转换成 64位 描述符
		auto Desc64 = reinterpret_cast<const SEGMENT_DESCRIPTOR_X64*>(SegmentDescriptor);
		ULONG64 BaseUpper32 = Desc64->BaseUpper32;
		Base |= (BaseUpper32 << 32);  // 得到高地址 向高位移动32位 相或
	}

	return Base;
}

// 执行 vmlaunch
_Use_decl_annotations_ static void VmLaunchVm()
{
	PAGED_CODE();

	auto ErrorCode = UtilVmRead(VMCS_FIELD::kVmInstructionError);
	if (ErrorCode)
		MYHYPERPLATFORM_LOG_WARN("VM_INSTRUCTION_ERROR = %Iu", ErrorCode);

	auto VmxStatus = static_cast<VMX_STATUS>(__vmx_vmlaunch());

	// 如果 __vmx_vmlunch成功执行, eip 应该转向 GuestEip
	if (VmxStatus == VMX_STATUS::kErrorWithStatus)
	{
		ErrorCode = UtilVmRead(VMCS_FIELD::kVmInstructionError);
		MYHYPERPLATFORM_LOG_ERROR("VM_INSTRUCTION_ERROR = %Iu", ErrorCode);
	}

	MYHYPERPLATFORM_COMMON_DBG_BREAK();
}

_Use_decl_annotations_ static void VmFreeProcessorData(PROCESSOR_DATA* ProcessorData)
{
	PAGED_CODE();

	if (!ProcessorData)
		return;

	if (ProcessorData->VmmStackLimit)
		MmFreeContiguousMemory(ProcessorData->VmmStackLimit);

	if (ProcessorData->VmcsRegion)
		ExFreePoolWithTag(ProcessorData->VmcsRegion, HyperPlatformCommonPoolTag);

	if (ProcessorData->VmxonRegion)
		ExFreePoolWithTag(ProcessorData->VmxonRegion, HyperPlatformCommonPoolTag);

	if (ProcessorData->EptData)
		EptTermination(ProcessorData->EptData);

	VmFreeSharedData(ProcessorData);

	ExFreePoolWithTag(ProcessorData, HyperPlatformCommonPoolTag);
}

// 当引用计数为0时，释放 共享数据
_Use_decl_annotations_ static void VmFreeSharedData(PROCESSOR_DATA* ProcessorData)
{
	PAGED_CODE();

	if (!ProcessorData->SharedData)
		return;

	// 如果还有处理器在引用 - 放弃释放
	if (InterlockedDecrement(&ProcessorData->SharedData->ReferenceCount) != 0)
		return;

	MYHYPERPLATFORM_LOG_DEBUG("Free shared data...");

	//  IoBitMapB 不释放吗 ?
	if (ProcessorData->SharedData->IoBitmapA)
		ExFreePoolWithTag(ProcessorData->SharedData->IoBitmapA, HyperPlatformCommonPoolTag);

	if (ProcessorData->SharedData->MsrBitmap)
		ExFreePoolWithTag(ProcessorData->SharedData->MsrBitmap, HyperPlatformCommonPoolTag);

	ExFreePoolWithTag(ProcessorData->SharedData, HyperPlatformCommonPoolTag);
}

_Use_decl_annotations_ static NTSTATUS VmStopVm(void* Context)
{
	UNREFERENCED_PARAMETER(Context);
	PAGED_CODE();

	MYHYPERPLATFORM_LOG_INFO("Terminating VMX for the processor %d.", KeGetCurrentProcessorNumberEx(nullptr));

	// 停止虚拟化
	PROCESSOR_DATA* ProcessorData = nullptr;
	auto NtStatus = UtilVmCall(HYPERCALL_NUMBER::kTerminateVmm, &ProcessorData);
	if (!NT_SUCCESS(NtStatus))
		return NtStatus;

	// 清空 CR4,VNXE - 因为 已经 vmxoff
	CR4 Cr4 = { __readcr4() };
	Cr4.fields.vmxe = false;

	__writecr4(Cr4.all);

	VmFreeProcessorData(ProcessorData);
	return STATUS_SUCCESS;
}

// 当热插入一个处理器 - 进行虚拟化
_Use_decl_annotations_ NTSTATUS VmHotplugCallback(const PROCESSOR_NUMBER& ProcNum)
{
	PAGED_CODE();

	// 切入到第一个处理器上 - 得到 SharedData
	GROUP_AFFINITY Affinity = { 0 };
	GROUP_AFFINITY PreviousAffinity = { 0 };
	KeSetSystemGroupAffinityThread(&Affinity, &PreviousAffinity);	// 传空调用 - 切入到0号处理器

	SHARED_PROCESSOR_DATA* ShareData = nullptr;
	auto NtStatus = UtilVmCall(HYPERCALL_NUMBER::kGetSharedProcessorData, &ShareData);

	KeSetSystemGroupAffinityThread(&Affinity, &PreviousAffinity);	// 为啥再调用一次 ???

	if (!NT_SUCCESS(NtStatus))
		return NtStatus;

	if (!ShareData)
		return STATUS_UNSUCCESSFUL;

	// 切换到新的处理器上 - 进行虚拟化
	Affinity.Group = ProcNum.Group;
	Affinity.Mask = 1ull << ProcNum.Number;
	KeSetSystemGroupAffinityThread(&Affinity, &PreviousAffinity);

	NtStatus = VmStartVm(ShareData);

	KeRevertToUserGroupAffinityThread(&PreviousAffinity);	// 切换回来
	return NtStatus;
}

// 结束 VM
_Use_decl_annotations_ void VmTermination()
{
	PAGED_CODE();

	MYHYPERPLATFORM_LOG_INFO("Uninstalling VMM.");
	auto NtStatus = UtilForEachProcessor(VmStopVm, nullptr);
	if (NT_SUCCESS(NtStatus))
	{
		MYHYPERPLATFORM_LOG_INFO("The VMM has been unistalled.");
	}
	else
	{
		MYHYPERPLATFORM_LOG_INFO("The VMm has not been uninstalled (%08x).", NtStatus);
	}

	// 判断是否卸载成功
	NT_ASSERT(!VmIsHyperPlatformInstalled());
}

_Use_decl_annotations_ static bool VmIsHyperPlatformInstalled()
{
	PAGED_CODE();

	int CpuInfo[4] = { 0 };
	__cpuid(CpuInfo, 1);
	const CPU_FEATURES_ECX CputFeaturesEcx = { static_cast<ULONG_PTR>(CpuInfo[2]) };
	if (!CputFeaturesEcx.fields.not_used)
		return false;

	__cpuid(CpuInfo, HyperVCpuidInterface);
	return CpuInfo[0] == 'AazZ';
}

EXTERN_C_END