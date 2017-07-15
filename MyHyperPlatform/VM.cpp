#include "VM.h"
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

	const auto SharedData = reinterpret_cast<SHARED_PROCESSOR_DATA*>(ExAllocatePoolWithTag(NonPagedPool, sizeof(SHARED_PROCESSOR_DATA), HyperPlatformCommonPoolTag));
	if (!SharedData)
		return nullptr;

	RtlZeroMemory(SharedData, sizeof(SHARED_PROCESSOR_DATA));
	MYHYPERPLATFORM_LOG_DEBUG("SharedData = %p", SharedData);

	// 启动 MSR bitmap
	SharedData->msr_bitmap = VmBuildMsrBitmap();
	if (!SharedData->msr_bitmap)
	{
		ExFreePoolWithTag(SharedData, HyperPlatformCommonPoolTag);
		return nullptr;
	}

	// 启动 IO bitmap
	const auto IoBitmaps = VmBuildIoBitmaps();
	if (!IoBitmaps)
	{
		ExFreePoolWithTag(SharedData->msr_bitmap, HyperPlatformCommonPoolTag);
		ExFreePoolWithTag(SharedData, HyperPlatformCommonPoolTag);
		return nullptr;
	}

	SharedData->io_bitmap_a = IoBitmaps;
	SharedData->io_bitmap_b = IoBitmaps + PAGE_SIZE;

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
	const auto IoBitmapA = IoBitmaps;
	const auto IoBitmapB = IoBitmaps + PAGE_SIZE;
	RtlZeroMemory(IoBitmapA, PAGE_SIZE, 0);
	RtlZeroMemory(IoBitmapB, PAGE_SIZE, 0);

	// 激活 VM-exit 在 0x10 - 0x2010  0x4010 - 0x6010 作为例子
	RTL_BITMAP BitmapAHeader = { 0 };
	RtlInitializeBitMap(&BitmapAHeader, reinterpret_cast<PULONG>(IoBitmapA), PAGE_SIZE * CHAR_BIT);
	RtlSetBits(&BitmapAHeader, 0x10, 0x2000);

	RTL_BITMAP BitmapBHeader = { 0 };
	RtlInitializeBitMap(&BitmapBHeader, reinterpret_cast<PULONG>(IoBitmapB), PAGE_SIZE * CHAR_BIT);
	RtlSetBits(&BitmapBHeader, 0x10, 0x2000);

	return IoBitmaps;
}


// 虚拟化当前处理器
_Use_decl_annotations_ static NTSTATUS VmStartVm(void* Context)
{
	PAGED_CODE();

	MYHYPERPLATFORM_LOG_INFO("Initializing VMX for the processor %d.", KeGetCurrentProcessorNumberEx(nullptr));
	const auto Ret = AsmInitializeVm(VmInitializeVm, Context);

	if (!Ret)
		return STATUS_UNSUCCESSFUL;

	MYHYPERPLATFORM_LOG_INFO("Initialized successfully.");
	return STATUS_SUCCESS;
}

// 申请虚拟化结构体，初始化VMCS区域并且虚拟化当前处理器
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

	ProcessorData->VmcsRegion = reinterpret_cast<VM_CONTROL_STRUCTURE*>(ExAllocatePoolWithTag(NonPagedPool, kVmxMaxVmcsSize, HyperPlatformCommonPoolTag));



RETURN_FALSE:

}

EXTERN_C_END