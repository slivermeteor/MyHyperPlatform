#include "Util.h"
#include <intrin.h>
#include "Common.h"
#include "Log.h"
#include "ASM.h"

EXTERN_C_START

// 根据情况使用 RtlPcToFileHeader 
// 这个函数在Win10 64位上会造成字体bug 所以有了下面这个标志位的存在
static const auto UtilUseRtlPcToFileHeader = false;

// 函数预声明 - 这个函数要自己得到地址
NTKERNELAPI PVOID NTAPI RtlPcToFileHeader(_In_ PVOID PcValue, _Out_ PVOID* BaseOfImage);
using RtlPcToFileHeaderType = decltype(RtlPcToFileHeader);

_Must_inspect_result_ _IRQL_requires_max_(DISPATCH_LEVEL) NTKERNELAPI _When_(return != NULL, _Post_writable_byte_size_(NumberOfBytes))
PVOID MmAllocateContiguousNodeMemory(_In_ SIZE_T NumberOfBytes, _In_ PHYSICAL_ADDRESS LowestAcceptableAddress, _In_ PHYSICAL_ADDRESS HighestAcceptableAddress, 
								     _In_opt_ PHYSICAL_ADDRESS BoundaryAddressMultiple, _In_ ULONG Protect, _In_ NODE_REQUIREMENT PreferredNode);
using MmAllocateContiguousNodeMemoryType = decltype(MmAllocateContiguousNodeMemory);

// dt nt!_LDR_DATA_ENTRY
typedef struct _LDR_DATA_TABLE_ENTRY_
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;

	void* DllBase;
	void* EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	// ... 不再实现 ???
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

//////////////////////////////////////////////////////////////////////////
// 函数预声明
_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS UtilInitializePageTableVariables();

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS UtilInitializeRtlPcToFileHeader(_In_ PDRIVER_OBJECT DriverObject);

_Success_(return != nullptr) static PVOID NTAPI UtilUnsafePcToFileHeader(_In_ PVOID PcValue, _Out_ PVOID* BaseOfImage);

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS UtilInitializePhysicalMemoryRanges();

_IRQL_requires_max_(PASSIVE_LEVEL) static PPHYSICAL_MEMORY_DESCRIPTOR UtilBuildPhysicalMemoryRanges();


static PHYSICAL_MEMORY_DESCRIPTOR* g_UtilPhysicalMemoryRanges = nullptr;
static RtlPcToFileHeaderType* g_UtilRtlPcToFileHeader = nullptr;
static LIST_ENTRY* g_UtilPsLoadedModuleList = nullptr;
static MmAllocateContiguousNodeMemoryType* g_UtilMmAllocateContiguousNodeMemory = nullptr;

// EPT页表的四个表的基地址
static ULONG_PTR g_UtilPXEBase = 0;
static ULONG_PTR g_UtilPPEBase = 0;
static ULONG_PTR g_UtilPDEBase = 0;
static ULONG_PTR g_UtilPTEBase = 0;

static ULONG_PTR g_UtilPXIShift = 0;
static ULONG_PTR g_UtilPPIShift = 0;
static ULONG_PTR g_UtilPDIShift = 0;
static ULONG_PTR g_UtilPTIShift = 0;

static ULONG_PTR g_UtilPXIMask = 0;
static ULONG_PTR g_UtilPPIMask = 0;
static ULONG_PTR g_UtilPDIMask = 0;
static ULONG_PTR g_UtilPTIMask = 0;

_Use_decl_annotations_ NTSTATUS UtilInitializePageTableVariables()
{
	PAGED_CODE();

#include "UtilPageConstants.h"

	// 得到系统版本 - 判断是否需要页表地址
	RTL_OSVERSIONINFOW OSVersionInfo = { sizeof(OSVersionInfo) };
	NTSTATUS NtStatus = RtlGetVersion(&OSVersionInfo);

	if (!NT_SUCCESS(NtStatus))
		return NtStatus;

	// 在 Win10 14316 之后 开启了随机页表地址
	// 对于32位系统，win7之前或者win10 14316 之前，直接采用定值
	if (!IsX64() || OSVersionInfo.dwMajorVersion < 10 || OSVersionInfo.dwBuildNumber < 14316)
	{
		if (IsX64())
		{
			// EPT页表机制 四个基地址赋值
			g_UtilPXEBase = UtilPXEBase;
			g_UtilPPEBase = UtilPPEBase;
			// 两个转换地址
			g_UtilPXIShift = UtilPXIShift;
			g_UtilPPIShift = UtilPPIShift;
			// 两个标志位的初始化
			g_UtilPXIMask = UtilPXIMask;
			g_UtilPPIMask = UtilPPIMask;
		}
		if (UtilIsX86PAE())
		{
			// EPT页表机制 四个基地址赋值
			g_UtilPXEBase = UtilPXEBase;
			g_UtilPPEBase = UtilPPEBase;
			// 两个转换地址
			g_UtilPXIShift = UtilPXIShift;
			g_UtilPPIShift = UtilPPIShift;
			// 两个标志位的初始化
			g_UtilPXIMask = UtilPXIMask;
			g_UtilPPIMask = UtilPPIMask;
		}
		else
		{
			// EPT页表机制 四个基地址赋值
			g_UtilPXEBase = UtilPXEBase;
			g_UtilPPEBase = UtilPPEBase;
			// 两个转换地址
			g_UtilPXIShift = UtilPXIShift;
			g_UtilPPIShift = UtilPPIShift;
			// 两个标志位的初始化
			g_UtilPXIMask = UtilPXIMask;
			g_UtilPPIMask = UtilPPIMask;
		}

		return NtStatus;
	}
	
	// 对于 Win10 14316 以后要自己修正 页表地址
	// 通过从MmGetVirtualForPhysical向下暴力搜索就可以得到PTE基地址 - 这个函数就是转换
	const auto pfnMmGetVirtualForPhysical = UtilGetSystemProcAddress(L"MmGetVirtualForPhysical");
	if (!pfnMmGetVirtualForPhysical)
		return STATUS_PROCEDURE_NOT_FOUND;

	static const UCHAR PatternWin10x64[] = {
		0x48, 0x8b, 0x04, 0xd0,  // mov     rax, [rax+rdx*8]
		0x48, 0xc1, 0xe0, 0x19,  // shl     rax, 19h
		0x48, 0xba,              // mov     rdx, ????????`????????  ; PTE_BASE
	};

	auto Found = reinterpret_cast<ULONG_PTR>(UtilMemSearch(pfnMmGetVirtualForPhysical, 0x30, PatternWin10x64, sizeof(PatternWin10x64)));
	if (!Found)
		return STATUS_PROCEDURE_NOT_FOUND;

	Found += sizeof(PatternWin10x64);
	MYHYPERPLATFORM_LOG_DEBUG("Found a hard coded PTE_BASE at %016Ix", Found);

	// 重新取值，得到EPT页表结构地址
	const auto PTEBase = *reinterpret_cast<ULONG_PTR*>(Found);		// 取出PTEBase
	const auto Index   = (PTEBase >> UtilPXIShift) & UtilPXIMask;	
	const auto PDEBase = PTEBase | (Index << UtilPPIShift);
	const auto PPEBase = PDEBase | (Index << UtilPDIShift);
	const auto PXEBase = PPEBase | (Index << UtilPTIShift);

	g_UtilPXEBase = static_cast<ULONG_PTR>(PXEBase);
	g_UtilPPEBase = static_cast<ULONG_PTR>(PPEBase);
	g_UtilPDEBase = static_cast<ULONG_PTR>(PDEBase);
	g_UtilPTEBase = static_cast<ULONG_PTR>(PTEBase);

	g_UtilPXIShift = UtilPXIShift;
	g_UtilPPIShift = UtilPPIShift;
	g_UtilPDIShift = UtilPDIShift;
	g_UtilPTIShift = UtilPTIShift;

	g_UtilPXIMask = UtilPXIMask;
	g_UtilPPIMask = UtilPPIMask;
	g_UtilPDIMask = UtilPDIMask;
	g_UtilPTIMask = UtilPTIMask;

	return NtStatus;
}

// 工具初始化函数
NTSTATUS UtilInitialization(PDRIVER_OBJECT DriverObject)
{
	PAGED_CODE();
	NTSTATUS NtStatus = UtilInitializePageTableVariables();
	MYHYPERPLATFORM_LOG_DEBUG("PXE at %016Ix, PPE at %016Ix, PDE at %016Ix, PTE at %016Ix", g_UtilPXEBase, g_UtilPPEBase, g_UtilPDEBase, g_UtilPTEBase);
	if (!NT_SUCCESS(NtStatus))
		return NtStatus;

	NtStatus = UtilInitializeRtlPcToFileHeader(DriverObject);
	if (!NT_SUCCESS(NtStatus))
		return NtStatus;

	NtStatus = UtilInitializePhysicalMemoryRanges();
	if (!NT_SUCCESS(NtStatus))
		return NtStatus;
	
	g_UtilMmAllocateContiguousNodeMemory = reinterpret_cast<MmAllocateContiguousNodeMemoryType*>(UtilGetSystemProcAddress(L"MmAllocateContiguousNodeMemory"));

	return NtStatus;
}

// 结束共用函数 
_Use_decl_annotations_ void UtilTermination()
{
	PAGED_CODE();

	if (g_UtilPhysicalMemoryRanges)
		ExFreePoolWithTag(g_UtilPhysicalMemoryRanges, HyperPlatformCommonPoolTag);
	
	return;
}

_Use_decl_annotations_ void* UtilMemSearch(const void* SearchBase, SIZE_T SearchSize, const void* Pattern, SIZE_T PatternSize)
{
	if (PatternSize > SearchSize)
		return nullptr;

	auto BaseAddr = static_cast<const char*>(SearchBase);
	// 搜索长度 SearchSize - PatternSize 最后一次搜索就是最后一个Pattern完整长度
	for (SIZE_T i = 0; i <= SearchSize - PatternSize; i++)
	{
		// RtlCompareMemory 函数返回的是相等的长度 (从第一个字节开始
		if (RtlCompareMemory(Pattern, &BaseAddr[i], PatternSize) == PatternSize)
			return const_cast<char*>(&BaseAddr[i]);
	}

	return nullptr;
}

// 自己实现的内核版 GetProcAddress
_Use_decl_annotations_ void* UtilGetSystemProcAddress(const wchar_t* ProcName)
{
	PAGED_CODE();

	UNICODE_STRING UniProcName = {};
	RtlInitUnicodeString(&UniProcName, ProcName);	

	return MmGetSystemRoutineAddress(&UniProcName);
}

// 判断当前机型的分页模式
bool UtilIsX86PAE()
{
	return (!IsX64() && CR4{ __readcr4() }.fields.pae);
}

// 两种得到 RtlPcToFileHeader 的方法
_Use_decl_annotations_ static NTSTATUS UtilInitializeRtlPcToFileHeader(PDRIVER_OBJECT DriverObject)
{
	PAGED_CODE();
	// 如果可以使用 - 直接得到地址
	if (UtilUseRtlPcToFileHeader)
	{
		const auto RtlPcToFileHeaderFunc = UtilGetSystemProcAddress(L"RtlPcToFileHeader");
		if (RtlPcToFileHeaderFunc)
		{
			g_UtilRtlPcToFileHeader = reinterpret_cast<RtlPcToFileHeaderType*>(RtlPcToFileHeaderFunc);
			return STATUS_SUCCESS;
		}
	}

	// 不能使用系统原生的 自己实现一个假的 - 但是有安全风险
#pragma warning(push)
#pragma warning(disable : 28175)
	auto Module = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);
#pragma warning(pop)

	g_UtilPsLoadedModuleList = Module->InLoadOrderLinks.Flink;
	g_UtilRtlPcToFileHeader = UtilUnsafePcToFileHeader;

	return STATUS_SUCCESS;
}

// 自己编写的一个 PcToFileHeader - 但是没有申请 PsLoadedModuleSpinLock
// 也就导致这个函数是不安全的，有可能在调用时，发生模块加载。而导致不安全的情况发生。
_Use_decl_annotations_ static PVOID NTAPI UtilUnsafePcToFileHeader(PVOID PcValue, PVOID* BaseOfImage)
{
	// 如果这个地址 都不在内核范围内  直接错误
	if (PcValue < MmSystemRangeStart)
		return nullptr;

	//遍历当前加载的所有模块 - 判断目标地址是否在模块内部
	const auto Head = g_UtilPsLoadedModuleList;
	for (auto Current = Head->Flink; Current != Head; Current = Current->Flink)
	{
		const auto Module = CONTAINING_RECORD(Current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		const auto DriverEnd = reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(Module->DllBase) + Module->SizeOfImage);

		if (UtilIsInBounds(PcValue, Module->DllBase, DriverEnd))
		{
			*BaseOfImage = Module->DllBase;
			return Module->DllBase;
		}
	}

	return nullptr;
}

// 初始化物理页面范围
_Use_decl_annotations_ static NTSTATUS UtilInitializePhysicalMemoryRanges()
{
	PAGED_CODE();
	// 得到页面范围
	const auto Ranges = UtilBuildPhysicalMemoryRanges();
	if (!Ranges)
		return STATUS_UNSUCCESSFUL;

	g_UtilPhysicalMemoryRanges = Ranges;
	// 遍历页面 输出信息
	for (auto i = 0ul; i < Ranges->NumberOfRuns; ++i)
	{
		// 物理页面范围
		const auto BaseAddr = static_cast<ULONG64>(Ranges->Run[i].BasePage) * PAGE_SIZE;
		MYHYPERPLATFORM_LOG_DEBUG("Physical Memory Ranges: %01611x - %01611x", BaseAddr, BaseAddr + Ranges->Run[i].PageCount * PAGE_SIZE);
		// 物理页面长度
		const auto PhysicalMemorySize = static_cast<ULONG64>(Ranges->NumberOfPages) * PAGE_SIZE;
		MYHYPERPLATFORM_LOG_DEBUG("Physical Memory Total: %llu KB", PhysicalMemorySize / 1024);
	}

	return STATUS_SUCCESS;
}

// 构造一个 PHYSICAL_MEMORY_DESCRIPTOR 结构体
_Use_decl_annotations_ static PHYSICAL_MEMORY_DESCRIPTOR* UtilBuildPhysicalMemoryRanges()
{
	PAGED_CODE();

	const auto PhysicalMemoryRanges = MmGetPhysicalMemoryRanges();
	if (!PhysicalMemoryRanges)
		return nullptr;

	PFN_COUNT NumberOfRuns = 0;
	PFN_NUMBER NumberOfPages = 0;

	for (; ; ++NumberOfRuns)
	{
		const auto Range = &PhysicalMemoryRanges[NumberOfRuns];
		if (!Range->BaseAddress.QuadPart && !Range->NumberOfBytes.QuadPart)
			break;

		NumberOfPages += static_cast<PFN_NUMBER>(BYTES_TO_PAGES(Range->NumberOfBytes.QuadPart));
	}

	if (NumberOfRuns == 0)
	{
		ExFreePoolWithTag(PhysicalMemoryRanges, 'hPmM'); // 这个标志位是确定的 ?
		return nullptr;
	}
	
	const auto MemoryBlockSize = sizeof(PHYSICAL_MEMORY_DESCRIPTOR) + sizeof(PHYSICAL_MEMORY_RUN) * (NumberOfRuns - 1);
	const auto PhyiscalMemoryBlock = reinterpret_cast<PPHYSICAL_MEMORY_DESCRIPTOR>(ExAllocatePoolWithTag(NonPagedPool, MemoryBlockSize, HyperPlatformCommonPoolTag));
	if (!PhyiscalMemoryBlock)
	{
		ExFreePoolWithTag(PhysicalMemoryRanges, 'hPmM');
		return nullptr;
	}
	RtlZeroMemory(PhyiscalMemoryBlock, MemoryBlockSize);

	PhyiscalMemoryBlock->NumberOfPages = NumberOfPages;
	PhyiscalMemoryBlock->NumberOfRuns = NumberOfRuns;

	for (auto RunIndex = 0ul; RunIndex < NumberOfRuns; RunIndex++)
	{
		auto CurrentRun = &PhyiscalMemoryBlock->Run[RunIndex];
		auto CurrentBlock = &PhysicalMemoryRanges[RunIndex];

		CurrentRun->BasePage = static_cast<ULONG_PTR>(UtilPfnFromPa(CurrentBlock->BaseAddress.QuadPart));
		CurrentRun->PageCount = static_cast<ULONG_PTR>(BYTES_TO_PAGES(CurrentBlock->NumberOfBytes.QuadPart));
	}

	ExFreePoolWithTag(PhysicalMemoryRanges, 'hPmM');
	return PhyiscalMemoryBlock;
}

// 虚拟地址 物理地址 物理地址页码 的相互转换
// PA -> PFN
_Use_decl_annotations_ PFN_NUMBER UtilPfnFromPa(ULONG64 pa)
{
	return static_cast<PFN_NUMBER>(pa >> PAGE_SHIFT);
}
// PA -> VA
_Use_decl_annotations_ PVOID UtilVaFromPa(ULONG64 pa)
{
	PHYSICAL_ADDRESS PhysicalAddress = { 0 };
	PhysicalAddress.QuadPart = pa;
	return MmGetVirtualForPhysical(PhysicalAddress);
}
// VA -> PA
_Use_decl_annotations_ ULONG64 UtilPaFromVa(void* va)
{
	const auto  pa = MmGetPhysicalAddress(va);
	return pa.QuadPart;
}
// VA -> PFN
_Use_decl_annotations_ PFN_NUMBER UtilPfnFromVa(void* va)
{
	return UtilPfnFromPa(UtilPaFromVa(va));
}
// PFN -> PA
_Use_decl_annotations_ ULONG64 UtilPaFromPfn(PFN_NUMBER pfn)
{
	return pfn << PAGE_SHIFT;
}
// PFN -> VA
_Use_decl_annotations_ void* UtilVaFromPfn(PFN_NUMBER pfn)
{
	return UtilVaFromPa(UtilPaFromPfn(pfn));
}

// MSR 读取函数
_Use_decl_annotations_ ULONG_PTR UtilReadMsr(MSR msr)
{
	return static_cast<ULONG_PTR>(__readmsr(static_cast<unsigned long>(msr)));
}

_Use_decl_annotations_ ULONG64 UtilReadMsr64(MSR msr)
{
	return __readmsr(static_cast<unsigned long>(msr));
}

_Use_decl_annotations_ void UtilWriteMsr(MSR msr, ULONG_PTR Value)
{
	__writemsr(static_cast<unsigned long>(msr), Value);

	return;
}

_Use_decl_annotations_ void UtilWriteMsr64(MSR msr, ULONG64 Value)
{
	__writemsr(static_cast<unsigned long>(msr), Value);

	return;
}

// 对所有处理器执行一个指定的回调函数在 PSSIVE_LEVEL
// 函数成功返回 STATUS_SUCCESS。只有当所有回调返回 STATUS_SUCCESS 函数才算成功。如果任何一个回调失败，函数不再调用其它回调，返回这个错误值。
_Use_decl_annotations_ NTSTATUS UtilForEachProcessor(NTSTATUS(*CallbackRoutine)(void*), void* Context)
{
	PAGED_CODE();
	// 返回活跃的处理器个数在特定的组内
	const auto NumberOfProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	// 遍历每个处理器 执行回调
	for (ULONG ProcessorIndex = 0; ProcessorIndex < NumberOfProcessors; ProcessorIndex++)
	{
		PROCESSOR_NUMBER ProcessorNumber = { 0 };
		NTSTATUS NtStatus = KeGetProcessorNumberFromIndex(ProcessorIndex, &ProcessorNumber);
		if (!NT_SUCCESS(NtStatus))
			return NtStatus;

		// 转换当前处理器
		GROUP_AFFINITY GroupAffinity = { 0 };
		GroupAffinity.Group = ProcessorNumber.Group;
		GroupAffinity.Mask = 1ull << ProcessorNumber.Number;

		GROUP_AFFINITY PreviousAffinity = { 0 };
		KeSetSystemGroupAffinityThread(&GroupAffinity, &PreviousAffinity);	// 转换

		NtStatus = CallbackRoutine(Context);

		KeRevertToUserGroupAffinityThread(&PreviousAffinity);
		if (!NT_SUCCESS(NtStatus))
			return NtStatus;
	}

	return STATUS_SUCCESS;
}


// 输出所有寄存器
_Use_decl_annotations_ void UtilDumpGpRegisters(const ALL_REGISTERS* AllRegisters, ULONG_PTR StackPointer)
{
	const auto CurrentIrql = KeGetCurrentIrql();
	if (CurrentIrql < DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();

#if defined(_AMD64_)
	MYHYPERPLATFORM_LOG_DEBUG_SAFE(
		"Context at %p: "
		"rax= %016Ix rbx= %016Ix rcx= %016Ix "
		"rdx= %016Ix rsi= %016Ix rdi= %016Ix "
		"rsp= %016Ix rbp= %016Ix "
		" r8= %016Ix  r9= %016Ix r10= %016Ix "
		"r11= %016Ix r12= %016Ix r13= %016Ix "
		"r14= %016Ix r15= %016Ix efl= %08Ix",
		_ReturnAddress(), AllRegisters->gp.ax, AllRegisters->gp.bx, AllRegisters->gp.cx,
		AllRegisters->gp.dx, AllRegisters->gp.si, AllRegisters->gp.di, StackPointer,
		AllRegisters->gp.bp, AllRegisters->gp.r8, AllRegisters->gp.r9, AllRegisters->gp.r10,
		AllRegisters->gp.r11, AllRegisters->gp.r12, AllRegisters->gp.r13, AllRegisters->gp.r14,
		AllRegisters->gp.r15, AllRegisters->flags.all);
#else
	MYHYPERPLATFORM_LOG_DEBUG_SAFE(
		"Context at %p: "
		"eax= %08Ix ebx= %08Ix ecx= %08Ix "
		"edx= %08Ix esi= %08Ix edi= %08Ix "
		"esp= %08Ix ebp= %08Ix efl= %08x",
		_ReturnAddress(), AllRegisters->gp.ax, AllRegisters->gp.bx, AllRegisters->gp.cx,
		AllRegisters->gp.dx, AllRegisters->gp.si, AllRegisters->gp.di, StackPointer,
		AllRegisters->gp.bp, AllRegisters->flags.all);
#endif

	if (CurrentIrql < DISPATCH_LEVEL)
		KeLowerIrql(CurrentIrql);
}

// 返回物理内存范围
const PHYSICAL_MEMORY_DESCRIPTOR* UtilGetPhysicalMemoryRanges()
{
	return g_UtilPhysicalMemoryRanges;
}

// 申请 连续物理内存
_Use_decl_annotations_ void* UtilAllocateContiguousMemory(SIZE_T NumberOfBytes)
{
	PHYSICAL_ADDRESS HighestAcceptableAddress = { 0 };
	HighestAcceptableAddress.QuadPart = -1;

	if (g_UtilMmAllocateContiguousNodeMemory)
	{
		// 申请 NX 物理内存
		PHYSICAL_ADDRESS LowestAcceptableAddress = { 0 };
		PHYSICAL_ADDRESS BoundaryAddressMultiple = { 0 };
		
		return g_UtilMmAllocateContiguousNodeMemory(NumberOfBytes, LowestAcceptableAddress, HighestAcceptableAddress, BoundaryAddressMultiple, PAGE_READWRITE, MM_ANY_NODE_OK);
	}
	else
	{
#pragma warning(push)
#pragma warning(disable : 30029)
		return MmAllocateContiguousMemory(NumberOfBytes, HighestAcceptableAddress);
#pragma warning(pop)
	}
}

VMX_STATUS UtilInveptGlobal()
{
	// 2.6.7.1 
	// 三种映射机制
	INV_EPT_DESCRIPTOR InvEptDescriptor = { 0 };
	return static_cast<VMX_STATUS>(AsmInvept(INV_EPT_TYPE::kGlobalInvalidation, &InvEptDescriptor));
}

// invvpid 指令一共有三种执行模式
_Use_decl_annotations_ VMX_STATUS UtilInvvpidIndividualAddress(USHORT Vpid, void* Address)
{
	INV_VPID_DESCRIPTOR InvVpidDescriptor = { 0 };
	InvVpidDescriptor.Vpid = Vpid;
	InvVpidDescriptor.LinearAddress = reinterpret_cast<ULONG64>(Address);

	return static_cast<VMX_STATUS>(AsmInvvpid(INV_VPID_TYPE::kIndividualAddressInvalidation, &InvVpidDescriptor));
}
// 第三种 全部刷新
VMX_STATUS UtilInvvpidAllContext()
{
	INV_VPID_DESCRIPTOR InvVpidDescriptor = { 0 };	
	return static_cast<VMX_STATUS>(AsmInvvpid(INV_VPID_TYPE::kAllContextInvalidation, &InvVpidDescriptor));
}

_Use_decl_annotations_ VMX_STATUS UtilVmWrite(VMCS_FIELD Field, ULONG_PTR FieldValue)
{
	return static_cast<VMX_STATUS>(__vmx_vmwrite(static_cast<size_t>(Field), FieldValue));
}

_Use_decl_annotations_ VMX_STATUS UtilVmWrite64(VMCS_FIELD Field, ULONG64 FieldValue)
{
#if defined(_AMD64_)
	return UtilVmWrite(Field, FieldValue);
#else
	// 当32位机器，操作64位域时。触发 - 这种情况下 每个域有两部分组成
	NT_ASSERT(UtilIsInBounds(Field, VMCS_FIELD::kIoBitmapA, VMCS_FIELD::kHostIa32PerfGlobalCtrlHigh));
	NT_ASSERT((static_cast<ULONG>(Field) % 2) == 0);	// 要写入的标号肯定是一个偶数 - 也就是从两个连续域的第一个域开始写

	ULARGE_INTEGER Value64 = { 0 };
	Value64.QuadPart = FieldValue;

	const auto VmxStatus = UtilVmWrite(Field, Value64.LowPart);
	if (VmxStatus != VMX_STATUS::kOk)
		return VmxStatus;

	return UtilVmWrite(static_cast<VMCS_FIELD>(static_cast<ULONG>(Field) + 1), Value64.HighPart);
#endif
}

// 从CE3 加载 PDPTE
_Use_decl_annotations_ void UtilLoadPdptes(ULONG_PTR Cr3Value)
{
	const auto CurCr3 = __readcr3();

	__writecr3(Cr3Value);

	PDPTR_REGISTER Pdptrs[4] = { 0 };
	for (auto i = 0; i < 4; i++)
	{
		const auto PdptrAddr = g_UtilPDEBase + i * PAGE_SIZE;	// PDE 之间其实是紧邻排列的
		Pdptrs[i].fields.Present = true;
		Pdptrs[i].fields.PageDirectoryPhysicalAddr = UtilPaFromVa(reinterpret_cast<void*>(PdptrAddr));
	}

	__writecr3(CurCr3);
	UtilVmWrite64(VMCS_FIELD::kGuestPdptr0, Pdptrs[0].all);
	UtilVmWrite64(VMCS_FIELD::kGuestPdptr0, Pdptrs[1].all);
	UtilVmWrite64(VMCS_FIELD::kGuestPdptr0, Pdptrs[2].all);
	UtilVmWrite64(VMCS_FIELD::kGuestPdptr0, Pdptrs[3].all);
}

// 读取 VMCS 域值
_Use_decl_annotations_ ULONG_PTR UtilVmRead(VMCS_FIELD Field)
{
	size_t FieldValue = 0;
	const auto VmxStatus = static_cast<VMX_STATUS>(__vmx_vmread(static_cast<size_t>(Field), &FieldValue));
	
	if (VmxStatus != VMX_STATUS::kOk)
	{
		MYHYPERPLATFORM_COMMON_BUG_CHECK(HYPERPLATFORM_BUG_CHECK::kCriticalVmxInstructionFailure, static_cast<ULONG_PTR>(VmxStatus), static_cast<ULONG_PTR>(Field), 0);
	}

	return FieldValue;
}

_Use_decl_annotations_ ULONG64 UtilVmRead64(VMCS_FIELD Field)
{
#if defined(_AMD64_)
	return UtilVmRead(Field);
#else
	// 只有 x86 下读取 64 bit 域才需要进行处理
	// 要连续读取两个 32 bit 自己构造
	NT_ASSERT(UtilIsInBounds(Field, VMCS_FIELD::kIoBitmapA, VMCS_FIELD::kHostIa32PerfGlobalCtrlHigh));	// 判断这个域是否是一个双 32 bit 的域
	NT_ASSERT((static_cast<ULONG>(Field) % 2) == 0);													// 要读取肯定是一个偶数 - 也就是从两个连续域的第一个域开始读

	ULARGE_INTEGER Value64 = { 0 };
	Value64.LowPart = UtilVmRead(Field);
	Value64.HighPart = UtilVmRead(static_cast<VMCS_FIELD>(static_cast<ULONG>(Field) + 1));
	
	return Value64.QuadPart;
#endif
}

_Use_decl_annotations_ NTSTATUS UtilVmCall(HYPERCALL_NUMBER HypercallNumber, void* Context)
{
	__try
	{
		const auto VmxStatus = static_cast<VMX_STATUS>(AsmVmxCall(static_cast<ULONG>(HypercallNumber), Context));

		return (VmxStatus == VMX_STATUS::kOk) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		const auto NtStatus = GetExceptionCode();
		MYHYPERPLATFORM_COMMON_DBG_BREAK();
		MYHYPERPLATFORM_LOG_WARN_SAFE("Exception thrown (code %08x)", NtStatus);
		return NtStatus;
	}
}

EXTERN_C_END