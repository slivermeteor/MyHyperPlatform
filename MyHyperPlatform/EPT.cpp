#include "EPT.h"
#include "Common.h"
#include "ASM.h"
#include "Log.h"
#include "Util.h"
#include "Performance.h"


EXTERN_C_START

//  64 位下 EPT Entries是如何描述物理地址的
//										   total 48 bits
// EPT Page map level 4 selector           9 bits 39 - 47
// EPT Page directory pointer selector     9 bits 30 - 38
// EPT Page directory selector             9 bits 21 - 39
// EPT Page table selector                 9 bits 12 - 20
// EPT Byte within page                   12 bits 0  - 11
// 于是有了下面的偏移 - 去得到对应的索引
// Get the highest 25 bits
static const auto kEptPxiShift = 39ull;
// Use 9 bits; 0b0000_0000_0000_0000_0000_0000_0001_1111_1111 - 因为每个Index有效长度都只有9位
static const auto kEptPtxMask = 0x1ffull;
// Get the highest 34 bits
static const auto kEptPpiShift = 30ull;
// Get the highest 43 bits
static const auto kEptPdiShift = 21ull;
// Get the highest 52 bits
static const auto kEptPtiShift = 12ull;

// 下面是64位地址物理地址的使用结构 
// 预申请的 EPT entry。当实际数字超过预设值，VMM触发bug
static const auto EptNumberOfPreallocatedEntries = 50;
// 
static const auto EptNumberOfMaxVariableRangeMtrrs = 255; // MTRR 规定作为 96 个内存范围 - 这个 255 自己规定的 

static const auto EptNumberOfFixedRangeMtrrs = 1 + 2 + 8; // 64K - 1 16K - 2 8K - 8

static const auto EptMtrrEntriesSize = EptNumberOfFixedRangeMtrrs + EptNumberOfMaxVariableRangeMtrrs;

// pshpack1.h poppack.h 两个就是控制结构体对齐力度的头文件 - #pragma pack(push, 1)
#include <pshpack1.h>
typedef struct _MTRR_DATA_
{
	bool      Enabled;		//<! Whether this entry is valid
	bool      FixedMtrr;		//<! Whether this entry manages a fixed range MTRR
	UCHAR     Type;			//<! Memory Type (such as WB, UC)
	bool      Reserved1;		//<! Padding
	ULONG     Reserved2;		//<! Padding
	ULONG64   RangeBase;		//<! A base address of a range managed by this entry
	ULONG64   RangeEnd;		//<! An end address of a range managed by this entry
}MTRR_DATA, *PMTRR_DATA;
#include <poppack.h>
static_assert(sizeof(_MTRR_DATA_) == 24, "Size check");

// EPT 相关结构体在 PROCESSOR_DATA
struct EPT_DATA
{
	EPT_POINTER* EptPointer;
	EPT_COMMON_ENTRY* EptPm14;
	
	EPT_COMMON_ENTRY** PreallocatedEntries;	
	volatile long PreallocatedEntriesCount;
};

static ULONG64 EptAddressToPxeIndex(_In_ ULONG64 PhysicalAddress);
static ULONG64 EptAddressToPpeIndex(_In_ ULONG64 PhysicalAddress);
static ULONG64 EptAddressToPdeIndex(_In_ ULONG64 PhysicalAddress);
static ULONG64 EptAddressToPteIndex(_In_ ULONG64 PhysicalAddress);



//
static MTRR_DATA g_EptMtrrEntries[EptMtrrEntriesSize];
static UCHAR g_EptMtrrDefaultType;

static MEMORY_TYPE EptGetMemoryType(_In_ ULONG64 PhysicalAddress);

_When_(EptData == nullptr, _IRQL_requires_max_(DISPATCH_LEVEL))
static EPT_COMMON_ENTRY* EptConstructTables(_In_ EPT_COMMON_ENTRY* Table, _In_ ULONG TableLevel, _In_ ULONG64 PhysicalAddress, _In_opt_ EPT_DATA* EptData);

static void EptDestructTables(_In_ EPT_COMMON_ENTRY* Table, _In_ ULONG TableLevel);

_Must_inspect_result_ __drv_allocatesMem(Mem)
_When_(EptData == nullptr, _IRQL_requires_max_(DISPATCH_LEVEL))
static EPT_COMMON_ENTRY* EptAllocateEptEntry(_In_opt_ EPT_DATA* EptData);

static EPT_COMMON_ENTRY* EptAllocateEptEntryFromPreAllocated(_In_ EPT_DATA* EptData);

_Must_inspect_result_ __drv_allocatesMem(Mem) _IRQL_requires_max_(DISPATCH_LEVEL)
static EPT_COMMON_ENTRY* EptAllocateEptEntryFromPool();

static void EptInitTableEntry(_In_ EPT_COMMON_ENTRY* Entry, _In_ ULONG TableLevel, _In_ ULONG64 PhysicalAddress);

static void EptFreeUnusedPreAllocatedEntries(_Pre_notnull_ __drv_allocatesMem(Mem) EPT_COMMON_ENTRY** PreallocatedEntries, _In_ long UsedCount);

static bool EptIsDeviceMemory(_In_ ULONG64 PhysicalAddress);
static EPT_COMMON_ENTRY* EptGetEptPtEntryByLevel(_In_ EPT_COMMON_ENTRY* Table, _In_ ULONG TableLevel, _In_ ULONG64 PhysicalAddress);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(PAGE, EptIsEptAvailable)
#pragma alloc_text(PAGE, EptInitializeMtrrEntries)
#pragma alloc_text(PAGE, EptInitialization)
#endif


// 监测EPT机制是否支持 - 处理器虚拟化 2.5.12
_Use_decl_annotations_ bool EptIsEptAvailable()
{
	PAGED_CODE();

	// 首先对于能否读取 IA32_VMX_EPT_VPID_CAP 寄存器也是有要求的
	// 检查下面的标志位: 
	// bit 6: 是否支持4级页表
	// bit 14: 是否支持WB类型
	// 

	IA32_VMX_EPT_VPID_CAP Ia32VmxEptVpidCap = { UtilReadMsr64(MSR::kIa32VmxEptVpidCap) };
	if (!Ia32VmxEptVpidCap.fields.support_page_walk_length4			 || !Ia32VmxEptVpidCap.fields.support_write_back_memory_type  ||
		!Ia32VmxEptVpidCap.fields.support_invept				     || !Ia32VmxEptVpidCap.fields.support_single_context_invept   ||
		!Ia32VmxEptVpidCap.fields.support_all_context_invept		 || !Ia32VmxEptVpidCap.fields.support_invvpid			      ||
		!Ia32VmxEptVpidCap.fields.support_individual_address_invvpid || !Ia32VmxEptVpidCap.fields.support_single_context_invvpid  ||
		!Ia32VmxEptVpidCap.fields.support_all_context_invvpid		 || !Ia32VmxEptVpidCap.fields.support_single_context_retaining_globals_invvpid)	
		return false;
	
	return true;
}

// 返回 EPT Pointer
_Use_decl_annotations_ ULONG64 EptGetEptPointer(EPT_DATA* EptData)
{
	return EptData->EptPointer->all;
}

// 读取所有的MTRR - 并构造对应的 MTRR_DATA
// 相关阅读 http://blog.csdn.net/lightseed/article/details/4603383 
// intel 手册 Volume 3 11.11
_Use_decl_annotations_ void EptInitializeMtrrEntries()
{
	PAGED_CODE();

	int Index = 0;
	MTRR_DATA* MtrrEntries = g_EptMtrrEntries;

	// 读取和存储默认的内存类型
	IA32_MTRR_DEFAULT_TYPE_MSR Ia32MtrrDefaultTypeMsr = { UtilReadMsr64(MSR::kIa32MtrrDefType) };
	g_EptMtrrDefaultType = Ia32MtrrDefaultTypeMsr.fields.DefaultMemoryType;

	// 读取 MTRR Capability 寄存器
	IA32_MTRR_CAPABILITIES_MSR Ia32MtrrCapabilitiesMsr = { UtilReadMsr64(MSR::kIa32MtrrCap) };
	MYHYPERPLATFORM_LOG_DEBUG(
		"MTRR Default=%lld, VariableCount=%lld, FixedSupported=%lld, FixedEnabled=%lld",
		Ia32MtrrDefaultTypeMsr.fields.DefaultMemoryType,
		Ia32MtrrCapabilitiesMsr.fields.VariableRangeCount,
		Ia32MtrrCapabilitiesMsr.fields.FixedRangeSupported,
		Ia32MtrrDefaultTypeMsr.fields.FixedMtrrsEnabled);

	// 读取 FIXED MTRR - 构造对应的 MTRR_ENTRIES
	//								是否支持 Fixed Range？							        是否启用 Fixed Range?
	if (Ia32MtrrCapabilitiesMsr.fields.FixedRangeSupported && Ia32MtrrDefaultTypeMsr.fields.FixedMtrrsEnabled)
	{
		// Fixed 管理基地址和每个范围的长度都是固定的。
		static const auto k64kBase = 0x0;
		static const auto k64kManagedSize = 0x10000;
		static const auto k16kBase = 0x80000;
		static const auto k16kManagedSize = 0x4000;
		static const auto k4kBase = 0xC0000;
		static const auto k4kManagedSize = 0x1000;

		// FIXED_64K 对齐长度 0x10000
		ULONG64 offset = 0;
		IA32_MTRR_FIXED_RANGE_MSR FixedRange = { UtilReadMsr64(MSR::kIa32MtrrFix64k00000) };
		for (auto MemoryType : FixedRange.fields.types)
		{
			ULONG64 Base = k64kBase + offset;
			offset += k64kManagedSize;

			// 保存 MTRR
			MtrrEntries[Index].Enabled = true;
			MtrrEntries[Index].FixedMtrr = true;
			MtrrEntries[Index].Type = MemoryType;
			MtrrEntries[Index].RangeBase = Base;
			MtrrEntries[Index].RangeEnd = Base + k64kManagedSize - 1;
			Index++;
		}
		NT_ASSERT(k64kBase + offset == k16kBase);

		// FIXED_16K 对齐长度 0x4000
		offset = 0;
		for (auto FixedMsr = static_cast<ULONG>(MSR::kIa32MtrrFix16k80000); FixedMsr <= static_cast<ULONG>(MSR::kIa32MtrrFix16kA0000); FixedMsr++)
		{
			// 读取对应的 FIXED_MSR
			FixedRange.all = UtilReadMsr64(static_cast<MSR>(FixedMsr));
			// 每个 16k 长度
			for (auto MemoryType : FixedRange.fields.types)
			{
				//  16K 对齐
				ULONG64 Base = k16kBase + offset;
				offset += k16kManagedSize;

				// 保存 MTRR_ENTRY
				MtrrEntries[Index].Enabled = true;
				MtrrEntries[Index].FixedMtrr = true;
				MtrrEntries[Index].Type = MemoryType;
				MtrrEntries[Index].RangeBase = Base;
				MtrrEntries[Index].RangeEnd = Base + k16kManagedSize - 1;	// 注意这个 - 1
				Index++;
			}
		}
		NT_ASSERT(k16kBase + offset == k4kBase);

		// FIX_4K - 对齐长度 0x1000
		offset = 0;
		for (auto FixedMsr = static_cast<ULONG>(MSR::kIa32MtrrFix4kC0000); FixedMsr <= static_cast<ULONG>(MSR::kIa32MtrrFix4kF8000); FixedMsr++)
		{
			FixedRange.all = UtilReadMsr64(static_cast<MSR>(FixedMsr));
			
			for (auto MemoryType : FixedRange.fields.types)
			{
				ULONG64 Base = k4kBase + offset;
				offset += k4kManagedSize;

				MtrrEntries[Index].Enabled = true;
				MtrrEntries[Index].FixedMtrr = true;
				MtrrEntries[Index].Type = MemoryType;
				MtrrEntries[Index].RangeBase = Base;
				MtrrEntries[Index].RangeEnd = Base + k4kManagedSize - 1;
				Index++;
			}
		}
		NT_ASSERT(k4kBase + offset == 0x100000);
	}

	// 读取所有 Variable-Range 构造 MTRR_ENTRY
	// Variable-Range寄存器是一队(两两绑定) 第一个指示 PHYSICAL_BASE 第二个指示 PHYSICAL_MASK 
	for (auto i = 0; i < Ia32MtrrCapabilitiesMsr.fields.VariableRangeCount; i++)
	{
		// 读取对应的 MTRR mask并且检查是否在使用中
		const auto PhysicalMask = static_cast<ULONG>(MSR::kIa32MtrrPhysMaskN) + i * 2; // Mask - 每队中的第二个寄存器 
		IA32_MTRR_PHYSICAL_MASK_MSR Ia32MtrrPhysicalMaskMsr = { UtilReadMsr64(static_cast<MSR>(PhysicalMask)) };
		if (!Ia32MtrrPhysicalMaskMsr.fields.valid)
			continue;

		// 得到 Variable-Range 的长度 
		ULONG Length = 0;
		BitScanForward64(&Length, Ia32MtrrPhysicalMaskMsr.fields.phys_mask * PAGE_SIZE); // * PAGE_SIZE 相当于 << 3(左移三位)
		

		const auto PhysicalBase = static_cast<ULONG>(MSR::kIa32MtrrPhysBaseN) + i * 2;
		IA32_MTRR_PHYSICAL_BASE_MSR Ia32MtrrPhysicalBaseMsr = { UtilReadMsr64(static_cast<MSR>(PhysicalBase)) };
		ULONG64 Base = Ia32MtrrPhysicalBaseMsr.fields.phys_base * PAGE_SIZE;
		ULONG64 End = Base + (1ull << Length) - 1;		// AddressWithin & Mask = Base & Mask -> 这个例子告诉我们 Mask 应该是将低位可能变化的位
												        // 都变成了0, 并且范围肯定是 4K 对齐的。那么我们只要得到有多少位是变化的，再加上 base 就是 end 
														// 其实就是 * 2 ... 

		MtrrEntries[Index].Enabled = true;
		MtrrEntries[Index].FixedMtrr = false;
		MtrrEntries[Index].Type = Ia32MtrrPhysicalBaseMsr.fields.type;
		MtrrEntries[Index].RangeBase = Base;
		MtrrEntries[Index].RangeEnd = End;
		Index++;
	}
	
}

_Use_decl_annotations_ EPT_DATA* EptInitialization()
{
	PAGED_CODE();
	static const auto EptPageWalkLevel = 4ul;

	// 申请 EPT_DATA
	const auto EptData = reinterpret_cast<EPT_DATA*>(ExAllocatePoolWithTag(NonPagedPool, sizeof(EPT_DATA), HyperPlatformCommonPoolTag));
	if (!EptData)
		return nullptr;

	RtlZeroMemory(EptData, sizeof(EPT_DATA));

	// 申请 EPT_POINTER
	const auto EptPointer = reinterpret_cast<EPT_POINTER*>(ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, HyperPlatformCommonPoolTag));
	if (!EptPointer)
	{
		ExFreePoolWithTag(EptData, HyperPlatformCommonPoolTag);
		return nullptr;
	}
	RtlZeroMemory(EptPointer, PAGE_SIZE);

	// 申请 EPT_PM14 并且初始化 EPT_POINTER
	const auto EptPm14 = reinterpret_cast<EPT_COMMON_ENTRY*>(ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, HyperPlatformCommonPoolTag));
	if (!EptPm14)
	{
		ExFreePoolWithTag(EptPointer, HyperPlatformCommonPoolTag);
		ExFreePoolWithTag(EptData, HyperPlatformCommonPoolTag);
		return nullptr;
	}
	RtlZeroMemory(EptPm14, PAGE_SIZE);
	EptPointer->fields.MemoryType = static_cast<ULONG64>(EptGetMemoryType(UtilPaFromVa(EptPm14)));
	EptPointer->fields.PageWalkLength = EptPageWalkLevel - 1;
	EptPointer->fields.Pm14Address = UtilPfnFromPa(UtilPaFromVa(EptPm14));

	// 初始化所有的EPT Entry - 构造完成的EPT结构
	const auto PhysicalMemoryRanges = UtilGetPhysicalMemoryRanges();
	for (auto RunIndex = 0ul; RunIndex < PhysicalMemoryRanges->NumberOfRuns; RunIndex++)
	{
		const auto Run = &PhysicalMemoryRanges->Run[RunIndex];
		const auto BaseAddr = Run->BasePage * PAGE_SIZE;	// 得到这块页的起始地址

		// 构造Run中的所有页 - 构造4级页表
		for (auto PageIndex = 0ull; PageIndex < Run->PageCount; PageIndex++)
		{
			const auto PageAddr = BaseAddr + PageIndex * PAGE_SIZE;
			const auto EptPointerEntry = EptConstructTables(EptPm14, 4, PageAddr, nullptr);		// 构造跟这一页相关的所有EPT表项 从高到低

			if (!EptPointerEntry)
			{
				EptDestructTables(EptPm14, 4);
				ExFreePoolWithTag(EptPointer, HyperPlatformCommonPoolTag);
				ExFreePoolWithTag(EptData, HyperPlatformCommonPoolTag);
				return nullptr;
			}
		}
	}

	// 为 APIC_BASE 初始化 EPT Entry。因为特殊原因要求在这里申请，否则可能系统崩溃。
	const IA32_APIC_BASE_MSR ApicMsr = { UtilReadMsr64(MSR::kIa32ApicBase) };
	if (!EptConstructTables(EptPm14, 4, ApicMsr.fields.ApicBase * PAGE_SIZE, nullptr))
	{
		EptDestructTables(EptPm14, 4);
		ExFreePoolWithTag(EptPointer, HyperPlatformCommonPoolTag);
		ExFreePoolWithTag(EptData, HyperPlatformCommonPoolTag);

		return nullptr;
	}

	// 申请 preallocated entries
	const auto PreallocatedEntriesSize = sizeof(EPT_COMMON_ENTRY*) * EptNumberOfPreallocatedEntries;
	const auto PreallocatedEntries = reinterpret_cast<EPT_COMMON_ENTRY**>(ExAllocatePoolWithTag(NonPagedPool, PreallocatedEntriesSize, HyperPlatformCommonPoolTag));
	if (!PreallocatedEntries)
	{
		EptDestructTables(EptPm14, 4);
		ExFreePoolWithTag(EptPointer, HyperPlatformCommonPoolTag);
		ExFreePoolWithTag(EptData, HyperPlatformCommonPoolTag);

		return nullptr;
	}

	// 填充 preallocated entries 
	for (auto i = 0ul; i < EptNumberOfPreallocatedEntries; i++)
	{
		const auto EptEntry = EptAllocateEptEntry(nullptr);
		if (!EptEntry)
		{
			EptFreeUnusedPreAllocatedEntries(PreallocatedEntries, 0);
			EptDestructTables(EptPm14, 4);
			ExFreePoolWithTag(EptPointer, HyperPlatformCommonPoolTag);
			ExFreePoolWithTag(EptData, HyperPlatformCommonPoolTag);

			return nullptr;
		}
		PreallocatedEntries[i] = EptEntry;
	}

	// 初始化完成
	EptData->EptPointer = EptPointer;
	EptData->EptPm14 = EptPm14;
	EptData->PreallocatedEntries = PreallocatedEntries;
	EptData->PreallocatedEntriesCount = 0;

	return EptData;
}

_Use_decl_annotations_ static MEMORY_TYPE EptGetMemoryType(ULONG64 PhysicalAddress)
{
	// 默认 MTRR 还没被定义
	UCHAR ResultType = MAXUCHAR;

	// 寻找描述特定物理地址的MTRR
	for (const auto MtrrEntry : g_EptMtrrEntries)
	{
		// 找到了最后一个
		if (!MtrrEntry.Enabled)
			break;

		// 判断这个物理地址是否在这个 MTRR 描述范围内
		if (!UtilIsInBounds(PhysicalAddress, MtrrEntry.RangeBase, MtrrEntry.RangeEnd))	
			continue;	// 如果不在这个范围 寻找下一个

		// 如果一个 FixedMtrr 描述了内存类型 - 直接返回
		if (MtrrEntry.FixedMtrr)
		{
			ResultType = MtrrEntry.Type;
			break;
		}

		// 如果是一个 VariableMtrr 描述。要进行判断，因为 Fixed 也可能描述。并且 Fixed描述优先级更高
		if (MtrrEntry.Type == static_cast<UCHAR>(MEMORY_TYPE::kUncacheable))
		{
			// 如果是一个 UC 内存类型 - 不再继续寻找，因为它拥有最高的权限。
			ResultType = MtrrEntry.Type;
			break;
		}

		if (ResultType == static_cast<UCHAR>(MEMORY_TYPE::kWriteThrough) || MtrrEntry.Type == static_cast<UCHAR>(MEMORY_TYPE::kWriteThrough))
		{
			if (ResultType == static_cast<UCHAR>(MEMORY_TYPE::kWriteBack))
			{
				// 如果有两个MTRR以上描述这段内存区域。并且一个是 WT 另一个是 WB - 使用WT
				// 但是还是要继续寻找另一个 MTRRs，指明内存类型是UC
				ResultType = static_cast<UCHAR>(MEMORY_TYPE::kWriteThrough);
				continue;
			}
		}
		
		// 如果上面都不符合 - 说明是一个未定义的MTRR内存类型
		ResultType = MtrrEntry.Type;
	}

	// 如果没有找到对应的描述 MTRRs 使用默认值
	if (ResultType == MAXUCHAR)
	{
		ResultType = g_EptMtrrDefaultType;
	}

	return static_cast<MEMORY_TYPE>(ResultType);
}

// 申请和初始化一块页表的所有 EPT Entryies - 递归构造
_Use_decl_annotations_ static EPT_COMMON_ENTRY* EptConstructTables(EPT_COMMON_ENTRY* Table, ULONG TableLevel, ULONG64 PhysicalAddress, EPT_DATA* EptData)
{
	switch (TableLevel)
	{
		case 4:
		{
			// 构造 PML4T
			const auto PxeIndex = EptAddressToPxeIndex(PhysicalAddress);
			const auto EptPm14Entry = &Table[PxeIndex];						// PML4 Entry
			if (!EptPm14Entry->all)	// 如果没有申请过
			{
				// 申请下一级的 PDPT (也就是这一级的表项
				const auto EptPdpt = EptAllocateEptEntry(EptData);
				if (!EptPdpt)
					return nullptr;

				// 对 这一级地址进行赋值
				EptInitTableEntry(EptPm14Entry, TableLevel, UtilPaFromVa(EptPdpt));
			}

			// 递归构造下一级
			return EptConstructTables(reinterpret_cast<EPT_COMMON_ENTRY*>(UtilVaFromPfn(EptPm14Entry->fields.PhysicalAddress)), TableLevel - 1, PhysicalAddress, EptData);
		}		
		case 3:
		{
			// 构造 PDPT
			const auto PpeIndex = EptAddressToPpeIndex(PhysicalAddress);
			const auto EptPdptEntry = &Table[PpeIndex];
			if (!EptPdptEntry->all)
			{
				const auto EptPdt = EptAllocateEptEntry(EptData);
				if (!EptPdt)
					return nullptr;

				EptInitTableEntry(EptPdptEntry, TableLevel, UtilPaFromVa(EptPdt));
			}

			return EptConstructTables(reinterpret_cast<EPT_COMMON_ENTRY*>(UtilVaFromPfn(EptPdptEntry->fields.PhysicalAddress)), TableLevel - 1, PhysicalAddress, EptData);
		}			
		case 2:
		{
			// 构造 PDT
			const auto PdeIndex = EptAddressToPdeIndex(PhysicalAddress);
			const auto EptPdtEntry = &Table[PdeIndex];

			if (!EptPdtEntry->all)
			{
				const auto EptPt = EptAllocateEptEntry(EptData);
				if (!EptPt)
					return nullptr;

				EptInitTableEntry(EptPdtEntry, TableLevel, UtilPaFromVa(EptPt));
			}

			return EptConstructTables(reinterpret_cast<EPT_COMMON_ENTRY*>(UtilVaFromPfn(EptPdtEntry->fields.PhysicalAddress)), TableLevel - 1, PhysicalAddress, EptData);
		}			
		case 1:
		{
			// 构造 PT
			const auto PteIndex = EptAddressToPteIndex(PhysicalAddress);
			const auto EptPtEntry = &Table[PteIndex];
			NT_ASSERT(!EptPtEntry->all);		// PTE 必须已经申请了内存
			EptInitTableEntry(EptPtEntry, TableLevel, PhysicalAddress);

			return EptPtEntry;
		}			
		default:
		{
			MYHYPERPLATFORM_COMMON_DBG_BREAK();
			return nullptr;
		}		
	}
}

// 释放所有的EPT Entry通过遍历所有的EPT
_Use_decl_annotations_ static void EptDestructTables(EPT_COMMON_ENTRY* Table, ULONG TableLevel)
{
	for (auto i = 0ul; i < 512; i++)
	{
		const auto Entry = Table[i];
		if (Entry.fields.PhysicalAddress)
		{
			// 得到下一级表的首地址
			const auto SubTable = reinterpret_cast<EPT_COMMON_ENTRY*>(UtilVaFromPfn(Entry.fields.PhysicalAddress));

			switch (TableLevel)
			{
				// 4 和 3 向下递归寻找
				case 4:
				case 3:
					EptDestructTables(SubTable, TableLevel - 1);
					break;
				// 2 释放 PTE
				case 2:
					ExFreePoolWithTag(SubTable, HyperPlatformCommonPoolTag);
					break;
				default:
					MYHYPERPLATFORM_COMMON_DBG_BREAK();
					break;
			}
		}
	}

	ExFreePoolWithTag(Table, HyperPlatformCommonPoolTag);
}

// 返回一个新的 EPT Entry 通过新申请或者从预申请中取出一个
_Use_decl_annotations_ static EPT_COMMON_ENTRY* EptAllocateEptEntry(EPT_DATA* EptData)
{
	if (EptData)
		return EptAllocateEptEntryFromPreAllocated(EptData);
	else
		return EptAllocateEptEntryFromPool();
}

// 取一个新的 EPT_COMMON_ENTRY 从预申请
_Use_decl_annotations_ static EPT_COMMON_ENTRY * EptAllocateEptEntryFromPreAllocated(EPT_DATA * EptData)
{
	const auto Count = InterlockedIncrement(&EptData->PreallocatedEntriesCount);
	if (Count > EptNumberOfPreallocatedEntries)
	{
		MYHYPERPLATFORM_COMMON_BUG_CHECK(HYPERPLATFORM_BUG_CHECK::kExhaustedPreallocatedEntries, Count, reinterpret_cast<ULONG_PTR>(EptData), 0);
	}
	return EptData->PreallocatedEntries[Count - 1];
}

// 申请一个新的 EPT_COMMON_ENTRY
_Use_decl_annotations_ static EPT_COMMON_ENTRY* EptAllocateEptEntryFromPool()
{
	static const auto AllocSize = 512 * sizeof(EPT_COMMON_ENTRY);
	static_assert(AllocSize == PAGE_SIZE, "Size Check");

	const auto Entry = reinterpret_cast<EPT_COMMON_ENTRY*>(ExAllocatePoolWithTag(NonPagedPool, AllocSize, HyperPlatformCommonPoolTag));
	if (!Entry)
		return nullptr;

	RtlZeroMemory(Entry, AllocSize);
	return Entry;
}

// 初始化一个 EPT entry 使用 "pass through" 属性
_Use_decl_annotations_ static void EptInitTableEntry(EPT_COMMON_ENTRY* Entry, ULONG TableLevel, ULONG64 PhysicalAddress)
{
	// PhysicalAddress  也就是下一级的基地址
	Entry->fields.ReadAccess = true;
	Entry->fields.WriteAccess = true;
	Entry->fields.ExecuteAccess = true;
	Entry->fields.PhysicalAddress = UtilPfnFromPa(PhysicalAddress);
	
	// 最后一级页表指示内存类型
	if (TableLevel == 1)
		Entry->fields.MemoryType = static_cast<ULONG64>(EptGetMemoryType(PhysicalAddress));
	
}

// 物理地址转换函数
_Use_decl_annotations_ static ULONG64 EptAddressToPxeIndex(ULONG64 PhysicalAddress)
{
	const auto Index = (PhysicalAddress >> kEptPxiShift) & kEptPtxMask;
	return Index;
}

_Use_decl_annotations_ static ULONG64 EptAddressToPpeIndex(ULONG64 PhysicalAddress)
{
	const auto Index = (PhysicalAddress >> kEptPpiShift) & kEptPtxMask;
	return Index;
}

_Use_decl_annotations_ static ULONG64 EptAddressToPdeIndex(ULONG64 PhysicalAddress)
{
	const auto Index = (PhysicalAddress >> kEptPdiShift) & kEptPtxMask;
	return Index;
}

_Use_decl_annotations_ static ULONG64 EptAddressToPteIndex(ULONG64 PhysicalAddress)
{
	const auto Index = (PhysicalAddress >> kEptPtiShift) & kEptPtxMask;
	return Index;
}

// 释放所有没有使用的预申请 Entries 已经使用的靠 EptDestructTables()
_Use_decl_annotations_ static void EptFreeUnusedPreAllocatedEntries(EPT_COMMON_ENTRY** PreallocatedEntries, long UsedCount)
{
	for (auto i = UsedCount; i < EptNumberOfPreallocatedEntries; i++)
	{
		if (!PreallocatedEntries[i])
			break;

#pragma warning(push)
#pragma warning(disable : 6001)
		ExFreePoolWithTag(PreallocatedEntries[i], HyperPlatformCommonPoolTag);
#pragma warning(pop)
	}
	ExFreePoolWithTag(PreallocatedEntries, HyperPlatformCommonPoolTag);
}

// 释放所有申请的内存 
_Use_decl_annotations_ void EptTermination(EPT_DATA* EptData)
{
	MYHYPERPLATFORM_LOG_DEBUG("Used pre-allocated = %2d / %2d", EptData->PreallocatedEntriesCount, EptNumberOfPreallocatedEntries);

	EptFreeUnusedPreAllocatedEntries(EptData->PreallocatedEntries, EptData->PreallocatedEntriesCount);

	EptDestructTables(EptData->EptPm14, 4);

	ExFreePoolWithTag(EptData->EptPointer, HyperPlatformCommonPoolTag);
	ExFreePoolWithTag(EptData, HyperPlatformCommonPoolTag);
}

// 处理 EPT volation - VM-exit
_Use_decl_annotations_ void EptHandleEptViolation(EPT_DATA* EptData)
{
	const EPT_VIOLATION_QUALIFICATION ExitQualification = { UtilVmRead(VMCS_FIELD::kExitQualification) };

	const auto FaultPa = UtilVmRead64(VMCS_FIELD::kGuestPhysicalAddress);
	const auto FaultVa = reinterpret_cast<void*>(ExitQualification.fields.ValidGuestLinearAddress ? UtilVmRead(VMCS_FIELD::kGuestLinearAddress) : 0);

	if (ExitQualification.fields.EptReadable || ExitQualification.fields.EptWriteable || ExitQualification.fields.EptExecutable)
	{
		MYHYPERPLATFORM_COMMON_DBG_BREAK();
		MYHYPERPLATFORM_LOG_ERROR_SAFE("[UNK1] VA = %p, PA = %016llx", FaultVa, FaultPa);
		return;
	}

	const auto EptEntry = EptGetEptPtEntry(EptData, FaultPa);
	if (EptEntry && EptEntry->all)
	{
		MYHYPERPLATFORM_COMMON_DBG_BREAK();
		MYHYPERPLATFORM_LOG_ERROR_SAFE("[UNK2] VA = %p, PA = %016llx", FaultVa, FaultPa);
		return;
	}

	// 没有得到 EptEntry， 肯定是 Device Memory
	MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	if (!IsReleaseBuild())
		NT_VERIFY(EptIsDeviceMemory(FaultPa));

	EptConstructTables(EptData->EptPm14, 4, FaultPa, EptData);

	UtilInveptGlobal();
}

// 根据给定的物理地址，返回 EPTEntry
_Use_decl_annotations_ EPT_COMMON_ENTRY* EptGetEptPtEntry(EPT_DATA* EptData, ULONG64 PhysicalAddress)
{
	return EptGetEptPtEntryByLevel(EptData->EptPm14, 4, PhysicalAddress);
}

_Use_decl_annotations_ static EPT_COMMON_ENTRY* EptGetEptPtEntryByLevel(EPT_COMMON_ENTRY* Table, ULONG TableLevel, ULONG64 PhysicalAddress)
{
	if (!Table)
		return nullptr;

	switch (TableLevel)
	{
		case 4:
		{
			// PML4
			const auto PxeIndex = EptAddressToPxeIndex(PhysicalAddress);
			const auto EptPml4Entry = &Table[PxeIndex];
			if (!EptPml4Entry->all)
				return nullptr;

			return EptGetEptPtEntryByLevel(reinterpret_cast<EPT_COMMON_ENTRY*>(UtilVaFromPfn(EptPml4Entry->fields.PhysicalAddress)), TableLevel - 1, PhysicalAddress);
		}
		case 3:
		{
			// PDPT
			const auto PpeIndex = EptAddressToPpeIndex(PhysicalAddress);
			const auto EptPdptEntry = &Table[PpeIndex];
			if (!EptPdptEntry->all) 
				return nullptr;
			
			return EptGetEptPtEntryByLevel(reinterpret_cast<EPT_COMMON_ENTRY*>(UtilVaFromPfn(EptPdptEntry->fields.PhysicalAddress)), TableLevel - 1, PhysicalAddress);
		}
		case 2:
		{
			// PDT
			const auto PdeIndex = EptAddressToPdeIndex(PhysicalAddress);
			const auto EptPdtEntry = &Table[PdeIndex];
			if (!EptPdtEntry->all)
				return nullptr;
			
			return EptGetEptPtEntryByLevel(reinterpret_cast<EPT_COMMON_ENTRY*>(UtilVaFromPfn(EptPdtEntry->fields.PhysicalAddress)), TableLevel - 1, PhysicalAddress);
		}
		case 1:
		{
			const auto PteIndex = EptAddressToPteIndex(PhysicalAddress);
			const auto EptPtEntry = &Table[PteIndex];
			return EptPtEntry;
		}
		default:
			MYHYPERPLATFORM_COMMON_DBG_BREAK();
			return nullptr;
	}
}

// 判断一个物理地址是否是设备内存 (which could not have a corresponding PFN entry)
_Use_decl_annotations_ static bool EptIsDeviceMemory(ULONG64 PhysicalAddress) 
{
	const auto PhysicalAddrRanges = UtilGetPhysicalMemoryRanges();
	for (auto i = 0ul; i < PhysicalAddrRanges->NumberOfRuns; ++i) 
	{
		const auto CurrentRun = &PhysicalAddrRanges->Run[i];
		const auto BaseAddr = static_cast<ULONG64>(CurrentRun->BasePage) * PAGE_SIZE;
		const auto EndAddr = BaseAddr + CurrentRun->PageCount * PAGE_SIZE - 1;

		if (UtilIsInBounds(PhysicalAddress, BaseAddr, EndAddr))
			return false;	
	}
	return true;
}

EXTERN_C_END