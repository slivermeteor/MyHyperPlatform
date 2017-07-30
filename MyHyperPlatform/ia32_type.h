#pragma once

#include <fltKernel.h>

static const SIZE_T kVmxMaxVmcsSize = 4096;

// 大多数现代VMM(虚拟机监控程序)发布它们的签名通过CPUID 使用这个 FunctionCode 证明它们的存在
static const ULONG32 HyperVCpuidInterface = 0x40000002;

/// See: CONTROL REGISTERS
union CR4 
{
	ULONG_PTR all;
	struct 
	{
		unsigned vme : 1;         //!< [0] Virtual Mode Extensions
		unsigned pvi : 1;         //!< [1] Protected-Mode Virtual Interrupts
		unsigned tsd : 1;         //!< [2] Time Stamp Disable
		unsigned de : 1;          //!< [3] Debugging Extensions
		unsigned pse : 1;         //!< [4] Page Size Extensions
		unsigned pae : 1;         //!< [5] Physical Address Extension
		unsigned mce : 1;         //!< [6] Machine-Check Enable
		unsigned pge : 1;         //!< [7] Page Global Enable
		unsigned pce : 1;         //!< [8] Performance-Monitoring Counter Enable
		unsigned osfxsr : 1;      //!< [9] OS Support for FXSAVE/FXRSTOR
		unsigned osxmmexcpt : 1;  //!< [10] OS Support for Unmasked SIMD Exceptions
		unsigned reserved1 : 2;   //!< [11:12]
		unsigned vmxe : 1;        //!< [13] Virtual Machine Extensions Enabled
		unsigned smxe : 1;        //!< [14] SMX-Enable Bit
		unsigned reserved2 : 2;   //!< [15:16]
		unsigned pcide : 1;       //!< [17] PCID Enable
		unsigned osxsave : 1;  //!< [18] XSAVE and Processor Extended States-Enable
		unsigned reserved3 : 1;  //!< [19]
		unsigned smep : 1;  //!< [20] Supervisor Mode Execution Protection Enable
		unsigned smap : 1;  //!< [21] Supervisor Mode Access Protection Enable
	} fields;
};

/// See: BASIC VMX INFORMATION
union IA32_VMX_BASIC_MSR {
	unsigned __int64 all;
	struct {
		unsigned revision_identifier : 31;    //!< [0:30]
		unsigned reserved1 : 1;               //!< [31]
		unsigned region_size : 12;            //!< [32:43]
		unsigned region_clear : 1;            //!< [44]
		unsigned reserved2 : 3;               //!< [45:47]
		unsigned supported_ia64 : 1;          //!< [48]
		unsigned supported_dual_moniter : 1;  //!< [49]
		unsigned memory_type : 4;             //!< [50:53]
		unsigned vm_exit_report : 1;          //!< [54]
		unsigned vmx_capability_hint : 1;     //!< [55]
		unsigned reserved3 : 8;               //!< [56:63]
	} fields;
};
static_assert(sizeof(IA32_VMX_BASIC_MSR) == 8, "Size check");

/// See: Feature Information Returned in the ECX Register - intel 手册 776
union CPU_FEATURES_ECX {
	ULONG32 all;
	struct {
		ULONG32 sse3 : 1;       //!< [0] Streaming SIMD Extensions 3 (SSE3)
		ULONG32 pclmulqdq : 1;  //!< [1] PCLMULQDQ
		ULONG32 dtes64 : 1;     //!< [2] 64-bit DS Area
		ULONG32 monitor : 1;    //!< [3] MONITOR/WAIT
		ULONG32 ds_cpl : 1;     //!< [4] CPL qualified Debug Store
		ULONG32 vmx : 1;        //!< [5] Virtual Machine Technology
		ULONG32 smx : 1;        //!< [6] Safer Mode Extensions
		ULONG32 est : 1;        //!< [7] Enhanced Intel Speedstep Technology
		ULONG32 tm2 : 1;        //!< [8] Thermal monitor 2
		ULONG32 ssse3 : 1;      //!< [9] Supplemental Streaming SIMD Extensions 3
		ULONG32 cid : 1;        //!< [10] L1 context ID
		ULONG32 sdbg : 1;       //!< [11] IA32_DEBUG_INTERFACE MSR
		ULONG32 fma : 1;        //!< [12] FMA extensions using YMM state
		ULONG32 cx16 : 1;       //!< [13] CMPXCHG16B
		ULONG32 xtpr : 1;       //!< [14] xTPR Update Control
		ULONG32 pdcm : 1;       //!< [15] Performance/Debug capability MSR
		ULONG32 reserved : 1;   //!< [16] Reserved
		ULONG32 pcid : 1;       //!< [17] Process-context identifiers
		ULONG32 dca : 1;        //!< [18] prefetch from a memory mapped device
		ULONG32 sse4_1 : 1;     //!< [19] SSE4.1
		ULONG32 sse4_2 : 1;     //!< [20] SSE4.2
		ULONG32 x2_apic : 1;    //!< [21] x2APIC feature
		ULONG32 movbe : 1;      //!< [22] MOVBE instruction
		ULONG32 popcnt : 1;     //!< [23] POPCNT instruction
		ULONG32 reserved3 : 1;  //!< [24] one-shot operation using a TSC deadline
		ULONG32 aes : 1;        //!< [25] AESNI instruction
		ULONG32 xsave : 1;      //!< [26] XSAVE/XRSTOR feature
		ULONG32 osxsave : 1;    //!< [27] enable XSETBV/XGETBV instructions
		ULONG32 avx : 1;        //!< [28] AVX instruction extensions
		ULONG32 f16c : 1;       //!< [29] 16-bit floating-point conversion
		ULONG32 rdrand : 1;     //!< [30] RDRAND instruction
		ULONG32 not_used : 1;   //!< [31] Always 0 (a.k.a. HypervisorPresent)
	} fields;
};
static_assert(sizeof(CPU_FEATURES_ECX) == 4, "Size check");

// 操作 CRx 寄存器 具体操作类型
enum class CR_ACCESS_TYPE
{
	kMovToCr = 0,
	kMovFromCr,
	kClts,
	kLmsw
};

// 操作 CRx 寄存器 具体位
union CR_ACCESS_QUALIFICATION {
	ULONG_PTR all;
	struct {
		ULONG_PTR ControlRegister : 4;   //!< [0:3]
		ULONG_PTR AccessType : 2;        //!< [4:5]
		ULONG_PTR LmswOperandType : 1;  //!< [6]
		ULONG_PTR Reserved1 : 1;          //!< [7]
		ULONG_PTR GpRegister : 4;        //!< [8:11]
		ULONG_PTR Reserved2 : 4;          //!< [12:15]
		ULONG_PTR LmswSourceData : 16;  //!< [16:31]
		ULONG_PTR Reserved3 : 32;         //!< [32:63]
	} fields;
};
static_assert(sizeof(CR_ACCESS_QUALIFICATION) == 8, "Size check");

// See: Exit Qualification for MOV DR
enum class DR_DIRECTION_TYPE 
{
	kMoveToDr = 0,
	kMoveFromDr,
};

// @copydoc MovDrDirection
union DR_ACCESS_QUALIFICATION 
{
	ULONG_PTR all;
	struct 
	{
		ULONG_PTR DebugOneRegister : 3;  //!< [0:2]
		ULONG_PTR Reserved1 : 1;        //!< [3]
		ULONG_PTR Direction : 1;        //!< [4]
		ULONG_PTR Reserved2 : 3;        //!< [5:7]
		ULONG_PTR GpRegister : 4;      //!< [8:11]
		ULONG_PTR Reserved3 : 20;       //!<
		ULONG_PTR Reserved4 : 32;       //!< [12:63]
	} fields;
};
static_assert(sizeof(DR_ACCESS_QUALIFICATION) == 8, "Size check");

// IO 操作导致的 VM-exit
union IO_INST_QUALIFICATION
{
	ULONG_PTR all;
	struct  
	{
		ULONG_PTR SizeOfAccess : 3;      //!< [0:2]
		ULONG_PTR Direction : 1;           //!< [3]
		ULONG_PTR StringInstruction : 1;  //!< [4]
		ULONG_PTR RepPrefixed : 1;        //!< [5]
		ULONG_PTR OperandEncoding : 1;    //!< [6]
		ULONG_PTR Reserved1 : 9;           //!< [7:15]
		ULONG_PTR PortNumber : 16;        //!< [16:31]
	}fields;
};
static_assert(sizeof(IO_INST_QUALIFICATION) == sizeof(void*), "Size check");

/// @copydoc IoInstQualification
enum class IO_INST_SIZE_OF_ACCESS
{
	k1Byte = 0,
	k2Byte = 1,
	k4Byte = 3,
};

/// See: MODEL-SPECIFIC REGISTERS (MSRS)
enum class MSR : unsigned int {
	kIa32ApicBase = 0x01B,

	kIa32FeatureControl = 0x03A,

	kIa32SysenterCs = 0x174,
	kIa32SysenterEsp = 0x175,
	kIa32SysenterEip = 0x176,

	kIa32Debugctl = 0x1D9,

	kIa32MtrrCap = 0xFE,
	kIa32MtrrDefType = 0x2FF,
	kIa32MtrrPhysBaseN = 0x200,
	kIa32MtrrPhysMaskN = 0x201,
	kIa32MtrrFix64k00000 = 0x250,
	kIa32MtrrFix16k80000 = 0x258,
	kIa32MtrrFix16kA0000 = 0x259,
	kIa32MtrrFix4kC0000 = 0x268,
	kIa32MtrrFix4kC8000 = 0x269,
	kIa32MtrrFix4kD0000 = 0x26A,
	kIa32MtrrFix4kD8000 = 0x26B,
	kIa32MtrrFix4kE0000 = 0x26C,
	kIa32MtrrFix4kE8000 = 0x26D,
	kIa32MtrrFix4kF0000 = 0x26E,
	kIa32MtrrFix4kF8000 = 0x26F,

	kIa32VmxBasic = 0x480,
	kIa32VmxPinbasedCtls = 0x481,
	kIa32VmxProcBasedCtls = 0x482,
	kIa32VmxExitCtls = 0x483,
	kIa32VmxEntryCtls = 0x484,
	kIa32VmxMisc = 0x485,
	kIa32VmxCr0Fixed0 = 0x486,
	kIa32VmxCr0Fixed1 = 0x487,
	kIa32VmxCr4Fixed0 = 0x488,
	kIa32VmxCr4Fixed1 = 0x489,
	kIa32VmxVmcsEnum = 0x48A,
	kIa32VmxProcBasedCtls2 = 0x48B,
	kIa32VmxEptVpidCap = 0x48C,
	kIa32VmxTruePinbasedCtls = 0x48D,
	kIa32VmxTrueProcBasedCtls = 0x48E,
	kIa32VmxTrueExitCtls = 0x48F,
	kIa32VmxTrueEntryCtls = 0x490,
	kIa32VmxVmfunc = 0x491,

	kIa32Efer = 0xC0000080,
	kIa32Star = 0xC0000081,
	kIa32Lstar = 0xC0000082,

	kIa32Fmask = 0xC0000084,

	kIa32FsBase = 0xC0000100,
	kIa32GsBase = 0xC0000101,
	kIa32KernelGsBase = 0xC0000102,
	kIa32TscAux = 0xC0000103,
};

// MemoryType 描述在VMCS中被建议使用的PAT内存类型和相关的数据类型
enum class MemoryType : unsigned __int8
{
	kUncacheable = 0,
	kWriteCombining = 1,
	kWriteThrough = 4,
	kWriteProtected = 5,
	kWriteBack = 6,
	kUncached = 7
};

/// See: FIELD ENCODING IN VMCS
enum class VMCS_FIELD : unsigned __int32 {
	// 16-Bit Control Field
	kVirtualProcessorId = 0x00000000,
	kPostedInterruptNotification = 0x00000002,
	kEptpIndex = 0x00000004,
	// 16-Bit Guest-State Fields
	kGuestEsSelector = 0x00000800,
	kGuestCsSelector = 0x00000802,
	kGuestSsSelector = 0x00000804,
	kGuestDsSelector = 0x00000806,
	kGuestFsSelector = 0x00000808,
	kGuestGsSelector = 0x0000080a,
	kGuestLdtrSelector = 0x0000080c,
	kGuestTrSelector = 0x0000080e,
	kGuestInterruptStatus = 0x00000810,
	kPmlIndex = 0x00000812,
	// 16-Bit Host-State Fields
	kHostEsSelector = 0x00000c00,
	kHostCsSelector = 0x00000c02,
	kHostSsSelector = 0x00000c04,
	kHostDsSelector = 0x00000c06,
	kHostFsSelector = 0x00000c08,
	kHostGsSelector = 0x00000c0a,
	kHostTrSelector = 0x00000c0c,
	// 64-Bit Control Fields
	kIoBitmapA = 0x00002000,
	kIoBitmapAHigh = 0x00002001,
	kIoBitmapB = 0x00002002,
	kIoBitmapBHigh = 0x00002003,
	kMsrBitmap = 0x00002004,
	kMsrBitmapHigh = 0x00002005,
	kVmExitMsrStoreAddr = 0x00002006,
	kVmExitMsrStoreAddrHigh = 0x00002007,
	kVmExitMsrLoadAddr = 0x00002008,
	kVmExitMsrLoadAddrHigh = 0x00002009,
	kVmEntryMsrLoadAddr = 0x0000200a,
	kVmEntryMsrLoadAddrHigh = 0x0000200b,
	kExecutiveVmcsPointer = 0x0000200c,
	kExecutiveVmcsPointerHigh = 0x0000200d,
	kTscOffset = 0x00002010,
	kTscOffsetHigh = 0x00002011,
	kVirtualApicPageAddr = 0x00002012,
	kVirtualApicPageAddrHigh = 0x00002013,
	kApicAccessAddr = 0x00002014,
	kApicAccessAddrHigh = 0x00002015,
	kEptPointer = 0x0000201a,
	kEptPointerHigh = 0x0000201b,
	kEoiExitBitmap0 = 0x0000201c,
	kEoiExitBitmap0High = 0x0000201d,
	kEoiExitBitmap1 = 0x0000201e,
	kEoiExitBitmap1High = 0x0000201f,
	kEoiExitBitmap2 = 0x00002020,
	kEoiExitBitmap2High = 0x00002021,
	kEoiExitBitmap3 = 0x00002022,
	kEoiExitBitmap3High = 0x00002023,
	kEptpListAddress = 0x00002024,
	kEptpListAddressHigh = 0x00002025,
	kVmreadBitmapAddress = 0x00002026,
	kVmreadBitmapAddressHigh = 0x00002027,
	kVmwriteBitmapAddress = 0x00002028,
	kVmwriteBitmapAddressHigh = 0x00002029,
	kVirtualizationExceptionInfoAddress = 0x0000202a,
	kVirtualizationExceptionInfoAddressHigh = 0x0000202b,
	kXssExitingBitmap = 0x0000202c,
	kXssExitingBitmapHigh = 0x0000202d,
	kEnclsExitingBitmap = 0x0000202e,
	kEnclsExitingBitmapHigh = 0x0000202f,
	kTscMultiplier = 0x00002032,
	kTscMultiplierHigh = 0x00002033,
	// 64-Bit Read-Only Data Field
	kGuestPhysicalAddress = 0x00002400,
	kGuestPhysicalAddressHigh = 0x00002401,
	// 64-Bit Guest-State Fields
	kVmcsLinkPointer = 0x00002800,
	kVmcsLinkPointerHigh = 0x00002801,
	kGuestIa32Debugctl = 0x00002802,
	kGuestIa32DebugctlHigh = 0x00002803,
	kGuestIa32Pat = 0x00002804,
	kGuestIa32PatHigh = 0x00002805,
	kGuestIa32Efer = 0x00002806,
	kGuestIa32EferHigh = 0x00002807,
	kGuestIa32PerfGlobalCtrl = 0x00002808,
	kGuestIa32PerfGlobalCtrlHigh = 0x00002809,
	kGuestPdptr0 = 0x0000280a,
	kGuestPdptr0High = 0x0000280b,
	kGuestPdptr1 = 0x0000280c,
	kGuestPdptr1High = 0x0000280d,
	kGuestPdptr2 = 0x0000280e,
	kGuestPdptr2High = 0x0000280f,
	kGuestPdptr3 = 0x00002810,
	kGuestPdptr3High = 0x00002811,
	kGuestIa32Bndcfgs = 0x00002812,
	kGuestIa32BndcfgsHigh = 0x00002813,
	// 64-Bit Host-State Fields
	kHostIa32Pat = 0x00002c00,
	kHostIa32PatHigh = 0x00002c01,
	kHostIa32Efer = 0x00002c02,
	kHostIa32EferHigh = 0x00002c03,
	kHostIa32PerfGlobalCtrl = 0x00002c04,
	kHostIa32PerfGlobalCtrlHigh = 0x00002c05,
	// 32-Bit Control Fields
	kPinBasedVmExecControl = 0x00004000,
	kCpuBasedVmExecControl = 0x00004002,
	kExceptionBitmap = 0x00004004,
	kPageFaultErrorCodeMask = 0x00004006,
	kPageFaultErrorCodeMatch = 0x00004008,
	kCr3TargetCount = 0x0000400a,
	kVmExitControls = 0x0000400c,
	kVmExitMsrStoreCount = 0x0000400e,
	kVmExitMsrLoadCount = 0x00004010,
	kVmEntryControls = 0x00004012,
	kVmEntryMsrLoadCount = 0x00004014,
	kVmEntryIntrInfoField = 0x00004016,
	kVmEntryExceptionErrorCode = 0x00004018,
	kVmEntryInstructionLen = 0x0000401a,
	kTprThreshold = 0x0000401c,
	kSecondaryVmExecControl = 0x0000401e,
	kPleGap = 0x00004020,
	kPleWindow = 0x00004022,
	// 32-Bit Read-Only Data Fields
	kVmInstructionError = 0x00004400,  // See: VM-Instruction Error Numbers
	kVmExitReason = 0x00004402,
	kVmExitIntrInfo = 0x00004404,
	kVmExitIntrErrorCode = 0x00004406,
	kIdtVectoringInfoField = 0x00004408,
	kIdtVectoringErrorCode = 0x0000440a,
	kVmExitInstructionLen = 0x0000440c,
	kVmxInstructionInfo = 0x0000440e,
	// 32-Bit Guest-State Fields
	kGuestEsLimit = 0x00004800,
	kGuestCsLimit = 0x00004802,
	kGuestSsLimit = 0x00004804,
	kGuestDsLimit = 0x00004806,
	kGuestFsLimit = 0x00004808,
	kGuestGsLimit = 0x0000480a,
	kGuestLdtrLimit = 0x0000480c,
	kGuestTrLimit = 0x0000480e,
	kGuestGdtrLimit = 0x00004810,
	kGuestIdtrLimit = 0x00004812,
	kGuestEsArBytes = 0x00004814,
	kGuestCsArBytes = 0x00004816,
	kGuestSsArBytes = 0x00004818,
	kGuestDsArBytes = 0x0000481a,
	kGuestFsArBytes = 0x0000481c,
	kGuestGsArBytes = 0x0000481e,
	kGuestLdtrArBytes = 0x00004820,
	kGuestTrArBytes = 0x00004822,
	kGuestInterruptibilityInfo = 0x00004824,
	kGuestActivityState = 0x00004826,
	kGuestSmbase = 0x00004828,
	kGuestSysenterCs = 0x0000482a,
	kVmxPreemptionTimerValue = 0x0000482e,
	// 32-Bit Host-State Field
	kHostIa32SysenterCs = 0x00004c00,
	// Natural-Width Control Fields
	kCr0GuestHostMask = 0x00006000,
	kCr4GuestHostMask = 0x00006002,
	kCr0ReadShadow = 0x00006004,
	kCr4ReadShadow = 0x00006006,
	kCr3TargetValue0 = 0x00006008,
	kCr3TargetValue1 = 0x0000600a,
	kCr3TargetValue2 = 0x0000600c,
	kCr3TargetValue3 = 0x0000600e,
	// Natural-Width Read-Only Data Fields
	kExitQualification = 0x00006400,
	kIoRcx = 0x00006402,
	kIoRsi = 0x00006404,
	kIoRdi = 0x00006406,
	kIoRip = 0x00006408,
	kGuestLinearAddress = 0x0000640a,
	// Natural-Width Guest-State Fields
	kGuestCr0 = 0x00006800,
	kGuestCr3 = 0x00006802,
	kGuestCr4 = 0x00006804,
	kGuestEsBase = 0x00006806,
	kGuestCsBase = 0x00006808,
	kGuestSsBase = 0x0000680a,
	kGuestDsBase = 0x0000680c,
	kGuestFsBase = 0x0000680e,
	kGuestGsBase = 0x00006810,
	kGuestLdtrBase = 0x00006812,
	kGuestTrBase = 0x00006814,
	kGuestGdtrBase = 0x00006816,
	kGuestIdtrBase = 0x00006818,
	kGuestDr7 = 0x0000681a,
	kGuestRsp = 0x0000681c,
	kGuestRip = 0x0000681e,
	kGuestRflags = 0x00006820,
	kGuestPendingDbgExceptions = 0x00006822,
	kGuestSysenterEsp = 0x00006824,
	kGuestSysenterEip = 0x00006826,
	// Natural-Width Host-State Fields
	kHostCr0 = 0x00006c00,
	kHostCr3 = 0x00006c02,
	kHostCr4 = 0x00006c04,
	kHostFsBase = 0x00006c06,
	kHostGsBase = 0x00006c08,
	kHostTrBase = 0x00006c0a,
	kHostGdtrBase = 0x00006c0c,
	kHostIdtrBase = 0x00006c0e,
	kHostIa32SysenterEsp = 0x00006c10,
	kHostIa32SysenterEip = 0x00006c12,
	kHostRsp = 0x00006c14,
	kHostRip = 0x00006c16
};

enum class VMX_EXIT_REASON : unsigned __int16 
{
	kExceptionOrNmi = 0,
	kExternalInterrupt = 1,
	kTripleFault = 2,
	kInit = 3,
	kSipi = 4,
	kIoSmi = 5,
	kOtherSmi = 6,
	kPendingInterrupt = 7,
	kNmiWindow = 8,
	kTaskSwitch = 9,
	kCpuid = 10,
	kGetSec = 11,
	kHlt = 12,
	kInvd = 13,
	kInvlpg = 14,
	kRdpmc = 15,
	kRdtsc = 16,
	kRsm = 17,
	kVmcall = 18,
	kVmclear = 19,
	kVmlaunch = 20,
	kVmptrld = 21,
	kVmptrst = 22,
	kVmread = 23,
	kVmresume = 24,
	kVmwrite = 25,
	kVmoff = 26,
	kVmon = 27,
	kCrAccess = 28,
	kDrAccess = 29,
	kIoInstruction = 30,
	kMsrRead = 31,
	kMsrWrite = 32,
	kInvalidGuestState = 33,  // See: BASIC VM-ENTRY CHECKS
	kMsrLoading = 34,
	kUndefined35 = 35,
	kMwaitInstruction = 36,
	kMonitorTrapFlag = 37,
	kUndefined38 = 38,
	kMonitorInstruction = 39,
	kPauseInstruction = 40,
	kMachineCheck = 41,
	kUndefined42 = 42,
	kTprBelowThreshold = 43,
	kApicAccess = 44,
	kVirtualizedEoi = 45,
	kGdtrOrIdtrAccess = 46,
	kLdtrOrTrAccess = 47,
	kEptViolation = 48,
	kEptMisconfig = 49,
	kInvept = 50,
	kRdtscp = 51,
	kVmxPreemptionTime = 52,
	kInvvpid = 53,
	kWbinvd = 54,
	kXsetbv = 55,
	kApicWrite = 56,
	kRdrand = 57,
	kInvpcid = 58,
	kVmfunc = 59,
	kUndefined60 = 60,
	kRdseed = 61,
	kUndefined62 = 62,
	kXsaves = 63,
	kXrstors = 64,
};
static_assert(sizeof(VMX_EXIT_REASON) == 2, "Size check");

/// See: ARCHITECTURAL MSRS
union IA32_FEATURE_CONTROL_MSR
{
	unsigned __int64 all;
	struct {
		unsigned Lock : 1;                  //!< [0]
		unsigned EnableSmx : 1;            //!< [1]
		unsigned EnableVmxon : 1;          //!< [2]
		unsigned reserved1 : 5;             //!< [3:7]
		unsigned EnableLocalSenter : 7;   //!< [8:14]
		unsigned EnableGlobalSenter : 1;  //!< [15]
		unsigned reserved2 : 16;            //!<
		unsigned reserved3 : 32;            //!< [16:63]
	} fields;
};
static_assert(sizeof(IA32_FEATURE_CONTROL_MSR) == 8, "Size check");

/// See: VPID AND EPT CAPABILITIES
union IA32_VMX_EPT_VPID_CAP {
	unsigned __int64 all;
	struct {
		unsigned support_execute_only_pages : 1;                        //!< [0]
		unsigned reserved1 : 5;                                         //!< [1:5]
		unsigned support_page_walk_length4 : 1;                         //!< [6]		是否支持4级页表
		unsigned reserved2 : 1;                                         //!< [7]
		unsigned support_uncacheble_memory_type : 1;                    //!< [8]
		unsigned reserved3 : 5;                                         //!< [9:13]
		unsigned support_write_back_memory_type : 1;                    //!< [14]
		unsigned reserved4 : 1;                                         //!< [15]
		unsigned support_pde_2mb_pages : 1;                             //!< [16]
		unsigned support_pdpte_1_gb_pages : 1;                          //!< [17]
		unsigned reserved5 : 2;                                         //!< [18:19]
		unsigned support_invept : 1;                                    //!< [20]
		unsigned support_accessed_and_dirty_flag : 1;                   //!< [21]
		unsigned reserved6 : 3;                                         //!< [22:24]
		unsigned support_single_context_invept : 1;                     //!< [25]
		unsigned support_all_context_invept : 1;                        //!< [26]
		unsigned reserved7 : 5;                                         //!< [27:31]
		unsigned support_invvpid : 1;                                   //!< [32]
		unsigned reserved8 : 7;                                         //!< [33:39]
		unsigned support_individual_address_invvpid : 1;                //!< [40]
		unsigned support_single_context_invvpid : 1;                    //!< [41]
		unsigned support_all_context_invvpid : 1;                       //!< [42]
		unsigned support_single_context_retaining_globals_invvpid : 1;  //!< [43]
		unsigned reserved9 : 20;                                        //!< [44:63]
	} fields;
};
static_assert(sizeof(IA32_VMX_EPT_VPID_CAP) == 8, "Size check");

/// See: IA32_MTRRCAP Register
// MTRR 机制 - 确定系统内存一段物理内存的类型
// MTRR 机制允许96个内存范围在物理内存的定义。它定义了一系列的MSRs。这些寄存器分别去说明MSR定义中包含的这段内存的具体类型。
// 内存类型已经定义了 5 个。
union IA32_MTRR_CAPABILITIES_MSR {
	ULONG64 all;
	struct {
		ULONG64 variable_range_count : 8;   //<! [0:7] VCNT 表示8个变量 指示8个MTRRs的范围。
		ULONG64 fixed_range_supported : 1;  //<! [8]   当被置1，固定MTRRs的范围
		ULONG64 reserved : 1;               //<! [9]   
		ULONG64 write_combining : 1;        //<! [10]  是否支持WC类型
		ULONG64 smrr : 1;                   //<! [11]
	} fields;
};
static_assert(sizeof(IA32_MTRR_CAPABILITIES_MSR) == 8, "Size check");

/// See: IA32_MTRR_DEF_TYPE MSR - 设定不被MTRRs包含的物理内存区域的默认属性
union IA32_MTRR_DEFAULT_TYPE_MSR {
	ULONG64 all;
	struct {
		ULONG64 DefaultMemoryType : 8;  //<! [0:7] 默认内存类型 - 类型编号是8字节的
		ULONG64 Reserved : 2;              //<! [8:9] 
		ULONG64 FixedMtrrsEnabled : 1;   //<! [10]  FE - 固定范围MTRRs enabled
		ULONG64 MtrrsEnabled : 1;         //<! [11]  E - MTRRs是否被启用。当这一位为0时，所有MTRRs被禁用，并且UC内存类型适用于所有的物理内存。
	} fields;
};
static_assert(sizeof(IA32_MTRR_DEFAULT_TYPE_MSR) == 8, "Size check");
// 上面两个结构体告诉我们 - MTRRs 一共有大类MTRs fixed 和 variable。fixed的是描述一段确定范围内的内存类型，variable描述一段可变范围的内存类型。fixed的描述优先级大于variable.
//  如果一段内存，即不被固定描述也不被可变描述。那么就是用默认类型。

/// See: Fixed Range MTRRs
// FixedMemoryRanges总共由11个64位的FixedRangeMsr寄存器来进行映射的。这些寄存器都是被分为8bits的区域，来描述对应的内存段的内存类型。
// IA32_MTRR_FIX64K_00000 - 映射从 0H ~ 7FFFFH 的512Kbyte的地址范围。此范围被分为8个64Kbyte子区间。
// IA32_MTRR_FIX16K_80000 IA32_MTRR_FIX16K_A0000 映射2个128Kbyte的地址范围。 0x80000 ~ 0xBFFFF 此端被划分为16个16Kbyte的子区间，每个寄存器有8个范围。(一个寄存器64位，要用8位来指定一个内存类型，所以一个寄存器只能藐视8段)
// IA32_MTRR_FIX4K_C0000 IA32_MTRR_FIX4K_F8000 映射8个32Kbyte的地址范围。此范围分为64个4kb子区间 (上同原理
union IA32_MTRR_FIXED_RANGE_MSR {
	ULONG64 all;
	struct {
		UCHAR types[8];
	} fields;
};
static_assert(sizeof(IA32_MTRR_FIXED_RANGE_MSR) == 8, "Size check");

/// See: IA32_MTRR_PHYSBASEn and IA32_MTRR_PHYSMASKn Variable-Range Register
// Variable-Range 物理地址寄存器是成对出现的 一个描述基地址 一个描述范围掩码
union IA32_MTRR_PHYSICAL_BASE_MSR
{
	ULONG64 all;
	struct {
		ULONG64 type : 8;        //!< [0:7]
		ULONG64 reserved : 4;    //!< [8:11]
		ULONG64 phys_base : 36;  //!< [12:MAXPHYADDR]
	} fields;
};
static_assert(sizeof(IA32_MTRR_PHYSICAL_BASE_MSR) == 8, "Size check");

/// See: IA32_MTRR_PHYSBASEn and IA32_MTRR_PHYSMASKn Variable-Range Register
union IA32_MTRR_PHYSICAL_MASK_MSR 
{
	ULONG64 all;
	struct {
		ULONG64 reserved : 11;   //!< [0:10]
		ULONG64 valid : 1;       //!< [11]				是否正在使用
		ULONG64 phys_mask : 36;  //!< [12:MAXPHYADDR]	PhysicalBase & PhysicalMask = PhysicalMask & AddressWithinRange
	} fields;
};
static_assert(sizeof(IA32_MTRR_PHYSICAL_MASK_MSR) == 8, "Size check");

// IA32_APIC_BASE MSR Supporting x2 APIC
union IA32_APIC_BASE_MSR
{
	ULONG64 all;
	struct
	{
		ULONG64 Reserved1 : 8;
		ULONG64 BootstrapProcessor : 1;
		ULONG64 Reserved2 : 1;
		ULONG64 EnableX2apicMode : 1;
		ULONG64 EnableX2apicGlobal : 1;
		ULONG64 ApicBase : 24;
	}fields;
};
static_assert(sizeof(IA32_APIC_BASE_MSR) == 8, "Size check");

// ASM about struct

/// See: SYSTEM FLAGS AND FIELDS IN THE EFLAGS REGISTER
union FLAG_REGISTER 
{
	ULONG_PTR all;
	struct {
		ULONG_PTR cf : 1;          //!< [0] Carry flag
		ULONG_PTR reserved1 : 1;   //!< [1] Always 1
		ULONG_PTR pf : 1;          //!< [2] Parity flag
		ULONG_PTR reserved2 : 1;   //!< [3] Always 0
		ULONG_PTR af : 1;          //!< [4] Borrow flag
		ULONG_PTR reserved3 : 1;   //!< [5] Always 0
		ULONG_PTR zf : 1;          //!< [6] Zero flag
		ULONG_PTR sf : 1;          //!< [7] Sign flag
		ULONG_PTR tf : 1;          //!< [8] Trap flag
		ULONG_PTR intf : 1;        //!< [9] Interrupt flag
		ULONG_PTR df : 1;          //!< [10] Direction flag
		ULONG_PTR of : 1;          //!< [11] Overflow flag
		ULONG_PTR iopl : 2;        //!< [12:13] I/O privilege level
		ULONG_PTR nt : 1;          //!< [14] Nested task flag
		ULONG_PTR reserved4 : 1;   //!< [15] Always 0
		ULONG_PTR rf : 1;          //!< [16] Resume flag
		ULONG_PTR vm : 1;          //!< [17] Virtual 8086 mode
		ULONG_PTR ac : 1;          //!< [18] Alignment check
		ULONG_PTR vif : 1;         //!< [19] Virtual interrupt flag
		ULONG_PTR vip : 1;         //!< [20] Virtual interrupt pending
		ULONG_PTR id : 1;          //!< [21] Identification flag
		ULONG_PTR reserved5 : 10;  //!< [22:31] Always 0
	} fields;
};
static_assert(sizeof(FLAG_REGISTER) == sizeof(void*), "Size check");

/// Represents a stack layout after PUSHAQ
struct GP_REGISTER_X64
{
	ULONG_PTR r15;
	ULONG_PTR r14;
	ULONG_PTR r13;
	ULONG_PTR r12;
	ULONG_PTR r11;
	ULONG_PTR r10;
	ULONG_PTR r9;
	ULONG_PTR r8;
	ULONG_PTR di;
	ULONG_PTR si;
	ULONG_PTR bp;
	ULONG_PTR sp;
	ULONG_PTR bx;
	ULONG_PTR dx;
	ULONG_PTR cx;
	ULONG_PTR ax;
};

/// Represents a stack layout after PUSHAD
struct GP_REGISTER_X86
{
	ULONG_PTR di;
	ULONG_PTR si;
	ULONG_PTR bp;
	ULONG_PTR sp;
	ULONG_PTR bx;
	ULONG_PTR dx;
	ULONG_PTR cx;
	ULONG_PTR ax;
};

#if defined(_AMD64_)
using GP_REGISTER = GP_REGISTER_X64;
#else
using GP_REGISTER = GP_REGISTER_X86;
#endif

// 记录pushfx pushax 后的栈情况
struct ALL_REGISTERS
{
	GP_REGISTER gp;
	FLAG_REGISTER flags;
};
#if defined(_AMD64_)
static_assert(sizeof(ALL_REGISTERS) == 0x88, "Size check");
#else
static_assert(sizeof(ALL_REGISTERS) == 0x24, "Size check");
#endif

/// See: CONTROL REGISTERS
union CR0 {
	ULONG_PTR all;
	struct {
		unsigned pe : 1;          //!< [0] Protected Mode Enabled
		unsigned mp : 1;          //!< [1] Monitor Coprocessor FLAG
		unsigned em : 1;          //!< [2] Emulate FLAG
		unsigned ts : 1;          //!< [3] Task Switched FLAG
		unsigned et : 1;          //!< [4] Extension Type FLAG
		unsigned ne : 1;          //!< [5] Numeric Error
		unsigned reserved1 : 10;  //!< [6:15]
		unsigned wp : 1;          //!< [16] Write Protect
		unsigned reserved2 : 1;   //!< [17]
		unsigned am : 1;          //!< [18] Alignment Mask
		unsigned reserved3 : 10;  //!< [19:28]
		unsigned nw : 1;          //!< [29] Not Write-Through
		unsigned cd : 1;          //!< [30] Cache Disable
		unsigned pg : 1;          //!< [31] Paging Enabled
	} fields;
};
static_assert(sizeof(CR0) == sizeof(void*), "Size check");

// GPTR IDTR
#include <pshpack1.h>
struct  IDTR
{
	unsigned short Limit;
	ULONG_PTR Base;
};

using GDTR = IDTR;
#if defined(_AMD64_)
static_assert(sizeof(IDTR) == 10, "Size check");
static_assert(sizeof(GDTR) == 10, "Size check");
#else
static_assert(sizeof(IDTR) == 6, "Size check");
static_assert(sizeof(GDTR) == 6, "Size check");
#endif
#include <poppack.h>

// MemoryType 被用来描述 VMCS和相关结构推荐使用的 PAT 内存类型
enum class MEMORY_TYPE : unsigned __int8
{
	kUncacheable = 0,
	kWriteCombining,
	kWriteThrough = 4,
	kWriteProtected,
	kWriteBack,
	kUncached
};

// Virtual-Machine Control StruCtures 
struct VM_CONTROL_STRUCTURE
{
	unsigned long RevisionIdentifier;
	unsigned long VmxAboutIndicator;
	unsigned long Data[1];				// 实现特殊的格式
};


// 3.5 Pin-Based VM-Execution Controls
union VMX_PINBASED_CONTROLS
{
	unsigned int all;
	struct
	{
		unsigned ExternalInterruptExiting : 1;
		unsigned Reserved1 : 2;
		unsigned NmiExiting : 1;
		unsigned Reserved2 : 1;
		unsigned VirtualNmis : 1;
		unsigned ActivateVmxPeemptionTimer : 1;
		unsigned ProcessPostedInterrupts : 1;
	}fields;
};
static_assert(sizeof(VMX_PINBASED_CONTROLS) == 4, "Size check");

// Primary Processor-Based VM-Execution Controls
union VMX_PROCESSOR_BASED_CONTROLS
{
	unsigned int all;
	struct  
	{
		unsigned Reserved1 : 2;					//!< [0:1]
		unsigned InterruptWindowExiting : 1;	//!< [2]
		unsigned UseTscOffseting : 1;			//!< [3]
		unsigned Reserved2 : 3;					//!< [4:6]
		unsigned HltExiting : 1;				//!< [7]
		unsigned Reserved3 : 1;					//!< [8]
		unsigned InvlpgExiting : 1;				//!< [9]
		unsigned MwaitExiting : 1;				//!< [10]
		unsigned RdpmcExiting : 1;				//!< [11]
		unsigned RdtscExiting : 1;				//!< [12]
		unsigned Reserved4 : 2;					//!< [13:14]
		unsigned Cr3LoadExiting : 1;			//!< [15]
		unsigned Cr3StoreExiting : 1;			//!< [16]
		unsigned Reserved5 : 2;					//!< [17:18]
		unsigned Cr8LoadExiting : 1;			//!< [19]
		unsigned Cr8StoreExiting : 1;			//!< [20]
		unsigned UseTprShadow : 1;				//!< [21]
		unsigned NmiWindowExiting : 1;			//!< [22]
		unsigned MovDrExiting : 1;				//!< [23]
		unsigned UnconditionalIoExiting : 1;	//!< [24]
		unsigned UseIoBitmap : 1;				//!< [25]
		unsigned Reserved6 : 1;					//!< [26]
		unsigned MonitorTrapFlag : 1;			//!< [27]
		unsigned UseMsrBitmaps : 1;				//!< [28]
		unsigned MonitorExiting : 1;			//!< [29]
		unsigned PauseExiting : 1;				//!< [30]
		unsigned ActivateSecondaryControl : 1;	//!< [31]
	}fields;
};
static_assert(sizeof(VMX_PROCESSOR_BASED_CONTROLS) == 4, "Size check");

union VMX_SECONDARY_PROCESSOR_BASED_CONTROLS
{
	unsigned int all;
	struct 
	{
		unsigned VirtualizeApicAccessed : 1;			//!< [0]	
		unsigned EnableEpt : 1;							//!< [1]
		unsigned DescriptorTableExiting : 1;			//!< [2]
		unsigned EnableRdtscap : 1;						//!< [3]
		unsigned VirtualizeX2apicMode : 1;				//!< [4]
		unsigned EnableVpid : 1;						//!< [5]
		unsigned WbinvdExiting : 1;						//!< [6]
		unsigned UnrestrictedGuest : 1;					//!< [7]
		unsigned ApicRegisterVirtualization : 1;		//!< [8]
		unsigned VirtualInterruptDelivery : 1;			//!< [9]
		unsigned PauseLoopExiting : 1;					//!< [10]
		unsigned RdrandExiting : 1;						//!< [11]
		unsigned EnableInvpcid : 1;						//!< [12]
		unsigned EnableVmFunctions : 1;					//!< [13]
		unsigned VmcsShadowing : 1;						//!< [14]
		unsigned Reserved1 : 1;							//!< [15]
		unsigned RdseedExiting : 1;						//!< [16]
		unsigned Reserved2 : 1;							//!< [17]
		unsigned EptViolationVe : 1;					//!< [18]
		unsigned Reserved3 : 1;							//!< [19]
		unsigned EnableXsavedXstors : 1;				//!< [20]
		unsigned Reserved4 : 1;							//!< [21]
		unsigned ModeBasedExecuteControlForEpt : 1;		//!< [22]
		unsigned Reserved5 : 2;							//!< [23:24]
		unsigned UseTscScaling : 1;						//!< [25]
	}fields;
};
static_assert(sizeof(VMX_SECONDARY_PROCESSOR_BASED_CONTROLS) == 4, "Size check");

// VM-Entry
union VMX_VMENTRY_CONTROLS
{
	unsigned int all;
	struct
	{
		unsigned Reserved1 : 2;                          //!< [0:1]
		unsigned LoadDebugControls : 1;                  //!< [2]
		unsigned Reserved2 : 6;                          //!< [3:8]
		unsigned Ia32eModeGuest : 1;                     //!< [9]
		unsigned EntryToSmm : 1;                         //!< [10]
		unsigned DeactivateDualMonitorTreatment : 1;     //!< [11]
		unsigned Reserved3 : 1;                          //!< [12]
		unsigned LoadIa32PerfGlobalCtrl : 1;             //!< [13]
		unsigned LoadIa32Pat : 1;                        //!< [14]
		unsigned LoadIa32Efer : 1;                       //!< [15]
		unsigned LoadIa32Bndcfgs : 1;                    //!< [16]
		unsigned ConcealVmentriesFromIntelPt : 1;        //!< [17]
	}fields;
};
static_assert(sizeof(VMX_VMENTRY_CONTROLS) == 4, "Size check");

union VMX_VMEXIT_CONTROLS
{
	unsigned int all;
	struct
	{
		unsigned Reserved1 : 2;                        //!< [0:1]
		unsigned SaveDebugControls : 1;                //!< [2]
		unsigned Reserved2 : 6;                        //!< [3:8]
		unsigned HostAddressSpaceSize : 1;             //!< [9]
		unsigned Reserved3 : 2;                        //!< [10:11]
		unsigned LoadIa32PerfGlobalCtrl : 1;           //!< [12]
		unsigned Reserver4 : 2;                        //!< [13:14]
		unsigned AcknowledgeInterruptOnExit : 1;       //!< [15]
		unsigned Reserved5 : 2;                        //!< [16:17]
		unsigned SaveIa32Pat : 1;                      //!< [18]
		unsigned LoadIa32Pat : 1;                      //!< [19]
		unsigned SaveIa32Efer : 1;                     //!< [20]
		unsigned LoadIa32Efer : 1;                     //!< [21]
		unsigned SaveVmxPreemptionTimerValue : 1;      //!< [22]
		unsigned ClearIa32Bndcfgs : 1;                 //!< [23]
		unsigned ConcealVmexitsFromIntelPt : 1;        //!< [24]
	}fields;
};
static_assert(sizeof(VMX_VMEXIT_CONTROLS) == 4, "Size check");

// EPT Struct (EPTP 
union EPT_POINTER
{
	ULONG64 all;
	struct {
		ULONG64 MemoryType : 3;                      //!< [0:2]
		ULONG64 PageWalkLength : 3;                 //!< [3:5]
		ULONG64 EnableAccessedAndDirtyFlags : 1;  //!< [6]
		ULONG64 Reserved1 : 5;                        //!< [7:11]
		ULONG64 Pm14Address : 36;                    //!< [12:48-1]
		ULONG64 Reserved2 : 16;                       //!< [48:63]
	} fields;
};
static_assert(sizeof(EPT_POINTER) == 8, "Size check");

struct INV_EPT_DESCRIPTOR
{
	EPT_POINTER EptPointer;
	ULONG64		Reserved1;
};
static_assert(sizeof(INV_EPT_DESCRIPTOR) == 16, "Size check");

enum class INV_EPT_TYPE : ULONG_PTR
{
	kSingleContextInvalidation = 1,
	kGlobalInvalidation
};

union EPT_VIOLATION_QUALIFICATION 
{
	ULONG64 all;
	struct {
		ULONG64 ReadAccess : 1;                   //!< [0]
		ULONG64 WriteAccess : 1;                  //!< [1]
		ULONG64 ExecuteAccess : 1;                //!< [2]
		ULONG64 EptReadable : 1;                  //!< [3]
		ULONG64 EptWriteable : 1;                 //!< [4]
		ULONG64 EptExecutable : 1;                //!< [5]
		ULONG64 EptExecutableForUserMode : 1;  //!< [6]
		ULONG64 ValidGuestLinearAddress : 1;    //!< [7]
		ULONG64 CausedByTranslation : 1;         //!< [8]
		ULONG64 UserModeLinearAddress : 1;      //!< [9]
		ULONG64 ReadableWritablePage : 1;        //!< [10]
		ULONG64 ExecuteDisablePage : 1;          //!< [11]
		ULONG64 NmiUnblocking : 1;                //!< [12]
	} fields;
};
static_assert(sizeof(EPT_VIOLATION_QUALIFICATION) == 8, "Size check");

// INVVPID 指令描述符
struct INV_VPID_DESCRIPTOR
{
	USHORT Vpid;
	USHORT Reserved1;
	USHORT Reserved2;
	ULONG64 LinearAddress;
};
static_assert(sizeof(INV_VPID_DESCRIPTOR) == 16, "Size check");

enum class INV_VPID_TYPE : ULONG_PTR
{
	kIndividualAddressInvalidation = 0,
	kSingleContextInvalidation,
	kAllContextInvalidation ,
	kSingleContextInvalidationExceptGlobal
};

/// See: PDPTE Registers
union PDPTR_REGISTER {
	ULONG64 all;
	struct {
		ULONG64 Present : 1;             //!< [0]
		ULONG64 Reserved1 : 2;           //!< [1:2]
		ULONG64 WriteThrough : 1;       //!< [3]
		ULONG64 CacheDisable : 1;       //!< [4]
		ULONG64 Reserved2 : 4;           //!< [5:8]
		ULONG64 Ignored : 3;             //!< [9:11]
		ULONG64 PageDirectoryPhysicalAddr : 41;  //!< [12:52]
		ULONG64 Reserved3 : 11;          //!< [53:63]
	} fields;
};
static_assert(sizeof(PDPTR_REGISTER) == 8, "Size check");

union VMX_REGMENT_DESCRIPTOR_ACCESS_RIGHT
{
	unsigned int all;
	struct 
	{
		unsigned Type : 4;			//!< [0:3]
		unsigned System : 1;		//!< [4]
		unsigned Dpl : 2;			//!< [5:6]
		unsigned Present : 1;		//!< [7]
		unsigned Reserved1 : 4;		//!< [8:11]
		unsigned Avl : 1;			//!< [12]
		unsigned l : 1;				//!< [13] Reserved (except for CS) 64-bit mode
		unsigned Db : 1;			//!< [14]
		unsigned Gran : 1;			//!< [15]
		unsigned Unusable : 1;		//!< [16] Segment unusable
		unsigned Reserved2 : 15;	//!< [17:31]
	}fields;
};
static_assert(sizeof(VMX_REGMENT_DESCRIPTOR_ACCESS_RIGHT) == 4, "Size check");

#include <pshpack1.h>
union SEGMENT_SELECTOR {
	unsigned short all;
	struct {
		unsigned short Rpl : 2;  //!< Requested Privilege Level
		unsigned short Ti : 1;   //!< Table Indicator
		unsigned short Index : 13;
	} fields;
};
static_assert(sizeof(SEGMENT_SELECTOR) == 2, "Size check");
#include <poppack.h>

union SEGMENT_DESCRIPTOR {
	ULONG64 all;
	struct {
		ULONG64 LimitLow : 16;
		ULONG64 BaseLow : 16;
		ULONG64 BaseMid : 8;
		ULONG64 Type : 4;
		ULONG64 System : 1;
		ULONG64 Dpl : 2;
		ULONG64 Present : 1;
		ULONG64 LimitHigh : 4;
		ULONG64 Avl : 1;
		ULONG64 L : 1;  //!< 64-bit code segment (IA-32e mode only)
		ULONG64 Db : 1;
		ULONG64 Gran : 1;
		ULONG64 BaseHigh : 8;
	} fields;
};
static_assert(sizeof(SEGMENT_DESCRIPTOR) == 8, "Size check");

/// @copydoc SegmentDescriptor
struct SEGMENT_DESCRIPTOR_X64 
{
	SEGMENT_DESCRIPTOR Descriptor;
	ULONG32 BaseUpper32;
	ULONG32 Reserved;
};
static_assert(sizeof(SEGMENT_DESCRIPTOR_X64) == 16, "Size check");

// See: Format of Exit Reason in Basic VM-Exit Information
union VM_EXIT_INFORMATION 
{
	unsigned int all;
	struct {
		VMX_EXIT_REASON reason;                      //!< [0:15]
		unsigned short reserved1 : 12;             //!< [16:30]
		unsigned short pending_mtf_vm_exit : 1;    //!< [28]
		unsigned short vm_exit_from_vmx_root : 1;  //!< [29]
		unsigned short reserved2 : 1;              //!< [30]
		unsigned short vm_entry_failure : 1;       //!< [31]
	} fields;
};
static_assert(sizeof(VM_EXIT_INFORMATION) == 4, "Size check");

union VM_EXIT_INTERRUPTION_INFORMATION_FIELD
{
	ULONG32 all;
	struct 
	{
		ULONG32 Vector : 8;				//!< [0:7]
		ULONG32 InterruptionType : 3;	//!< [8:10]
		ULONG32 ErrorCodeValid : 1;		//!< [11]
		ULONG32 NmiUnblocking : 1;		//!< [12]
		ULONG32 Reserved : 18;			//!< [13:30]
		ULONG32 Valid : 1;				//!< [31]
	}field;
};
static_assert(sizeof(VM_EXIT_INTERRUPTION_INFORMATION_FIELD) == 4, "Size check");


/// @copydoc VmEntryInterruptionInformationField
enum class INTERRUPTION_TYPE 
{
	kExternalInterrupt = 0,
	kReserved = 1,						// Not used for VM-Exit
	kNonMaskableInterrupt = 2,
	kHardwareException = 3,
	kSoftwareInterrupt = 4,            // Not used for VM-Exit
	kPrivilegedSoftwareException = 5,  // Not used for VM-Exit
	kSoftwareException = 6,
	kOtherEvent = 7,				  // Not used for VM-Exit
};

enum class INTERRUPTION_VECTOR
{
	kDivideErrorException = 0,         //!< Error code: None
	kDebugException = 1,               //!< Error code: None
	kNmiInterrupt = 2,                 //!< Error code: N/A
	kBreakpointException = 3,          //!< Error code: None
	kOverflowException = 4,            //!< Error code: None
	kBoundRangeExceededException = 5,  //!< Error code: None
	kInvalidOpcodeException = 6,       //!< Error code: None
	kDeviceNotAvailableException = 7,  //!< Error code: None
	kDoubleFaultException = 8,         //!< Error code: Yes
	kCoprocessorSegmentOverrun = 9,    //!< Error code: None
	kInvalidTssException = 10,         //!< Error code: Yes
	kSegmentNotPresent = 11,           //!< Error code: Yes
	kStackFaultException = 12,         //!< Error code: Yes
	kGeneralProtectionException = 13,  //!< Error code: Yes
	kPageFaultException = 14,          //!< Error code: Yes
	kx87FpuFloatingPointError = 16,    //!< Error code: None
	kAlignmentCheckException = 17,     //!< Error code: Yes
	kMachineCheckException = 18,       //!< Error code: None
	kSimdFloatingPointException = 19,  //!< Error code: None
	kVirtualizationException = 20,     //!< Error code: None
};

/// See: Page-Fault Error Code
union PAGEFAULT_ERROR_CODE 
{
	ULONG32 all;
	struct {
		ULONG32 present : 1;   //!< [1] 0= NotPresent
		ULONG32 write : 1;     //!< [2] 0= Read
		ULONG32 user : 1;      //!< [3] 0= CPL==0
		ULONG32 reserved : 1;  //!< [4]
		ULONG32 fetch : 1;     //!< [5]
	} fields;
};
static_assert(sizeof(PAGEFAULT_ERROR_CODE) == 4, "Size check");

union VM_ENTRY_INTERRUPTION_INFORMATION_FIELD
{
	ULONG32 all;
	struct 
	{
		ULONG32 Vector : 8;				//!< [0:7]
		ULONG32 InterruptionType : 3;	//!< [8:10]
		ULONG32 DeliverErrorType : 1;	//!< [11]
		ULONG32 Reserved : 18;			//!< [12:30]
		ULONG32 Valid : 1;				//!< [31]			标示是否有效
	}fields;
};
static_assert(sizeof(VM_ENTRY_INTERRUPTION_INFORMATION_FIELD) == 4, "Size check");

union GDTR_IDTR_INST_INFORMATION
{
	ULONG32 all;
	struct {
		ULONG32 Scalling : 2;                //!< [0:1]
		ULONG32 Reserved1 : 5;               //!< [2:6]
		ULONG32 AddressSize : 3;            //!< [7:9]
		ULONG32 Reserved2 : 1;               //!< [10]
		ULONG32 OperandSize : 1;            //!< [11]
		ULONG32 Reserved3 : 3;               //!< [12:14]
		ULONG32 SegmentRegister : 3;        //!< [15:17]
		ULONG32 IndexRegister : 4;          //!< [18:21]
		ULONG32 IndexRegisterInvalid : 1;  //!< [22]
		ULONG32 BaseRegister : 4;           //!< [23:26]
		ULONG32 BaseRegisterInvalid : 1;   //!< [27]
		ULONG32 InstructionIdentity : 2;    //!< [28:29]
		ULONG32 Reserved4 : 2;               //!< [30:31]
	} fields;
};
static_assert(sizeof(GDTR_IDTR_INST_INFORMATION) == 4, "Size check");

enum class SCALING
{
	kNoScaling = 0,
	kScaleBy2,
	kScaleBy4,
	kScaleBy8,
};

enum class ADDRESS_SIZE 
{
	k16bit = 0,
	k32bit,
	k64bit,
};


enum class GDTR_IDTR_INST_IDENTIFY 
{
	kSgdt = 0,
	kSidt,
	kLgdt,
	kLidt,
};

union LDTR_TR_INST_INFORMATION {
	ULONG32 all;
	struct {
		ULONG32 Scalling : 2;                //!< [0:1]
		ULONG32 Reserved1 : 1;               //!< [2]
		ULONG32 Register1 : 4;               //!< [3:6]
		ULONG32 AddressSize : 3;            //!< [7:9]
		ULONG32 RegisterAccess : 1;         //!< [10]
		ULONG32 Reserved2 : 4;               //!< [11:14]
		ULONG32 SegmentRegister : 3;        //!< [15:17]
		ULONG32 IndexRegister : 4;          //!< [18:21]
		ULONG32 IndexRegisterInvalid : 1;  //!< [22]
		ULONG32 BaseRegister : 4;           //!< [23:26]
		ULONG32 BaseRegisterInvalid : 1;   //!< [27]
		ULONG32 InstructionIdentity : 2;    //!< [28:29]
		ULONG32 Reserved4 : 2;               //!< [30:31]
	} fields;
};
static_assert(sizeof(LDTR_TR_INST_INFORMATION) == 4, "Size check");

enum class LDTR_TR_INST_IDENTITY 
{
	kSldt = 0,
	kStr,
	kLldt,
	kLtr,
};