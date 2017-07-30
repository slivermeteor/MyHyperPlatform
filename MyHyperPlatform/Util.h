#pragma once

#include "ia32_type.h"

EXTERN_C_START


// 在一个给定地址范围内搜索一段字符串(代码
// @param SearchBase 搜索起始地址 
// @param SearchSize 搜索范围长度
// @param Pattern 进行搜索的字符串
// @param PatternSize 搜索字符串长度
// @return 第一个搜索到的地址，如果没找到返回nullptr
void* UtilMemSearch(_In_ const void* SearchBase, _In_ SIZE_T SearchSize, _In_ const void* Pattern, _In_ SIZE_T PatternSize);

// 得到一个内核导出符号(函数)地址
// @param ProcName 导出符号名
// @return 符号地址或者空
void* UtilGetSystemProcAddress(_In_ const wchar_t* ProcName);

// 在每个处理器上执行回调函数
// @param CallbackRoutine 想要执行的回调函数
// @prarm Context 传入回调函数的参数
// @return 见实现的注释
_IRQL_requires_max_(APC_LEVEL) NTSTATUS UtilForEachProcessor(_In_ NTSTATUS(*CallbackRoutine)(void*), _In_opt_ void* Context);

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS UtilInitialization(_In_ PDRIVER_OBJECT DriverObject);

_IRQL_requires_max_(PASSIVE_LEVEL) void UtilTermination();

// VMX 指令操作函数 - 将 VMX 的汇编指令封装成函数
enum class VMX_STATUS : unsigned __int8
{
	kOk = 0,
	kErrorWithStatus,
	kErrorWithoutStatus
};

// 提供 VmxStatus 的 |= c=操作符
constexpr VMX_STATUS operator |= (_In_ VMX_STATUS lhs, _In_ VMX_STATUS rhs)
{
	return static_cast<VMX_STATUS>(static_cast<unsigned __int8>(lhs) | static_cast<unsigned __int8>(rhs));
}

// Available command numbers for VMCALL
enum class HYPERCALL_NUMBER : unsigned __int32 
{
	kTerminateVmm,            //!< Terminates VMM
	kPingVmm,                 //!< Sends ping to the VMM
	kGetSharedProcessorData,  //!< Terminates VMM
};

// 返回物理地址范围
// @return 永远不会失败
const PHYSICAL_MEMORY_DESCRIPTOR* UtilGetPhysicalMemoryRanges();

// PA VA PFN 三者之间的相互转换
// PA -> PFN
// @pa 想要得到页面号码的物理地址
// @return 页面号码 
PFN_NUMBER UtilPfnFromPa(_In_ ULONG64 pa);
// PA -> VA
PVOID UtilVaFromPa(_In_ ULONG64 pa);

// 两个虚拟地址转换的函数 对分页模式有要求 不能在使用PTE的模式下使用
// VA -> PA
ULONG64 UtilPaFromVa(_In_ void* va);
// VA -> PFN
PFN_NUMBER UtilPfnFromVa(_In_ void* va);

// PFN -> PA
ULONG64 UtilPaFromPfn(_In_ PFN_NUMBER pfn);
// PFN -> VA
void* UtilVaFromPfn(_In_ PFN_NUMBER pfn);

// 申请连续物理内存
// @param NumberOfBytes 申请大小
// @return 申请得到的内存的基地址
// @tips 申请的内存必须通过 UtilFreeContiguousMemory
_Must_inspect_result_ _IRQL_requires_max_(DISPATCH_LEVEL)
void* UtilAllocateContiguousMemory(_In_ SIZE_T NumberOfBytes);

// MSR 操作函数
ULONG_PTR UtilReadMsr(_In_ MSR msr);
ULONG64 UtilReadMsr64(_In_ MSR msr);

void UtilWriteMsr(_In_ MSR msr, _In_ ULONG_PTR Value);
void UtilWriteMsr64(_In_ MSR msr, _In_ ULONG64 Value);

// 读取自适应长度的 VMCS-field 
// @param Field  VMCS-field to read
// @return read value
ULONG_PTR UtilVmRead(_In_ VMCS_FIELD Field);

// 读取定长64位的 VMCS
// @param Field 读取域
ULONG64 UtilVmRead64(_In_ VMCS_FIELD Field);

// 写入 VMCS 区域
// @param Field 进行写入的 VMCS-Filed 
// @param FiledValue 写入的值
// @return 写入结果
VMX_STATUS UtilVmWrite(_In_ VMCS_FIELD Field, _In_ ULONG_PTR FieldValue);

// 写入 64 bits VMCS 区域
VMX_STATUS UtilVmWrite64(_In_ VMCS_FIELD Field, _In_ ULONG64 FieldValue);

// 执行 VMCALL - asm层封装
NTSTATUS UtilVmCall(_In_ HYPERCALL_NUMBER HypercallNumber, _In_opt_ void* Context);


// 输出寄存器的值
// @param AllRegiters 要输出的寄存器
// @param StackPointer 在调用函数之前的栈地址
void UtilDumpGpRegisters(_In_ const ALL_REGISTERS* AllRegisters, _In_ ULONG_PTR StackPointer);


// 执行 INVEPT 指令，冲刷 EPT Entry 缓存
// @return INVEPT 指令返回结果
VMX_STATUS UtilInveptGlobal();

// Executes the INVVPID instruction (type 0)
// @return A result of the INVVPID instruction
VMX_STATUS UtilInvvpidIndividualAddress(_In_ USHORT Vpid, _In_ void* Address);

// Executes the INVVPID instruction (type 2)
// @return A result of the INVVPID instruction
VMX_STATUS UtilInvvpidAllContext();

/// Executes the INVVPID instruction (type 3)
/// @return A result of the INVVPID instruction
VMX_STATUS UtilInvvpidSingleContextExceptGlobal(_In_ USHORT Vpid);

// 检查当前系统是否是 32位下的 PAE 分页模式
bool UtilIsX86PAE();

void UtilLoadPdptes(_In_ ULONG_PTR Cr3Value);

EXTERN_C_END

template<typename T>
constexpr bool UtilIsInBounds(_In_ const T& Value, _In_ const T& Min, _In_ const T& Max)
{
	return (Min <= Value) && (Value <= Max);
}


