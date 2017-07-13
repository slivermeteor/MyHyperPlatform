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

// MSR 操作函数
ULONG_PTR UtilReadMsr(_In_ MSR msr);
ULONG64 UtilReadMsr64(_In_ MSR msr);

void UtilWriteMsr(_In_ MSR msr, _In_ ULONG_PTR Value);
void UtilWriteMsr64(_In_ MSR msr, _In_ ULONG64 Value);

EXTERN_C_END

template<typename T>
constexpr bool UtilIsInBounds(_In_ const T& Value, _In_ const T& Min, _In_ const T& Max)
{
	return (Min <= Value) && (Value <= Max);
}


