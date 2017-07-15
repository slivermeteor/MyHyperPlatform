#pragma once

#include <fltKernel.h>

EXTERN_C_START

struct EPT_DATA;

// 
union EPT_COMMON_ENTRY
{
	ULONG64 all;
	struct {
		ULONG64 ReadAccess : 1;       //!< [0]
		ULONG64 WriteAccess : 1;      //!< [1]
		ULONG64 ExecuteAccess : 1;    //!< [2]
		ULONG64 MemoryType : 3;       //!< [3:5]
		ULONG64 Reserved1 : 6;         //!< [6:11]
		ULONG64 PhysicalAddress : 36;  //!< [12:48-1]
		ULONG64 Reserved2 : 16;        //!< [48:63]
	} fields;
};
static_assert(sizeof(EPT_COMMON_ENTRY) == 8, "Size check");

// 检查EPT机制是否支持
// @return 支持，返回真
_IRQL_requires_max_(PASSIVE_LEVEL) bool EptIsEptAvailable();

// 读取存储所有的MTRR 用来纠正EPT
_IRQL_requires_max_(PASSIVE_LEVEL) void EptInitializeMtrrEntries();

// 构造申请 EPT 结构体 申请 Pre-Allocated 初始化 EPT 页表结构
// 
_IRQL_requires_max_(PASSIVE_LEVEL) EPT_DATA* EptInitialization();

EXTERN_C_END