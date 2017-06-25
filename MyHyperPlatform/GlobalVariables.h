#pragma once

#include <fltKernel.h>

EXTERN_C_START

// 呼叫所有的构造器和注册所有的销毁器
// @return 函数成功返回STATUS_SUCCESS 
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS GlobalVariablesInitialization();

// 调用所有的销毁器
_IRQL_requires_max_(PASSIVE_LEVEL) void GlobalVariablesTermination();


EXTERN_C_END