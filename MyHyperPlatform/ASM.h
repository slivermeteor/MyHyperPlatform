#pragma once

#include "ia32_type.h"

EXTERN_C_START

// 对VM初始化的一层包装
// @param VmInitializationRoutine 进入VMX-mode的入口函数
// @param Context Context参数
// @return true 当函数执行成功
bool _stdcall AsmInitializeVm(_In_ void(*VmInitializationRoutine)(_In_ ULONG_PTR, _In_ ULONG_PTR, _In_opt_ void*), _In_opt_ void* Context);


EXTERN_C_END