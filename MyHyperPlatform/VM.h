#pragma once

#include <fltKernel.h>

EXTERN_C_START

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS VmInitialization();

// 结束虚拟化
_IRQL_requires_max_(PASSIVE_LEVEL) void VmTermination();

// 虚拟化一个特定的处理器
// @param ProcNum   A processor number to virtualize
// @return 成功执行返回 STATUS_SUCCESS
// The processor 0 must have already been virtualized, or it fails.
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS VmHotplugCallback(const PROCESSOR_NUMBER& ProcNum);

EXTERN_C_END