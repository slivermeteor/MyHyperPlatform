#pragma once

#include <fltKernel.h>

EXTERN_C_START


// 检查EPT机制是否支持
// @return 支持，返回真
_IRQL_requires_max_(PASSIVE_LEVEL) bool EptIsEptAvailable();

// 读取存储所有的MTRR 用来纠正EPT
_IRQL_requires_max_(PASSIVE_LEVEL) void EptInitializeMtrrEntries();

EXTERN_C_END