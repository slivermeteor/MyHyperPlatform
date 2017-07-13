#pragma once

#include <fltKernel.h>

EXTERN_C_START

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS VmInitialization();

_IRQL_requires_max_(PASSIVE_LEVEL) void VmTermination();

EXTERN_C_END