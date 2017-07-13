#pragma once

#include <fltKernel.h>

EXTERN_C_START

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS HotplugCallbackInitialization();

_IRQL_requires_max_(PASSIVE_LEVEL) void HotplugCallbackTermination();

EXTERN_C_END