#pragma once

#include <fltKernel.h>

EXTERN_C_START

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS PowerCallbackInitialization();
_IRQL_requires_max_(PASSIVE_LEVEL) void PowerCallbackTermination();



EXTERN_C_END