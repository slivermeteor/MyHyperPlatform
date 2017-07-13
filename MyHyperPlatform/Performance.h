#pragma once
#include "PerfCounter.h"

EXTERN_C_START



_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS PerfInitialization();

_IRQL_requires_max_(PASSIVE_LEVEL) void PerfTermination();



EXTERN_C_END

