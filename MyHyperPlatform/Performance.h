#pragma once
#include "PerfCounter.h"

EXTERN_C_START

#if (MYHYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER != 0)

// 计算执行时间
#define MYHYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE()	\
	MYHYPERPLATFORM_PERFCOUNTER_MEASURE_TIME(g_PerformanceCollector, PerfGetTime)

#else
	#define MYHYPERPLATFORM_PEFORMANCE_MEASURE_THIS_SCOPE()
#endif

_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS PerfInitialization();

_IRQL_requires_max_(PASSIVE_LEVEL) void PerfTermination();

ULONG64 PerfGetTime();

extern PERF_COLLECTOR* g_PerformanceCollector;

EXTERN_C_END

