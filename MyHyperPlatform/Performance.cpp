#include "common.h"
#include "Performance.h"
#include "Log.h"

// 这一系列函数主要用来记录一些具体函数的执行时间和调用次数等等
// 也就调用行为记录

static PERF_COLLECTOR::INITIAL_OUTPUT_ROUTINE PerfInitialOutputRoutine;
static PERF_COLLECTOR::FINAL_OUTPUT_ROUTINE PerfFinalOutputRoutine;
static PERF_COLLECTOR::OUTPUT_ROUTINE PerfOutputRoutine;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, PerfInitialization)
#pragma alloc_text(PAGE, PerfTermination) 
#endif

PERF_COLLECTOR* g_PerformanceCollector;

// 初始化函数
_Use_decl_annotations_ NTSTATUS PerfInitialization()
{
	PAGED_CODE();
	
	NTSTATUS NtStatus = STATUS_SUCCESS;
	
	const auto PerfCollector = reinterpret_cast<PERF_COLLECTOR*>(ExAllocatePoolWithTag(NonPagedPool, sizeof(PERF_COLLECTOR), HyperPlatformCommonPoolTag));
	if (!PerfCollector)
		return STATUS_MEMORY_NOT_ALLOCATED;

	// 无锁 - 避免在VMM中呼叫内核函数 竞速状态?在这不是一个问题
	PerfCollector->Initialize(PerfOutputRoutine, PerfInitialOutputRoutine, PerfFinalOutputRoutine);
	g_PerformanceCollector = PerfCollector;

	return NtStatus;
}

// 终止函数
_Use_decl_annotations_ void PerfTermination()
{
	PAGED_CODE();

	if (g_PerformanceCollector)
	{
		g_PerformanceCollector->Terminate();
		ExFreePoolWithTag(g_PerformanceCollector, HyperPlatformCommonPoolTag);
		g_PerformanceCollector = nullptr;
	}
}

_Use_decl_annotations_ static void PerfInitialOutputRoutine(void* OutputContext)
{
	UNREFERENCED_PARAMETER(OutputContext);
	MYHYPERPLATFORM_LOG_INFO("%-45s,%-20s,%-20s", "FunctionName(Line)","Execution Count", "Elapsed Time");
}

_Use_decl_annotations_ static void PerfOutputRoutine(const char* LocationName, ULONG64 TotalExecutionCount, ULONG64 TotalElapsedTime, void* OutputContext)
{
	UNREFERENCED_PARAMETER(OutputContext);
    MYHYPERPLATFORM_LOG_INFO("%-45s,%20I64u,%20I64u,", LocationName, TotalExecutionCount, TotalElapsedTime);
}

_Use_decl_annotations_ static void PerfFinalOutputRoutine(void* OutputContext)
{
	UNREFERENCED_PARAMETER(OutputContext);
}

// 得到调用次数
ULONG64 PerfGetTime()
{
	LARGE_INTEGER Counter = KeQueryPerformanceCounter(nullptr);
	return static_cast<ULONG64>(Counter.QuadPart);
}