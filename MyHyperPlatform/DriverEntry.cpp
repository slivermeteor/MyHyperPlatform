// https://msdn.microsoft.com/en-us/library/windows/hardware/hh920402(v=vs.85).aspx
// 为了编译一个简单二进制驱动 可以运行在win8及之前的驱动。就应该使用这个宏选项
// 这个宏是为了第三方驱动可以动态支持多个版本的windows而诞生的 - 关联函数 ExInitializeDriverRuntime
#ifndef POOL_NX_OPTIN
#define POOL_NX_OPTIN 1
#endif

#include "Common.h"
#include "Log.h"
#include "GlobalVariables.h"
#include "PowerCallback.h"
#include "Util.h"
#include "Performance.h"
#include "HotplugCallback.h"
#include "VM.h"

EXTERN_C_START

// 函数预声明
DRIVER_UNLOAD DriverUnload;
BOOLEAN IsSupportedOS();

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath)
{
	NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
	BOOLEAN NeedReinitialization = FALSE;
	
	UNREFERENCED_PARAMETER(RegisterPath);
	UNREFERENCED_PARAMETER(DriverObject);
	// LogFile 变量初始化
	static const wchar_t LogFilePath[] = L"\\SystemRoot\\HyperPlatform.log";
	static const unsigned long LogLevel = (IsReleaseBuild()) ? LogPutLevelInfo  | LogOptDisableFunctionName :
															   LogPutLevelDebug | LogOptDisableFunctionName;

	// UnloadDriver
	DriverObject->DriverUnload = DriverUnload;

	// 请求 NX 非分页内存池
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);	// 这个函数必须在任何内存申请操作之前

	// 初始化 Log 函数
	NtStatus = LogInitialization(LogLevel, LogFilePath);
	if (NtStatus == STATUS_REINITIALIZATION_NEEDED)
		NeedReinitialization = TRUE;
	else if (!NT_SUCCESS(NtStatus))
		return NtStatus;

	// 检查系统是否支持
	if (IsSupportedOS())
	{
		LogTermination();
		return NtStatus;
	}

	//  初始化全局变量
	NtStatus = GlobalVariablesInitialization();
	if (!NT_SUCCESS(NtStatus))
	{
		LogTermination();
		return NtStatus;
	}

	// 初始化行为函数 ?
	NtStatus = PerfInitialization();
	if (!NT_SUCCESS(NtStatus)) {
		GlobalVariablesTermination();
		LogTermination();
		return NtStatus;
	}

	// 初始化工具函数
	NtStatus = UtilInitialization(DriverObject);
	if (!NT_SUCCESS(NtStatus)) {
		PerfTermination();
		GlobalVariablesTermination();
		LogTermination();
		return NtStatus;
	}

	// 初始化电源回调函数
	NtStatus = PowerCallbackInitialization();
	if (!NT_SUCCESS(NtStatus)) {
		UtilTermination();
		PerfTermination();
		GlobalVariablesTermination();
		LogTermination();
		return NtStatus;
	}

	// 初始化热插拔函数
	NtStatus = HotplugCallbackInitialization();
	if (!NT_SUCCESS(NtStatus)) {
		PowerCallbackTermination();
		UtilTermination();
		PerfTermination();
		GlobalVariablesTermination();
		LogTermination();
		return NtStatus;
	}

	// 虚拟化所有处理器
	NtStatus = VmInitialization();
	if (!NT_SUCCESS(NtStatus)) {
		HotplugCallbackTermination();
		PowerCallbackTermination();
		UtilTermination();
		PerfTermination();
		GlobalVariablesTermination();
		LogTermination();
		return NtStatus;
	}

	// 如果需要，注册重初始化函数为log函数
	//if (NeedReinitialization)
	//	LogRegisterReinitialization(DriverObject);

	MYHYPERPLATFORM_LOG_PRINT("The VM has been installed.");
	return NtStatus;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
}

// 检查系统是否支持
BOOLEAN IsSupportedOS()
{
	PAGED_CODE();

	RTL_OSVERSIONINFOW OsVersionInfo = { 0 };
	NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;

	NtStatus = RtlGetVersion(&OsVersionInfo);
	if (!NT_SUCCESS(NtStatus))
		return FALSE;
	// 6 - Windows Vista --- Windows 8.1
	// 10 - Windows 10
	if (OsVersionInfo.dwMajorVersion != 6 && OsVersionInfo.dwMajorVersion != 10)
		return FALSE;

	if (IsX64() && (ULONG_PTR)MmSystemRangeStart != 0x80000000)
		return FALSE;

	return TRUE;
}

EXTERN_C_END