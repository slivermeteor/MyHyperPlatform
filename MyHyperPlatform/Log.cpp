#include "Log.h"
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstatus.h>
#include <Ntstrsafe.h>

#pragma prefast(disable : 30030)

EXTERN_C_START

//
// LogBuffer 缓存的页个数 - 在 LOG_BUFFER_INFO 申请了两块缓存
// 超出这个长度后，不再记录Log消息。
static const auto LogBufferSizeInPages = 16ul;
static const auto LogBufferSize = PAGE_SIZE * LogBufferSizeInPages;	// Buffer 真实长度
static const auto LogBufferUsableSize = LogBufferSize - 1;			// Buffer 可用最大长度 - 减去了尾部的 \0
// 刷新线程 间隔时间
static const auto LogFlushIntervalMsec = 50;
static const ULONG LogPoolTag = 'log ';

// 
typedef struct _LOG_BUFFER_INFO_
{
	volatile char* LogBufferHead;
	volatile char* LogBufferTail;

	char* LogBufferOne;
	char* LogBufferTwo;

	SIZE_T LogMaxUsage;
	HANDLE LogFileHandle;
	KSPIN_LOCK SpinLock;
	ERESOURCE Resource;
	bool ResourceInitialized;
	volatile bool BufferFlushThreadShouldBeAlive;		// 控制刷新线程运行变量
	volatile bool BufferFlushThreadStarted;

	HANDLE	BufferFlushThreadHandle;
	wchar_t LogFilePath[100];
}LOG_BUFFER_INFO, *PLOG_BUFFER_INFO;

//
static auto g_LogDebugFlag = LogPutLevelDisable;
static LOG_BUFFER_INFO g_LogBufferInfo = { 0 };

// 本地函数预声明
NTKERNELAPI UCHAR* NTAPI PsGetProcessImageFileName(_In_ PEPROCESS Process);


_IRQL_requires_max_(PASSIVE_LEVEL) static void LogFinalizeBufferInfo(_In_ LOG_BUFFER_INFO* LogBufferInfo);

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS LogInitializeBufferInfo(_In_ const wchar_t* LogFilePath, _Inout_ LOG_BUFFER_INFO* LogBufferInfo);

static bool LogIsLogNeeded(_In_ ULONG Level);

static bool LogIsDbgPrintNeeded();

static void LogDbgBreak();

static NTSTATUS LogMakePrefix(_In_ ULONG Level, _In_z_ const char* FunctionName, _In_z_ const char* LogMessage, _Out_ char* LogBuffer, _In_ SIZE_T LogBufferLength);

static const char* LogFindBaseFunctionName(_In_z_ const char* FunctionName);

static NTSTATUS LogPut(_In_z_ char* Message, _In_ ULONG Attribute);

static void LogDoDbgPrint(_In_z_ char * Message);

static bool LogIsLogFileEnabled(_In_ const LOG_BUFFER_INFO& LogBufferInfo);

static bool LogIsLogFileActivated(_In_ const LOG_BUFFER_INFO& LogBufferInfo);

static bool LogIsPrinted(char *Message);

static void LogSetPrintedBit(_In_z_ char *Message, _In_ bool on);

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS LogFlushLogBuffer(_Inout_ LOG_BUFFER_INFO* LogBufferInfo);

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS LogWriteMessageToFile(_In_z_ const char* Message, _In_ const LOG_BUFFER_INFO& LogBufferInfo);

static NTSTATUS LogBufferMessage(_In_z_ const char* Message,_Inout_ LOG_BUFFER_INFO* LogBufferInfo);

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS LogInitializeLogFile(_Inout_ LOG_BUFFER_INFO* LogBufferInfo); 

static KSTART_ROUTINE LogBufferFlushThreadRoutine;
static DRIVER_REINITIALIZE LogReinitializationRoutine;

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS LogSleep(_In_ LONG Millsecond);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, LogInitialization)
#pragma alloc_text(INIT, LogInitializeBufferInfo)
//#pragma alloc_text(INIT, LogRegisterReinitialization)

#pragma alloc_text(PAGE, LogInitializeLogFile)
#pragma alloc_text(PAGE, LogTermination)
#pragma alloc_text(PAGE, LogFinalizeBufferInfo)
#pragma alloc_text(PAGE, LogSleep)
#pragma alloc_text(PAGE, LogBufferFlushThreadRoutine)
#endif

////////////////////////////////////////////////////////////////
// 函数实现

_Use_decl_annotations_ NTSTATUS LogInitialization(ULONG Flag, const wchar_t* LogFilePath)
{
	PAGED_CODE();

	NTSTATUS NtStatus = STATUS_SUCCESS;
	g_LogDebugFlag = Flag;

	// 创建LogFile - 如果指定LogFilePath
	bool NeedReinitialization = false;
	if (LogFilePath)
	{
		NtStatus = LogInitializeBufferInfo(LogFilePath, &g_LogBufferInfo);
		if (NtStatus == STATUS_REINITIALIZATION_NEEDED)
			NeedReinitialization = true;	// 需要等待第二时间初始化
		else if (!NT_SUCCESS(NtStatus))
			return NtStatus;				// 失败
	}

	// 测试Log
	NtStatus = MYHYPERPLATFORM_LOG_INFO("Log has been %sinitialized.", (NeedReinitialization ? "partially " : ""));
	if (!NT_SUCCESS(NtStatus))
		goto FAIL;

	// 输出Log信息
	MYHYPERPLATFORM_LOG_DEBUG("Info=%p, Buffer=%p %p, File=%S", &g_LogBufferInfo, g_LogBufferInfo.LogBufferOne, g_LogBufferInfo.LogBufferTwo, LogFilePath);
	return (NeedReinitialization ? STATUS_REINITIALIZATION_NEEDED : STATUS_SUCCESS);	// 正确退出

FAIL:
	if (LogFilePath)
		LogFinalizeBufferInfo(&g_LogBufferInfo);

	return NtStatus;
} 

// 初始化传入的第二个成员 LOG_BUFFER_INFO 变量
_Use_decl_annotations_ static NTSTATUS LogInitializeBufferInfo(const wchar_t* LogFilePath, LOG_BUFFER_INFO* LogBufferInfo)
{
	PAGED_CODE();
	NT_ASSERT(LogFilePath);
	NT_ASSERT(LogBufferInfo);

	// 初始化自旋锁
	KeInitializeSpinLock(&LogBufferInfo->SpinLock);

	// 拷贝字符串													  得到 LogFilePath 长度
	NTSTATUS NtStatus = RtlStringCchCopyW(LogBufferInfo->LogFilePath, RTL_NUMBER_OF_FIELD(LOG_BUFFER_INFO, LogFilePath), LogFilePath);
	if (!NT_SUCCESS(NtStatus))
		return NtStatus;

	// 初始化一个资源
	NtStatus = ExInitializeResourceLite(&LogBufferInfo->Resource);
	if (!NT_SUCCESS(NtStatus))
		return NtStatus;

	LogBufferInfo->ResourceInitialized = true;

	// 申请两块缓存 - 如果失败就清理 LogBufferInfo
	LogBufferInfo->LogBufferOne = reinterpret_cast<char*>(ExAllocatePoolWithTag(NonPagedPool, LogBufferSize, LogPoolTag));
	if (!LogBufferInfo->LogBufferOne)
	{
		LogFinalizeBufferInfo(LogBufferInfo);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	LogBufferInfo->LogBufferTwo = reinterpret_cast<char*>(ExAllocatePoolWithTag(NonPagedPool, LogBufferSize, LogPoolTag));
	if (!LogBufferInfo->LogBufferTwo)
	{
		LogFinalizeBufferInfo(LogBufferInfo);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// 初始化两块Buffer
	// 两块 Buffer， 一块用来写入(LogFlushLogBuffer), 一块用来输出(LogBufferMessage)。两块轮转交换任务
	RtlFillMemory(LogBufferInfo->LogBufferOne, LogBufferSize, 0xFF);
	LogBufferInfo->LogBufferOne[0] = '\0';
	LogBufferInfo->LogBufferOne[LogBufferSize - 1] = '\0';

	RtlFillMemory(LogBufferInfo->LogBufferTwo, LogBufferSize, 0xFF);
	LogBufferInfo->LogBufferTwo[0] = '\0';
	LogBufferInfo->LogBufferTwo[LogBufferSize - 1] = '\0';

	// 写入 Buffer 时使用的都是写入 LogBufferTail
	// 读取 Buffer 都从 LogBufferHead 开始读取
	// 在切换 读取和写入Buffer的时候，也有牵涉到这两个变量的变化。具体见 LogFlushLogBuffer
	LogBufferInfo->LogBufferHead = LogBufferInfo->LogBufferOne;
	LogBufferInfo->LogBufferTail = LogBufferInfo->LogBufferOne;

	// 真正初始化函数
	NtStatus = LogInitializeLogFile(LogBufferInfo);
	if (NtStatus == STATUS_OBJECT_PATH_NOT_FOUND)	
		MYHYPERPLATFORM_LOG_INFO("The log file needs to be activated later.");	
	else if (!NT_SUCCESS(NtStatus))	// 失败 - 清理资源
		LogFinalizeBufferInfo(LogBufferInfo);

	return NtStatus;
}

// 结束对于LogFile的操作 - 清空 LogBufferInfo
_Use_decl_annotations_ static void LogFinalizeBufferInfo(LOG_BUFFER_INFO* LogBufferInfo)
{
	PAGED_CODE();
	NT_ASSERT(LogBufferInfo);

	// 关闭LogBuffe刷新线程
	if (LogBufferInfo->BufferFlushThreadHandle)
	{
		LogBufferInfo->BufferFlushThreadShouldBeAlive = false;
		auto NtStatus = ZwWaitForSingleObject(LogBufferInfo->BufferFlushThreadHandle, FALSE, nullptr);
		if (!NT_SUCCESS(NtStatus))
			LogDbgBreak();

		ZwClose(LogBufferInfo->BufferFlushThreadHandle);
		LogBufferInfo->BufferFlushThreadHandle = nullptr;
	}

	// 清空其它项
	if (LogBufferInfo->LogFileHandle)
	{
		ZwClose(LogBufferInfo->LogFileHandle);
		LogBufferInfo->LogFileHandle = nullptr;
	}

	if (LogBufferInfo->LogBufferTwo)
	{
		ExFreePoolWithTag(LogBufferInfo->LogBufferTwo, LogPoolTag);
		LogBufferInfo->LogBufferTwo = nullptr;
	}

	if (LogBufferInfo->LogBufferOne)
	{
		ExFreePoolWithTag(LogBufferInfo->LogBufferOne, LogPoolTag);
		LogBufferInfo->LogBufferOne = nullptr;
	}

	if (LogBufferInfo->ResourceInitialized)
	{
		ExDeleteResourceLite(&LogBufferInfo->Resource);
		LogBufferInfo->ResourceInitialized = false;
	}
}

// 真正的Log输出函数
_Use_decl_annotations_ NTSTATUS LogPrint(ULONG Level, const char* FunctionName, const char* Format, ...)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;

	if (!LogIsLogNeeded(Level))
		return NtStatus;

	va_list Args;
	va_start(Args, Format);
	char LogMessage[412] = { 0 };
	// 创建一个字符串
	NtStatus = RtlStringCchVPrintfA(LogMessage, RTL_NUMBER_OF(LogMessage), Format, Args);

	va_end(Args);
	if (!NT_SUCCESS(NtStatus))
	{
		LogDbgBreak();
		return NtStatus;
	}

	if (LogMessage[0] == '\0')
	{
		LogDbgBreak();
		return STATUS_INVALID_PARAMETER;
	}

	const auto PureLevel = Level & 0xF0;
	const auto Attribute = Level & 0x0F;

	// 单次放入Log的消息长度应该小于512
	char Message[512] = { 0 };
	static_assert(RTL_NUMBER_OF(Message) <= 512, "On message should not exceed 512 bytes.");
	NtStatus = LogMakePrefix(PureLevel, FunctionName, LogMessage, Message, RTL_NUMBER_OF(Message));
	if (!NT_SUCCESS(NtStatus))
	{
		LogDbgBreak();
		return NtStatus;
	}
	// 将Message消息放入文件 或者 输出
	NtStatus = LogPut(Message, Attribute);
	if (!NT_SUCCESS(NtStatus))
		LogDbgBreak();
	
	return NtStatus;
}

// 连接Log消息
_Use_decl_annotations_ static NTSTATUS LogMakePrefix(ULONG Level, const char* FunctionName, const char* LogMessage, char* LogBuffer, SIZE_T LogBufferLength)
{
	// 构造Level
	char const *LevelString = nullptr;
	switch (Level)
	{
		case LogLevelDebug:
			LevelString = "DBG\t";
			break;
		case LogLevelError:
			LevelString = "ERR\t";
			break;
		case LogLevelWarn:
			LevelString = "WRN\t";
			break;
		case LogLevelInfo:
			LevelString = "INF\t";
			break;
		default:
			return STATUS_INVALID_PARAMETER;
	}

	NTSTATUS NtStatus = STATUS_SUCCESS;

	// 构造时间字符串
	char TimeBuffer[20] = { 0 };
	if ((g_LogDebugFlag & LogOptDisableTime) == 0)
	{
		TIME_FIELDS TimeFields = { 0 };
		LARGE_INTEGER SystemTime = { 0 };
		LARGE_INTEGER LocalTime = { 0 };

		KeQuerySystemTime(&SystemTime);
		ExSystemTimeToLocalTime(&SystemTime, &LocalTime);
		RtlTimeToTimeFields(&LocalTime, &TimeFields);

		NtStatus = RtlStringCchPrintfA(TimeBuffer, RTL_NUMBER_OF(TimeBuffer), "%02u:%02u:%02u.%03u\t", TimeFields.Hour, TimeFields.Minute, TimeFields.Second, TimeFields.Milliseconds);
		if (!NT_SUCCESS(NtStatus))
			return NtStatus;
	}

	// 构造函数名字符串
	char FunctionNameBuffer[50] = { 0 };
	if ((g_LogDebugFlag & LogOptDisableFunctionName) == 0)
	{
		const auto BaseFunctionName = LogFindBaseFunctionName(FunctionName);
		NtStatus = RtlStringCchPrintfA(FunctionNameBuffer, RTL_NUMBER_OF(FunctionNameBuffer), "%-40s\t", BaseFunctionName);
		if (!NT_SUCCESS(NtStatus))
			return NtStatus;
	}

	// 构造处理器字符串
	char ProcessorNumberBuffer[10] = { 0 };
	if ((g_LogDebugFlag & LogOptDisableProcessorNumber) == 0)
	{
		NtStatus = RtlStringCchPrintfA(ProcessorNumberBuffer, RTL_NUMBER_OF(ProcessorNumberBuffer), "#%lu\t", KeGetCurrentProcessorNumberEx(nullptr));
		if (!NT_SUCCESS(NtStatus))
			return NtStatus;
	}

	// 合并字符串

	NtStatus = RtlStringCchPrintfA(LogBuffer, LogBufferLength, "%s%s%s%5Iu\t%5Iu\t%-15s\t%s%s\r\n", TimeBuffer, LevelString, ProcessorNumberBuffer, reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId()),
		reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId()), PsGetProcessImageFileName(PsGetCurrentProcess()), FunctionNameBuffer, LogMessage);

	return NtStatus;
}

// 修改 __FUNCTION__ 宏，得到最基本的函数名
// namespace::class::function -> function
_Use_decl_annotations_ static const char * LogFindBaseFunctionName(const char * FunctionName)
{
	if (!FunctionName)
		return nullptr;
	
	auto Ptr = FunctionName;
	auto Name = FunctionName;

	while (*(Ptr++))
	{
		if (*Ptr == ':')
			Name = Ptr + 1;
	}

	return Name;
}

// 记录入口根据属性和线程情况
_Use_decl_annotations_ static NTSTATUS LogPut(char* Message, ULONG Attribute)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;

	// 当前属性中包含数安全 并且 IRQL 等级正常才可以进行输出
	auto DoDbgPrint = ((Attribute & LogLevelOptSafe) == 0 &&
		KeGetCurrentIrql() < CLOCK_LEVEL);

	// 记录Log消息到Buffer或者文件
	auto& LogBufferInfo = g_LogBufferInfo;
	if (LogIsLogFileEnabled(LogBufferInfo))		// 判断文件路径是否有效
	{
		// 判断当前是否可以写入文件
		if (((Attribute & LogLevelOptSafe) == 0) && KeGetCurrentIrql() == PASSIVE_LEVEL && LogIsLogFileActivated(LogBufferInfo))
		{
#pragma warning(push)
#pragma warning(disable:28123)
			if (!KeAreAllApcsDisabled()) // 这个函数判断当前线程的IRQL是否 >= APC_LEVEL，因为APC_LEVEL会使所有APC失效。如果大于，返回真。小于，返回FALSE
			{
				LogFlushLogBuffer(&LogBufferInfo);		// 刷新缓存
				NtStatus = LogWriteMessageToFile(Message, LogBufferInfo);
			}
#pragma warning(pop)
		}
	}
	else
	{
		// 如果可以打印 - 设置打印标志位为真
		if (DoDbgPrint)
			LogSetPrintedBit(Message, true);
		// 写入到 LogBuffeInfo 中
		NtStatus = LogBufferMessage(Message, &LogBufferInfo);
		LogSetPrintedBit(Message, false);
	}
	// 选择性输出
	if (DoDbgPrint)
		LogDoDbgPrint(Message);

	return NtStatus;
}

// @return 返回true，当需要打印Log
_Use_decl_annotations_ bool LogIsLogNeeded(ULONG Level)
{
	return !!(g_LogDebugFlag & Level);
}

static void LogDbgBreak()
{
	if (!KD_DEBUGGER_NOT_PRESENT)
		__debugbreak();
}

_Use_decl_annotations_ static bool LogIsLogFileEnabled(const LOG_BUFFER_INFO& LogBufferInfo)
{
	if (LogBufferInfo.LogBufferOne)
	{
		NT_ASSERT(LogBufferInfo.LogBufferTwo);
		NT_ASSERT(LogBufferInfo.LogBufferHead);
		NT_ASSERT(LogBufferInfo.LogBufferTail);

		return true;
	}
	
	NT_ASSERT(!LogBufferInfo.LogBufferTwo);
	NT_ASSERT(!LogBufferInfo.LogBufferHead);
	NT_ASSERT(!LogBufferInfo.LogBufferTail);

	return false;
}

_Use_decl_annotations_ static bool LogIsLogFileActivated(const LOG_BUFFER_INFO& LogBufferInfo)
{
	if (LogBufferInfo.BufferFlushThreadShouldBeAlive)
	{
		NT_ASSERT(LogBufferInfo.BufferFlushThreadHandle);
		NT_ASSERT(LogBufferInfo.BufferFlushThreadHandle);

		return true;
	}

	NT_ASSERT(!LogBufferInfo.BufferFlushThreadHandle);
	NT_ASSERT(!LogBufferInfo.BufferFlushThreadHandle);

	return false;
}

// 刷新Log缓存 - 将旧的Log缓存写入到Log文件中，如果必要打印它们。
_Use_decl_annotations_ static NTSTATUS LogFlushLogBuffer(LOG_BUFFER_INFO* LogBufferInfo)
{
	NT_ASSERT(LogBufferInfo);
	NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

	NTSTATUS NtStatus = STATUS_SUCCESS;

	// 进入临界区 - 并且上锁资源
	ExEnterCriticalRegionAndAcquireResourceExclusive(&LogBufferInfo->Resource);

	// 申请队列自旋锁 
	// https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/queued-spin-locks 关于 Queued Spin Lock 
	// 队列自旋锁在多核多线程的机器上，更加高效。保证是第一个申请锁的先执行。
	// 这里申请锁，为了改变 LogBufferHead 安全
	KLOCK_QUEUE_HANDLE LockHandle = {};
	// 锁在切换和写入的时候才使用。
	// 在读取的时候不用。因为主要牵涉到 Head 和 Tail 的修改
	KeAcquireInStackQueuedSpinLock(&LogBufferInfo->SpinLock, &LockHandle);

	// 得到当前的写入Buffer
	const auto OldLogBuffer = const_cast<char*>(LogBufferInfo->LogBufferHead);
	if (OldLogBuffer[0])	// 判断是否使用了，如果没有使用就没有切换的需要
	{
		// 切换写入 Buffer 另一个 Buffer 上。
		LogBufferInfo->LogBufferHead = (OldLogBuffer == LogBufferInfo->LogBufferOne)
			? LogBufferInfo->LogBufferTwo : LogBufferInfo->LogBufferOne;
		LogBufferInfo->LogBufferHead[0] = '\0';		// 清空 Buffer
		LogBufferInfo->LogBufferTail = LogBufferInfo->LogBufferHead; // 尾部回到当前写入 Buffer 首部。	
	}
	KeReleaseInStackQueuedSpinLock(&LockHandle);	

	// 将所有OldLogBuffer写入文件
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	for (auto CurrentLogEntry = OldLogBuffer; CurrentLogEntry[0]; )
	{
		const auto IsPrinteOut = LogIsPrinted(CurrentLogEntry);
		LogSetPrintedBit(CurrentLogEntry, false);					// 设置标志位 - 标示已经输出

		// 得到长度，写入文件。
		const auto CurrentLogEntryLength = strlen(CurrentLogEntry);
		NtStatus = ZwWriteFile(LogBufferInfo->LogFileHandle, nullptr, nullptr, nullptr, &IoStatusBlock, CurrentLogEntry, static_cast<ULONG>(CurrentLogEntryLength), nullptr, nullptr);
		if (!NT_SUCCESS(NtStatus)) //  // It could happen when you did not register IRP_SHUTDOWN and call LogIrpShutdownHandler() and the system tried to log to a file after a file system was unmounted.
			LogDbgBreak();

		// 如果需要 打印
		if (!IsPrinteOut)
			LogDoDbgPrint(CurrentLogEntry);

		CurrentLogEntry += CurrentLogEntryLength + 1;
	}
	OldLogBuffer[0] = '\0';

	ExReleaseResourceAndLeaveCriticalRegion(&LogBufferInfo->Resource);
	return NtStatus;
}

// 测试这块缓存是否可以输出
_Use_decl_annotations_ static bool LogIsPrinted(char *Message) 
{
	return (Message[0] & 0x80) != 0;
}

// 修改标志位  - 赋值，表示已经准备输出 清零，并将它放回原始
_Use_decl_annotations_ static void LogSetPrintedBit(char *Message, bool on) 
{
	if (on) {
		Message[0] |= 0x80;
	}
	else {
		Message[0] &= 0x7f;
	}
}

// Calls DbgPrintEx() while converting \r\n to \n\0
_Use_decl_annotations_ static void LogDoDbgPrint(char *Message) 
{
	if (!LogIsDbgPrintNeeded()) {
		return;
	}
	const auto LocationOfTail = strlen(Message) - 2;
	Message[LocationOfTail] = '\n';
	Message[LocationOfTail + 1] = '\0';
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", Message);
}

// @return 当可以调用 DbgPrint 时，返回真
static bool LogIsDbgPrintNeeded()
{
	return (g_LogDebugFlag & LogOptDisableDbgPrint) == 0;
}

// 将Log信息写入到文件中
_Use_decl_annotations_ static NTSTATUS LogWriteMessageToFile(const char* Message, const LOG_BUFFER_INFO& LogBufferInfo)
{
	NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	NTSTATUS NtStatus = ZwWriteFile(LogBufferInfo.LogFileHandle, nullptr, nullptr, nullptr, &IoStatusBlock, const_cast<char*>(Message), static_cast<ULONG>(strlen(Message)), nullptr, nullptr);
	if (!NT_SUCCESS(NtStatus))
		LogDbgBreak();

	NtStatus = ZwFlushBuffersFile(LogBufferInfo.LogFileHandle, &IoStatusBlock);
	return NtStatus;
}

// 将Log信息放入到缓存中
_Use_decl_annotations_ static NTSTATUS LogBufferMessage(const char* Message, LOG_BUFFER_INFO* LogBufferInfo)
{
	NT_ASSERT(LogBufferInfo);

	// 申请自旋锁 - 牵涉 Head Tail 必须上锁
	KLOCK_QUEUE_HANDLE LockHandle = { 0 };
	const auto OldIRQL = KeGetCurrentIrql();
	
	if (OldIRQL < PASSIVE_LEVEL)
		KeAcquireInStackQueuedSpinLock(&LogBufferInfo->SpinLock, &LockHandle);
	else
		KeAcquireInStackQueuedSpinLockAtDpcLevel(&LogBufferInfo->SpinLock, &LockHandle);

	NT_ASSERT(KeGetCurrentIrql() >= DISPATCH_LEVEL);

	// 将当前的 Logbuffer 拷贝出来
	SIZE_T UsedBufferSize = LogBufferInfo->LogBufferTail - LogBufferInfo->LogBufferHead;
	NTSTATUS NtStatus = RtlStringCchCopyA(const_cast<char*>(LogBufferInfo->LogBufferTail), LogBufferUsableSize - UsedBufferSize, Message);	// 拷贝的长度 是还可以使用的长度

	// 更新 LogBufferTail 可能更新 LogMaxUsage
	if (NT_SUCCESS(NtStatus))
	{
		const auto MessageLength = strlen(Message) + 1;
		LogBufferInfo->LogBufferTail += MessageLength;
		UsedBufferSize += MessageLength;

		if (UsedBufferSize > LogBufferInfo->LogMaxUsage)
			LogBufferInfo->LogMaxUsage = UsedBufferSize;
	}
	else
		LogBufferInfo->LogMaxUsage = LogBufferSize;		// 表示已经溢出

	*LogBufferInfo->LogBufferTail = '\0';	// 每次写入完成，加 0。用来读取时候，作为分隔符。

	if (OldIRQL < DISPATCH_LEVEL)
		KeReleaseInStackQueuedSpinLock(&LockHandle);
	else
		KeReleaseInStackQueuedSpinLockFromDpcLevel(&LockHandle);

	return NtStatus;
}

// 初始化 LogBufferInfo 中有关文件的成员  并且开启刷新线程
_Use_decl_annotations_ static NTSTATUS LogInitializeLogFile(LOG_BUFFER_INFO* LogBufferInfo)
{
	PAGED_CODE();

	// 如果已经完成了 - 退出
	if (LogBufferInfo->LogFileHandle)
		return STATUS_SUCCESS;

	// 初始化Log文件
	UNICODE_STRING UniLogFilePath = { 0 };
	RtlInitUnicodeString(&UniLogFilePath, LogBufferInfo->LogFilePath);
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	InitializeObjectAttributes(&ObjectAttributes, &UniLogFilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);
	IO_STATUS_BLOCK IoStatusBlock = { 0 };

	// 创建 / 打开文件 FILE_OPEN_IF
	NTSTATUS NtStatus = ZwCreateFile(&LogBufferInfo->LogFileHandle, FILE_APPEND_DATA | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, nullptr, FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, nullptr, 0);
	if (!NT_SUCCESS(NtStatus))
		return NtStatus;

	// 初始化刷新线程
	LogBufferInfo->BufferFlushThreadShouldBeAlive = true;
	NtStatus = PsCreateSystemThread(&LogBufferInfo->BufferFlushThreadHandle, GENERIC_ALL, nullptr, nullptr, nullptr, LogBufferFlushThreadRoutine, LogBufferInfo); // 当刷新线程启动成功 - 修改 LogBufferInfo->BufferFlushThreadStarted
	if (!NT_SUCCESS(NtStatus))
	{
		ZwClose(LogBufferInfo->LogFileHandle);
		LogBufferInfo->LogFileHandle = nullptr;
		LogBufferInfo->BufferFlushThreadShouldBeAlive = false;
		return NtStatus;
	}

	// 等待到线程启动完成 - 判断 BufferFlushThreadStarted
	// 目标线程在初始化完成后，修改变量。这里等待变量值的修改
	while (!LogBufferInfo->BufferFlushThreadStarted)
		LogSleep(100);

	return NtStatus;
}

// 睡眠函数
_Use_decl_annotations_ static NTSTATUS LogSleep(LONG Millsecond)
{
	PAGED_CODE();

	LARGE_INTEGER LargeInteger = { 0 };
	LargeInteger.QuadPart = -(10000ll * Millsecond);	// 10000 LL(两个小写l)
	return KeDelayExecutionThread(KernelMode, FALSE, &LargeInteger);
}

// LogFile刷新线程 - 跟 LogBufferInfo 一起存活的线程 由 LogBufferInfo->BufferFlushThreadShouldBeAlive 变量控制
// 刷新线程主要将 LogBuffer 写入到 Log文件中 - 每隔 LogFlushIntervalMsec 时间 进行刷新
_Use_decl_annotations_ static VOID LogBufferFlushThreadRoutine(void* StartContext)
{
	PAGED_CODE();
	NTSTATUS NtStatus = STATUS_SUCCESS;
	auto LogBufferInfo = reinterpret_cast<LOG_BUFFER_INFO*>(StartContext);
	LogBufferInfo->BufferFlushThreadStarted = true;				// 通知 LogInitializeLogFile ，刷新线程启动完成

	MYHYPERPLATFORM_LOG_DEBUG("Log thread started (TID = %p).", PsGetCurrentThreadId());

	// BufferFlushThreadShouldBeAlive !!!
	while (LogBufferInfo->BufferFlushThreadShouldBeAlive)
	{
		NT_ASSERT(LogIsLogFileActivated(*LogBufferInfo));
		if (LogBufferInfo->LogBufferHead[0])
		{
			NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
			NT_ASSERT(!KeAreAllApcsDisabled());
			NtStatus = LogFlushLogBuffer(LogBufferInfo);

			// 别为整体性能(overall performance)刷新文件。
			//就算触发了 KeBugCheck, 我们也可以通过 LogBuffer 恢复 Log
		}
		LogSleep(LogFlushIntervalMsec);
	}

	PsTerminateSystemThread(NtStatus);
}

// 结束Log系统
_Use_decl_annotations_ void LogTermination()
{
	PAGED_CODE();
	MYHYPERPLATFORM_LOG_DEBUG("Finalizing... (Max log usage = %Iu/%lu bytes)", g_LogBufferInfo.LogMaxUsage, LogBufferSize);
	MYHYPERPLATFORM_LOG_INFO("Log termination.");

	g_LogDebugFlag = LogPutLevelDisable;	// 修改全局标志 - 不再输出任何Log消息
	LogFinalizeBufferInfo(&g_LogBufferInfo);
}

_Use_decl_annotations_ void LogRegisterReinitialization(PDRIVER_OBJECT DriverObject)
{
	PAGED_CODE();

	IoRegisterBootDriverReinitialization(DriverObject, LogReinitializationRoutine, &g_LogBufferInfo);
	MYHYPERPLATFORM_LOG_INFO("The log file will be activated later.");
}

_Use_decl_annotations_ void static LogReinitializationRoutine(DRIVER_OBJECT* DriverObject, PVOID Context, ULONG Count)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(Count);

	NT_ASSERT(Context);

	auto LogBufferInfo = reinterpret_cast<LOG_BUFFER_INFO*>(Context);
	auto NtStatus = LogInitializeLogFile(LogBufferInfo);
	NT_ASSERT(NT_SUCCESS(NtStatus));

	if (NT_SUCCESS(NtStatus))
		MYHYPERPLATFORM_LOG_INFO("The log file has been activated.");

}

EXTERN_C_END

