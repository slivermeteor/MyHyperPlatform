#ifndef MYHYPERPLATFORM_LOG_H
#define MYHYPERPLATFORM_LOG_H

#include <fltKernel.h>

EXTERN_C_START

#define MYHYPERPLATFORM_LOG_PRINT(msg) DbgPrint("%s\r\n", msg);

#define MYHYPERPLATFORM_LOG_INFO(Format, ...) \
	LogPrint(LogLevelInfo, __FUNCTION__, (Format), __VA_ARGS__)

#define MYHYPERPLATFORM_LOG_DEBUG(Format, ...) \
	LogPrint(LogLevelDebug, __FUNCTION__, (Format), __VA_ARGS__)

#define MYHYPERPLATFORM_LOG_WARN(Format, ...) \
	LogPrint(LogLevelWarn, __FUNCTION__, (Format), __VA_ARGS__)

#define MYHYPERPLATFORM_LOG_ERROR(Format, ...) \
	LogPrint(LogLevelError, __FUNCTION__, (Format), __VA_ARGS__)


#define MYHYPERPLATFORM_LOG_DEBUG_SAFE(Format, ...) \
	LogPrint(LogLevelDebug | LogLevelOptSafe, __FUNCTION__, (Format), __VA_ARGS__)

#define MYHYPERPLATFORM_LOG_WARN_SAFE(Format, ...) \
	LogPrint(LogLevelWarn | LogLevelOptSafe, __FUNCTION__, (Format), __VA_ARGS__)

#define MYHYPERPLATFORM_LOG_ERROR_SAFE(Format, ...) \
	LogPrint(LogLevelError | LogLevelOptSafe, __FUNCTION__, (Format), __VA_ARGS__)

#define MYHYPERPLATFORM_LOG_INFO_SAFE(Format, ...) \
	LogPrint(LogLevelInfo | LogLevelOptSafe, __FUNCTION__, (Format), __VA_ARGS__)

// 决定Log消息是写入文件还是输出
static const auto LogLevelOptSafe = 0x1ul;

// Log Variables 
// 下面是四个Log的等级 - 根据Log等级，决定是否答应信息
static const auto LogLevelDebug = 0x10ul;	
static const auto LogLevelInfo  = 0x20ul;
static const auto LogLevelWarn  = 0x40ul;
static const auto LogLevelError = 0x80ul;

// 下面五个参数是分别指明在Log消息中，是否输出指定消息的控制函数
static const auto LogPutLevelDisable = 0x00ul;
static const auto LogOptDisableTime = 0x100ul;
static const auto LogOptDisableFunctionName = 0x200ul;
static const auto LogOptDisableProcessorNumber = 0x400ul;
static const auto LogOptDisableDbgPrint = 0x800ul;

// 有效所有的Log消息
static const auto LogPutLevelDebug = LogLevelError | LogLevelInfo | LogLevelDebug | LogLevelWarn;
// 有效 INFO WARN ERROR 的Log消息
static const auto LogPutLevelInfo = LogLevelError | LogLevelWarn | LogLevelInfo;
// 有效 WARN ERROR 的Log消息
static const auto LogPutLevelWarn = LogLevelError | LogLevelWarn;
// 有效 ERROR 的Log消息
static const auto LogPutLevelError = LogLevelError;



// Log a message: 一般都是通过 MYHYPERPLATFORM_LOG_*()函数来调用
// @param Level 消息等级
// @param FunctionName 调用函数名
// @param Format 要输出的消息
// @return 函数成功返回 STATUS_SUCCESS
// @see MYHYPERPLATFORM_LOG_DEBUG MYHYPERPLATFORM_LOG_SAFE
NTSTATUS LogPrint(_In_ ULONG Level, _In_z_ const char* FunctionName, _In_z_ _Printf_format_string_ const char* Format, ...);


// 初始化Log系统
// @param Flag  OR-ed 值去控制Log等级和可选项 LogPutLevel* | LogOpt* (LogPutLevelDebug | LogOptDisableFunctionName
// @param FilaPath Log文件路径
// @return 函数成功返回STATUS_SUCCESS。 返回 STATUS_REINITIALIZATION_NEEDED， 当函数需要调用 LogRegisterReinitialization，即函数没有真正初始化完成。
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS LogInitialization(_In_ ULONG Flag, _In_opt_ const wchar_t* FilePath);

// 结束Log系统。由UnloadDriver呼叫,或者错误处理。
_IRQL_requires_max_(PASSIVE_LEVEL) void LogTermination();


EXTERN_C_END



#endif