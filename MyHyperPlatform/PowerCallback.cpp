#include "PowerCallback.h"
#include "Log.h"
#include "Common.h"
#include "VM.h"


EXTERN_C_START

static CALLBACK_FUNCTION PowerCallbackRoutine;

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, PowerCallbackInitialization)
#pragma alloc_text(PAGE, PowerCallbackTermination)
#pragma alloc_text(PAGE, PowerCallbackRoutine)
#endif

static PCALLBACK_OBJECT g_PC_CallbackObject = nullptr;	// PowerState 回调对象
static PVOID g_PC_Registration = nullptr;			    // 回调函数句柄


_Use_decl_annotations_ NTSTATUS PowerCallbackInitialization()
{
	PAGED_CODE();

	UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
	OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&Name, OBJ_CASE_INSENSITIVE);

	// 创建或者打开一个回调对象
	// 第三参数决定是打开还是创建 - FALSE 打开
	// \\Callback\\PowerState \\Callback\\SetSystemTime 是两个系统创建好的 可以直接使用的回调对象
	// 关机的时候，进行各项回收处理 - 类似 Unload。
	auto NtStatus = ExCreateCallback(&g_PC_CallbackObject, &ObjectAttributes, FALSE, TRUE);
	if (!NT_SUCCESS(NtStatus))
		return NtStatus;

	// 向 PowerState 回调对象注册回调函数
	// https://msdn.microsoft.com/EN-US/library/ff545534(v=VS.85,d=hv.2).aspx - 关于 PowerState 的回调函数要求
	g_PC_Registration = ExRegisterCallback(g_PC_CallbackObject, PowerCallbackRoutine, nullptr);
	if (!g_PC_Registration)
	{
		ObDereferenceObject(g_PC_CallbackObject);
		g_PC_CallbackObject = nullptr;
		
		return STATUS_UNSUCCESSFUL;
	}

	return NtStatus;
}

_Use_decl_annotations_ void PowerCallbackTermination()
{
	PAGED_CODE();

	if (g_PC_Registration)
	{
		ExUnregisterCallback(g_PC_Registration);
		g_PC_Registration = nullptr;
	}

	if (g_PC_CallbackObject)
	{
		ObDereferenceObject(g_PC_CallbackObject);
		g_PC_Registration = nullptr;
	}
}

// @param CallbackContext 驱动支持的上下文 - 是在你注册的时候 传入 ExRegisterCallback 的第三参数
// @param Argument1 PO_CB_XXX const 指针值 根据传入的结构体不同 表示不同的状态
// @prarm Argument2 TRUE / FALSE 
// https://msdn.microsoft.com/EN-US/library/ff545534(v=VS.85,d=hv.2).aspx 具体各个参数的含义
// 当前回调主要为了处理 睡眠和休眠
_Use_decl_annotations_ static void PowerCallbackRoutine(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
	UNREFERENCED_PARAMETER(CallbackContext);
	PAGED_CODE();

	MYHYPERPLATFORM_LOG_DEBUG("PowerCallback %p %p", Argument1, Argument2);

	if (Argument1 != reinterpret_cast<void*>(PO_CB_SYSTEM_STATE_LOCK))
		return;

	MYHYPERPLATFORM_COMMON_DBG_BREAK();

	if (Argument2)
	{
		MYHYPERPLATFORM_LOG_INFO("Resume the system.");
		NTSTATUS NtStatus = VmInitialization();
		if (!NT_SUCCESS(NtStatus))
			MYHYPERPLATFORM_LOG_ERROR("Failed to re-virtualize processors. Please unload the driver.");
	}
	else
	{
		MYHYPERPLATFORM_LOG_INFO("Suspend thr system.");
		VmTermination();
	}
}

EXTERN_C_END
