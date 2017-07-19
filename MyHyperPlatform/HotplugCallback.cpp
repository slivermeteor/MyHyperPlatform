#include "HotplugCallback.h"
#include "Common.h"
#include "Log.h"
#include "VM.h"


EXTERN_C_START

static PROCESSOR_CALLBACK_FUNCTION HotplugCallbackRoutine;

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, HotplugCallbackInitialization)
#pragma alloc_text(PAGE, HotplugCallbackTermination)
#pragma alloc_text(PAGE, HotplugCallbackRoutine)
#endif

static PVOID g_HC_CallbackHandle = nullptr;

_Use_decl_annotations_ NTSTATUS HotplugCallbackInitialization()
{
	PAGED_CODE();

	// 注册热插拔回调
	auto CallbackHandle = KeRegisterProcessorChangeCallback(HotplugCallbackRoutine, nullptr, 0);
	if (!CallbackHandle)
		return STATUS_UNSUCCESSFUL;

	g_HC_CallbackHandle = CallbackHandle;
	
	return STATUS_SUCCESS;
}

_Use_decl_annotations_ void HotplugCallbackTermination()
{
	// 注销热插拔
	if (g_HC_CallbackHandle)
		KeDeregisterProcessorChangeCallback(g_HC_CallbackHandle);
}

_Use_decl_annotations_ static void HotplugCallbackRoutine(PVOID CallbackContext, PKE_PROCESSOR_CHANGE_NOTIFY_CONTEXT ChangeContext, PNTSTATUS OperationStatus)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(CallbackContext);
	UNREFERENCED_PARAMETER(OperationStatus);

	if (ChangeContext->State != KeProcessorAddCompleteNotify)
		return;

	MYHYPERPLATFORM_LOG_DEBUG("A new processor %hu:%hu has been added.", ChangeContext->ProcNumber.Group, ChangeContext->ProcNumber.Number);
	MYHYPERPLATFORM_COMMON_DBG_BREAK();

	auto NtStatus = VmHotplugCallback(ChangeContext->ProcNumber);
	if (!NT_SUCCESS(NtStatus))
		MYHYPERPLATFORM_LOG_ERROR("Failed to virtualize the new processors.");

	return;
}



EXTERN_C_END