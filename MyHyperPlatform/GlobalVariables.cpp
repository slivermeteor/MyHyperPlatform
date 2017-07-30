#include "GlobalVariables.h"

// .CRT 节要求调用 ctors and dtors. 当前程序嵌入一个 .CRT 节到 .rdata 节。
// 或者会触发一个链接警告
#pragma comment(linker, "/merge:.CRT=.rdata")

// 创建两个节 - 来放置ctors数组 在编译时 - 注意按照字母顺序排序
#pragma section(".CRT$XCA", read)
#pragma section(".CRT$XCZ", read)

EXTERN_C_START

static const ULONG GlobalVariablePoolTag = 'asXX';

using DESTRUCTOR = void(__cdecl *)();	// 销毁器 - 函数指针

typedef struct _DESTRUCTOR_ENTRY_ 
{
	DESTRUCTOR        Destructor;	    // 销毁器 - 函数指针
	SINGLE_LIST_ENTRY ListEntry;		// 系统提供的Next指针。可以使用它放在自己的结构体里面。同时调用系统的API，来快速维护链表
}DESTRUCTOR_ENTRY;


#ifdef ALLOC_PRAGMA	// ALLOC_PRAGM 宏来判断当前编译器是否支持alloc_text
//alloc_text 可以将指定的函数放入指定的段中
#pragma alloc_text(INIT, GlobalVariablesInitialization) // 对于初始化完成就不再需要的函数，可以插入INIT段
#pragma alloc_text(INIT, atexit)
#pragma alloc_text(PAGE, GlobalVariablesTermination)	// PAGE - 分页池
#endif

// 将开始和结束指针放入CRT两个节中
// https://docs.microsoft.com/zh-cn/cpp/c-runtime-library/crt-initialization
// 下面这两个是标志了CRT节组的开始和结束 - 意味着用户对于全局变量的初始化一定在这两个节之前
__declspec(allocate(".CRT$XCA")) static DESTRUCTOR g_GopCtorsBegin[1] = {};
__declspec(allocate(".CRT$XCZ")) static DESTRUCTOR g_GopCtorsEnd[1] = {};

// 存储 销毁器 的指针，在退出的时候要用
static SINGLE_LIST_ENTRY gGopDtorsListHead = {};

// 如果你有任何全局变量需要初始化，放入到 g_GopCtorsBegin 。在这里使用。在当前框架中未使用到。
_Use_decl_annotations_ NTSTATUS GlobalVariablesInitialization()
{
	PAGED_CODE();

	for (auto ctor = g_GopCtorsBegin + 1; ctor < g_GopCtorsEnd; ctor++)
	{
		(*ctor)();
	}

	return STATUS_SUCCESS;
}
						
_Use_decl_annotations_ void GlobalVariablesTermination()
{
	PAGED_CODE();

	auto Entry = PopEntryList(&gGopDtorsListHead);
	while (Entry)
	{
		const auto Element = CONTAINING_RECORD(Entry, DESTRUCTOR_ENTRY, ListEntry);
		Element->Destructor();
		ExFreePoolWithTag(Element, GlobalVariablePoolTag);
		Entry = PopEntryList(&gGopDtorsListHead);
	}
}

// 注册销毁器 - 这个函数应该由一个构造器呼叫
_IRQL_requires_max_(PASSIVE_LEVEL) int __cdecl atexit(_In_ DESTRUCTOR Destructor)
{
	PAGED_CODE();
	const auto Element = reinterpret_cast<DESTRUCTOR_ENTRY*>(ExAllocatePoolWithTag(PagedPool, sizeof(DESTRUCTOR), GlobalVariablePoolTag));

	if (!Element)
		return 1;

	Element->Destructor = Destructor;
	// 插入一个节点在List前面
	PushEntryList(&gGopDtorsListHead, &Element->ListEntry);
	return 0;
}

EXTERN_C_END