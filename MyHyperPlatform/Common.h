#pragma once

#include <fltKernel.h>

#pragma prefast(disable : 30030)

#if !defined(MYHYPERPLATFORM_COMMON_DBG_BREAK)
// 判断当前是否有调试器加载
// 最后的 0 是为了让这个宏使用时，类似一个函数
#define MYHYPERPLATFORM_COMMON_DBG_BREAK()  \
		if (KD_DEBUGGER_NOT_PRESENT)        \
		{ }						            \
		else                                \
		{									\
			__debugbreak();					\
		}									\
		reinterpret_cast<void*>(0)
#endif

// 说明和触发BUG
// @param TypeOfCheckBug bug类型
// @param param1 KeBugCheckEx() 第一参数
// @param param2 KeBugCheckEx() 第二参数
// @param param3 KeBugCheckEx() 第三参数
#if !defined(MYHYPERPLATFORM_COMMON_BUG_CHECK)
#define MYHYPERPLATFORM_COMMON_BUG_CHECK(BugType, param1, param2, param3)	\
			MYHYPERPLATFORM_COMMON_DBG_BREAK();							    \
			const HYPERPLATFORM_BUG_CHECK code = (BugType);					\
			KeBugCheckEx(MANUALLY_INITIATED_CRASH, static_cast<ULONG>(code),\
						(param1), (param2), (param3))
#endif

// 启动 | 关闭 全局行为记录
#define MYHYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER 1

static const ULONG HyperPlatformCommonPoolTag = 'AazZ';

// BugCheck Type for #MYHYPERPLATFORM_COMMON_BUG_CHECK
enum class HYPERPLATFORM_BUG_CHECK : ULONG
{
	kUnspecified,                    //!< An unspecified bug occurred
	kUnexpectedVmExit,               //!< An unexpected VM-exit occurred
	kTripleFaultVmExit,              //!< A triple fault VM-exit occurred
	kExhaustedPreallocatedEntries,   //!< All pre-allocated entries are used
	kCriticalVmxInstructionFailure,  //!< VMRESUME or VMXOFF has failed
	kEptMisconfigVmExit,             //!< EPT misconfiguration VM-exit occurred
	kCritialPoolAllocationFailure,   //!< Critical pool allocation failed
};

// 判断是否是 64 位系统
// @return 当系统是64位，返回 true 
constexpr bool IsX64() 
{
// constrexpr 描述函数，表示函数返回常量
#if defined(_AMD64_)
	return true;
#else
	return false;
#endif
}

// 检查当前是否是 released 编译状态
// @return 当前是relese版本 返回true
constexpr bool IsReleaseBuild()
{
#if defined(DBG)
	return false;
#else
	return true;
#endif
}
