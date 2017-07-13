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

static const ULONG HyperPlatformCommonPoolTag = 'AazZ';

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
