#pragma once

#include <fltKernel.h>

#define HYPERPLATFORM_PERFCOUNTER_P_JOIN2(x, y) x##y		// question ??? 
#define HYPERPLATFORM_PERFCOUNTER_P_JOIN1(x, y) \
	HYPERPLATFORM_PERFCOUNTER_P_JOIN2(x, y)

#define HYPERPLATFORM_PERFCOUNTER_P_JOIN(x, y) \
	HYPERPLATFORM_PERFCOUNTER_P_JOIN1(x, y)

#define HYPERPLATFORM_PERFCOUNTER_P_TO_STRING1(n) #n

#define HYPERPLATFORM_PERFCOUNTER_P_TO_STRING(n) \
	HYPERPLATFORM_PERFCOUNTER_P_TO_STRING1(n)

// 创建一个 PerfCounter 实例来计算这段代码运行的时间
// @param Collector PerfCollector 实例
// @param QueryTimeRoutine 计算运行时间的函数指针
// 这个宏不能直接使用，
// 这个宏创建一个 PerfCounter 实例，命名为 PerfObj_N 。N 是一个连续变化的数字，从0开始递增。传入函数名和源代码行数传入宏。
// PerfCounter 在自己的构造函数里得到这两个参数。计算执行时间，并将它传入 Collector。
#define MYHYPERPLATFORM_PERFCOUNTER_MEASURE_TIME(Collector, QueryTimeRoutine)	\
	const PERF_COUNTER HYPERPLATFORM_PERFCOUNTER_P_JOIN(PerfObj_, __COUNTER__)(	\
		  (Collector), (QueryTimeRoutine),									    \
		  __FUNCTION__"("HYPERPLATFORM_PERFCOUNTER_P_TO_STRING(__LINE__) ")")


class PERF_COLLECTOR
{
public: 
	// 结果 最前面输出函数
	using INITIAL_OUTPUT_ROUTINE = void(_In_opt_ void* OutputContext);
	// 结果 最后行输出函数
	using FINAL_OUTPUT_ROUTINE = void(_In_opt_ void* OutputContext);
	// 结果 主输出函数类型
	using OUTPUT_ROUTINE = void(_In_ const char* LocationName,
							   _In_ ULONG64 TotalExecutionCount,
							   _In_ ULONG64 TotalElapsedTime,
						       _In_opt_ void* OutputContext);
	// Lock函数类型
	using LOCK_ROUTINE = void(_In_opt_ void* LockContext);

private:
	// 异常返回值
	static const ULONG InvalidDataIndex = MAXULONG;
	// 最多记录个数
	static const ULONG MaxNumberOfDataEntries = 200;
	// 记录每一个位置的行为 数据结构
	typedef struct _PERF_DATA_ENTRY_
	{
		// 唯一标示
		const char* Key;
		// 总共的执行次数
		ULONG64 TotalExecutionCount;	
		// 总共的执行时间
		ULONG64 TotalElapsedTime;
	}PERF_DATA_ENTRY;

	// 局部锁 - 内嵌类
	class SCOPED_LOCK
	{
	public: 
		SCOPED_LOCK(_In_ LOCK_ROUTINE* LockEnterRoutine, _In_ LOCK_ROUTINE* LockLeaveRoutine, _In_opt_ void* LockContext):
		m_EnterRoutine(LockEnterRoutine),  m_LeaveRoutine(LockLeaveRoutine), m_LockContext(LockContext)
		{
			// 执行背景文的初始化
			m_EnterRoutine(m_LockContext);
		}

		~SCOPED_LOCK()
		{
			m_LeaveRoutine(m_LockContext);
		}

	private:
		LOCK_ROUTINE* m_EnterRoutine;
		LOCK_ROUTINE* m_LeaveRoutine;
		void* m_LockContext;
	};
	// 私有变量定义

	INITIAL_OUTPUT_ROUTINE* m_InitialOutputRoutine;
	FINAL_OUTPUT_ROUTINE* m_FinalOutputRoutine;
	OUTPUT_ROUTINE* m_OutputRoutine;
	LOCK_ROUTINE* m_LockEnterRoutine;
	LOCK_ROUTINE* m_LockLeaveRoutine;
	void* m_LockContext;
	void* m_OutputContext;
	PERF_DATA_ENTRY m_Data[MaxNumberOfDataEntries];

	// 默认输出函数
	// @param OutputComtext 无效参数
	static void NoOutputRoutine(_In_opt_ void* OutputContext)
	{
		UNREFERENCED_PARAMETER(OutputContext);
	}
	// 默认锁函数
	// @param LockContext 无效参数
	static void NoLockRoutine(_In_opt_ void* LockContext)
	{
		UNREFERENCED_PARAMETER(LockContext);
	}

	// 返回当前位 LOCATION_NAME 的确定索引
	// @param Key 想要得到索引的LOCATION_NAME 
	// @return    搜索得到的索引。
	// 如果在已经存在的Data中未能找到，函数会自动添加搜索的LOCATION到Data中。如果没能找到，并且添加失败。返回 InvalidDataIndex (MAXULONG)
	ULONG GetPerfDataIndex(_In_ const char* Key)
	{
		if (!Key)
			return false;

		for (auto i = 0; i < MaxNumberOfDataEntries; i++)
		{
			if (m_Data[i].Key == Key)	// 这个比较方式 ?
				return i;

			// 如果找到了空节点 - 说明搜索失败。 直接添加进去
			if (m_Data[i].Key == nullptr)
			{
				m_Data[i].Key = Key;
				return i;
			}
		}

		return InvalidDataIndex;
	}

public:
	// 初始化函数 5个函数指针 两个背景文指针
	void Initialize(_In_ OUTPUT_ROUTINE* OutputRoutine, _In_opt_ INITIAL_OUTPUT_ROUTINE* InitialOutputRoutine = NoOutputRoutine, _In_opt_ FINAL_OUTPUT_ROUTINE* FinalOutputRoutine = NoOutputRoutine,
		_In_opt_ LOCK_ROUTINE* LockEnterRoutine = NoLockRoutine, _In_opt_ LOCK_ROUTINE* LockLeaveRoutine = NoLockRoutine, _In_opt_ void* LockContext = nullptr, _In_opt_ void* OutputContext = nullptr)
	{
		m_InitialOutputRoutine = InitialOutputRoutine;
		m_FinalOutputRoutine = FinalOutputRoutine;
		m_OutputRoutine = OutputRoutine;
		m_LockEnterRoutine = LockEnterRoutine;
		m_LockLeaveRoutine = LockLeaveRoutine;
		m_LockContext = LockContext;
		m_OutputContext = OutputContext;
		memset(m_Data, 0, sizeof(m_Data));
	}

	// 销毁器 ：输出记录的行为记录
	void Terminate()
	{
		if (m_Data[0].Key)
			m_InitialOutputRoutine(m_OutputContext);
		
		for (auto i = 0; i < MaxNumberOfDataEntries; i++)
		{
			if (m_Data[i].Key == nullptr)
				break;

			m_OutputRoutine(m_Data[i].Key, m_Data[i].TotalExecutionCount, m_Data[i].TotalElapsedTime, m_OutputContext);
		}

		if (m_Data[0].Key)
			m_FinalOutputRoutine(m_OutputContext);
	}

	// 保存行为数据
	bool AddData(_In_ const char* LocationName, _In_ ULONG64 ElapsedTime)
	{
		SCOPED_LOCK Lock(m_LockEnterRoutine, m_LockLeaveRoutine, m_LockContext);
		const auto DataIndex = GetPerfDataIndex(LocationName);
		if (DataIndex == InvalidDataIndex)
			return false;

		m_Data[DataIndex].TotalElapsedTime += ElapsedTime;
		m_Data[DataIndex].TotalExecutionCount++;

		return true;
	}
};

class PERF_COUNTER
{
public:
	using QUERY_TIME_ROUTINE = ULONG64();

	// 通过QueryTimeRoutine得到当前时间
	// @param Collector 类实例 来存储行为数据
	// @param QueryTimeRoutine 时间查询函数指针
	// @param LocationName 将会被记录的函数名
	// 你必须使用 #HYPERPLATFORM_PERFCOUNTER_MEASURE_TIME() 来创建这个类的实例
	PERF_COUNTER(_In_ PERF_COLLECTOR* Collector, _In_opt_ QUERY_TIME_ROUTINE* QueryTimeRoutine, _In_ const char* LocationName):
	m_Collector(Collector), m_QueryTimeRoutine(QueryTimeRoutine ? QueryTimeRoutine : RdTsc), m_LocationName(LocationName), m_BeforeTime(m_QueryTimeRoutine())
	{
	}

	~PERF_COUNTER()
	{
		if (m_Collector)
		{
			// 运行时间 = 当前时间戳 - 以前时间戳
			const auto ElapsedTime = m_QueryTimeRoutine() - m_BeforeTime;
			m_Collector->AddData(m_LocationName, ElapsedTime);
		}
	}

private:
	// // 返回处理器时间戳
	static ULONG64 RdTsc()
	{
		// 返回处理器时间戳
		return __rdtsc();
	}

	PERF_COLLECTOR* m_Collector;
	QUERY_TIME_ROUTINE* m_QueryTimeRoutine;
	const char* m_LocationName;
	const ULONG64 m_BeforeTime;

};