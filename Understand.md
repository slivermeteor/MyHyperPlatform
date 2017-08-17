1. LogInitialization Log函数初始化 - 要点 BufferHead BufferTail的切换
2. GlobalVariablesInitialization 架构中无用
3. PerfInitialization 记录函数初始化 (全局函数的初始化)
4. UtilInitialization 物理页面范围(MmGetPhysicalMemoryRanges) EPT页表基地址变量初始化 RtlGetPcToFile 函数初始化
5. PowerCallbackInitialization 注册电源回调
6. HotplugCallbackInitialization 注册热插拔回调
7. VmInitialization VM 开始初始化

#### VmInitialization
----
1. VmIsMyHyperPlatformIsInstalled   
   检查是否已经安装
2. VmIsVmxAvailable  
   检查处理器是否支持 VMX 架构，是否支持 EPT   
3. VmInitializeSharedData  
   初始化共享数据段(根据使用用途改变) I/O bitmap、MSR bitmap  
4. EptInitializeMtrrEntries  
   构造 MTRRs 结构 - 为后面自己构造 EPT 页表的时候做准备。  
5. UtilForEachProcessor - VmStartVm - AsmInitializeVm(寄存器保存， VM 代码) - VmInitializeVm  
6. VmInitializeVm  
    6.1 EptInitialization  
        EPT 页表的构造  
    6.2 申请 PROCESSOR_DATA 相关数据结构 VMCS VMXO  
    6.3 进入 VMX 模式 - 注意 CR0、CR4 要求
    6.4 初始化 VMCS
    6.5 填充 VMCS 区域字段
    6.6 VmLaunchVm - 执行 __vmx_vmlaunch 