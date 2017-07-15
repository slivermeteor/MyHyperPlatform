#pragma once

#include <fltKernel.h>

/// Represents VMM related data shared across all processors
struct SHARED_PROCESSOR_DATA 
{
	volatile long ReferenceCount;  //!< Number of processors sharing this data
	void* MsrBitmap;               //!< Bitmap to activate MSR I/O VM-exit
	void* IoBitmapA;              //!< Bitmap to activate IO VM-exit (~ 0x7FFF)
	void* IoBitmapB;              //!< Bitmap to activate IO VM-exit (~ 0xffff)
};

struct PROCESSOR_DATA
{
	SHARED_PROCESSOR_DATA* SharedData;
	void* VmmStackLimit;
	struct VM_CONTROL_STRUCTURE* VmxonRegion;
	struct VM_CONTROL_STRUCTURE* VmcsRegion;
	struct EPT_DATA* EptData;
};