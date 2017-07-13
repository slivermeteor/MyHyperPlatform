#pragma once

#include <fltKernel.h>

/// Represents VMM related data shared across all processors
struct SHARED_PROCESSOR_DATA 
{
	volatile long reference_count;  //!< Number of processors sharing this data
	void* msr_bitmap;               //!< Bitmap to activate MSR I/O VM-exit
	void* io_bitmap_a;              //!< Bitmap to activate IO VM-exit (~ 0x7FFF)
	void* io_bitmap_b;              //!< Bitmap to activate IO VM-exit (~ 0xffff)
};