#ifndef MYHYPERPLATFORM_LOG_H
#define MYHYPERPLATFORM_LOG_H

extern "C"
{
#include <fltKernel.h>

#define  MYHYPERPLATFORM_LOG_PRINT (Message) \
	DbgPrint("%s", Message);	



}



#endif