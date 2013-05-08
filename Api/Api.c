// Api.c : Defines the exported functions for the DLL application.
//

#include "Tcdefs.h"

#include "Api.h"

DLLEXPORT int APIENTRY LoadTrueCryptDriver()
{
	int status = 42; //DriverAttach();
	return status;
}
