// Api.c : Defines the exported functions for the DLL application.
//

#include "Tcdefs.h"

#include "Api.h"
#include "Errors.h"

BOOL bTcApiInitialized = FALSE;

#define TCAPI_CHECK_INITIALIZED(...) do { if (!bTcApiInitialized) { SetLastError(TCAPI_E_NOT_INITIALIZED); return __VA_ARGS__; } } while (0)

DLLEXPORT BOOL APIENTRY Initialize() {

	bTcApiInitialized = TRUE;
	return bTcApiInitialized;
}

DLLEXPORT int APIENTRY LoadTrueCryptDriver()
{
	int status = 0;
	
	TCAPI_CHECK_INITIALIZED(0);
	
	status = 42; //DriverAttach();
	return status;
}
