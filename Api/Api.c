// Api.c : Defines the exported functions for the DLL application.
//

#include "Tcdefs.h"

#include "Api.h"
#include "Errors.h"
#include "Options.h"

BOOL bTcApiInitialized = FALSE;

#define TCAPI_CHECK_INITIALIZED(RESULT) do { if (!bTcApiInitialized) { SetLastError(TCAPI_E_NOT_INITIALIZED); return RESULT; } } while (0)

DLLEXPORT BOOL APIENTRY Initialize(PTCAPI_OPTIONS options) {

	if (!options || !ApplyOptions(options)) {
		//TODO: Doc -> See GetLastError()
		return FALSE;
	}

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
