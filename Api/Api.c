// Api.c : Defines the exported functions for the DLL application.
//

#include "Api.h"
#include "Errors.h"
#include "OsInfo.h"
#include "EncryptionThreadPool.h"
#include "Apidrvr.h"

BOOL bTcApiInitialized = FALSE;

#define TCAPI_CHECK_INITIALIZED(RESULT) do { if (!bTcApiInitialized) { SetLastError(TCAPI_E_NOT_INITIALIZED); return RESULT; } } while (0)

DLLEXPORT BOOL APIENTRY Initialize(PTCAPI_OPTIONS options) {

	if (!options || !ApplyOptions(options)) {
		//TODO: Doc -> See GetLastError()
		return FALSE;
	}

	if (!EncryptionThreadPoolStart (ReadEncryptionThreadPoolFreeCpuCountLimit()))
	{
		//TODO: Doc -> See GetLastError()
		SetLastError(TCAPI_E_CANT_START_ENCPOOL);
		return FALSE;
	}

	bTcApiInitialized = TRUE;
	return bTcApiInitialized;
}

DLLEXPORT BOOL APIENTRY Shutdown() {

	//returns FALSE if not initialized
	TCAPI_CHECK_INITIALIZED(0);

	EncryptionThreadPoolStop();
	return TRUE;
}

DLLEXPORT BOOL APIENTRY LoadTrueCryptDriver()
{
	int status = FALSE;
	
	TCAPI_CHECK_INITIALIZED(0);
	
	status = DriverAttach ();
	if (status == FALSE)
	{
		//TODO: Doc -> See GetLastError()
	}

	return status;
}
