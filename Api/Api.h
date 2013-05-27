// Instead of using conditional __declspec(dllexport)/dllimport way of defining exports
// we define those unconditionally. This library is supposed to be used with 
// LoadLibrary/GetProcAddress way, so no importing required.

#ifndef API_H
#define API_H

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <winver.h>

#include "Options.h"
#include "Password.h"

#define DLLEXPORT __declspec(dllexport)

#ifdef __cplusplus
extern "C" {
#endif

	extern BOOL bTcApiInitialized;

	DLLEXPORT BOOL APIENTRY Initialize(PTCAPI_OPTIONS options);
	DLLEXPORT BOOL APIENTRY Shutdown(void);
	DLLEXPORT int APIENTRY LoadTrueCryptDriver(void);
	DLLEXPORT BOOL APIENTRY UnloadTrueCryptDriver(void);
	DLLEXPORT BOOL APIENTRY MountV(int nDosDriveNo, char *szFileName, Password VolumePassword);

#ifdef __cplusplus
}
#endif

#endif