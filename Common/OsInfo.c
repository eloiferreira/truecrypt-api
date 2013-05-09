/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */
#include <windows.h>
#include "OsInfo.h"
#include "Errors.h"

OSVersionEnum nCurrentOS = WIN_UNKNOWN;
int CurrentOSMajor = 0;
int CurrentOSMinor = 0;
int CurrentOSServicePack = 0;
BOOL IsServerOS = FALSE;

DWORD InitOSVersionInfo ()
{
	OSVERSIONINFO os;
	OSVERSIONINFOEX osEx;
	DWORD result = TCAPI_S_SUCCESS;

	os.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);

	if (GetVersionEx (&os) == FALSE)
		return TCAPI_E_CANT_GET_OS_VER;

	CurrentOSMajor = os.dwMajorVersion;
	CurrentOSMinor = os.dwMinorVersion;

	if (CurrentOSMajor < 5)
		return TCAPI_E_UNSUPPORTED_OS;

	if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 5 && CurrentOSMinor == 0)
		nCurrentOS = WIN_2000;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 5 && CurrentOSMinor == 1)
		nCurrentOS = WIN_XP;

	/* At this point we would like more details */

	osEx.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEX);

	if (GetVersionEx ((LPOSVERSIONINFOA) &osEx) == FALSE)
		return TCAPI_E_CANT_GET_OS_VER;
	
	IsServerOS = (osEx.wProductType == VER_NT_SERVER || osEx.wProductType == VER_NT_DOMAIN_CONTROLLER);
	
	if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 5 && CurrentOSMinor == 2)
		nCurrentOS = IsServerOS ? WIN_SERVER_2003 : WIN_XP64;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 6 && CurrentOSMinor == 0)
		nCurrentOS = IsServerOS ? WIN_SERVER_2008 : WIN_VISTA;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 6 && CurrentOSMinor == 1)
		nCurrentOS = IsServerOS ? WIN_SERVER_2008_R2 : WIN_7;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 6 && CurrentOSMinor == 2)
		nCurrentOS = IsServerOS ? WIN_SERVER_2012 : WIN_8;
	else
		nCurrentOS = WIN_UNKNOWN;

	// Service pack check & warnings about critical MS issues
	CurrentOSServicePack = osEx.wServicePackMajor;
	switch (nCurrentOS)
	{
		case WIN_2000:
			if (osEx.wServicePackMajor < 3)
				result = TCAPI_W_LARGE_IDE_2K;
			else
			{
				DWORD val = 0, size = sizeof(val);
				HKEY hkey;

				if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Atapi\\Parameters", 0, KEY_READ, &hkey) == ERROR_SUCCESS)
				{
					if (RegQueryValueEx (hkey, "EnableBigLba", 0, 0, (LPBYTE) &val, &size) != ERROR_SUCCESS || val != 1)
					{
						result = TCAPI_W_LARGE_IDE_2K_REGISTRY;
					}
					RegCloseKey (hkey);
				}
			}
			break;
		case WIN_XP:
			if (osEx.wServicePackMajor < 1)
			{
				HKEY k;
				// PE environment does not report version of SP
				if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\minint", 0, KEY_READ, &k) != ERROR_SUCCESS)
					result = TCAPI_W_LARGE_IDE_XP;
				else
					RegCloseKey (k);
			}
			break;
	}
	return result;
}