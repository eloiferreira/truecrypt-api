/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */
#include <windows.h>
#include "OsInfo.h"
#include "Errors.h"
#include "Apidrvr.h"

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
		return TCAPI_E_UNKNOWN_OS;	/* Original TrueCrypt code does nCurrentOS = WIN_UNKNOWN; here and goes on 
									with that. This allows it to work in newly released OSes without modification, 
									albeit probably in reduced functionality mode. We for now will return error 
									from here and wait and see if this strategy is of any good. */

									/* TODO: Should get back to this when it's clear what we do have to know 
											 about OS in order to work. */

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

BOOL IsOSAtLeast (OSVersionEnum reqMinOS)
{
	return IsOSVersionAtLeast (reqMinOS, 0);
}

// Returns TRUE if the operating system is at least reqMinOS and service pack at least reqMinServicePack.
// Example 1: IsOSVersionAtLeast (WIN_VISTA, 1) called under Windows 2008, returns TRUE.
// Example 2: IsOSVersionAtLeast (WIN_XP, 3) called under Windows XP SP1, returns FALSE.
// Example 3: IsOSVersionAtLeast (WIN_XP, 3) called under Windows Vista SP1, returns TRUE.
BOOL IsOSVersionAtLeast (OSVersionEnum reqMinOS, int reqMinServicePack)
{
	/* When updating this function, update IsOSAtLeast() in Ntdriver.c too. */

	int major = 0, minor = 0;

	switch (reqMinOS)
	{
		case WIN_2000:			major = 5; minor = 0; break;
		case WIN_XP:			major = 5; minor = 1; break;
		case WIN_SERVER_2003:	major = 5; minor = 2; break;
		case WIN_VISTA:			major = 6; minor = 0; break;
		case WIN_7:				major = 6; minor = 1; break;
		case WIN_8:				major = 6; minor = 2; break;

		default:				return FALSE;
	}

	return ((CurrentOSMajor << 16 | CurrentOSMinor << 8 | CurrentOSServicePack)
		>= (major << 16 | minor << 8 | reqMinServicePack));
}

BOOL ReadLocalMachineRegistryDword (char *subKey, char *name, DWORD *value)
{
	HKEY hkey = 0;
	DWORD size = sizeof (*value);
	DWORD type;

	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hkey) != ERROR_SUCCESS)
		return FALSE;

	if (RegQueryValueEx (hkey, name, NULL, &type, (BYTE *) value, &size) != ERROR_SUCCESS)
	{
		RegCloseKey (hkey);
		return FALSE;
	}

	RegCloseKey (hkey);
	return type == REG_DWORD;
}

uint32 ReadEncryptionThreadPoolFreeCpuCountLimit ()
{
	DWORD count;

	if (!ReadLocalMachineRegistryDword ("SYSTEM\\CurrentControlSet\\Services\\truecrypt", TC_ENCRYPTION_FREE_CPU_COUNT_REG_VALUE_NAME, &count))
		count = 0;

	return count;
}
