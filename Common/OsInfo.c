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
BOOL RemoteSession = FALSE;

BOOL InitOSVersionInfo ()
{
	OSVERSIONINFO os;
	OSVERSIONINFOEX osEx;

	os.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);

	if (GetVersionEx (&os) == FALSE) {
		debug_out("TCAPI_E_CANT_GET_OS_VER", TCAPI_E_CANT_GET_OS_VER);
		SetLastError(TCAPI_E_CANT_GET_OS_VER);
		return FALSE;
	}

	CurrentOSMajor = os.dwMajorVersion;
	CurrentOSMinor = os.dwMinorVersion;

	if (CurrentOSMajor < 5) {
		debug_out("TCAPI_E_UNSUPPORTED_OS", TCAPI_E_UNSUPPORTED_OS);
		SetLastError(TCAPI_E_UNSUPPORTED_OS);
		return FALSE;
	}

	if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 5 && CurrentOSMinor == 0)
		nCurrentOS = WIN_2000;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 5 && CurrentOSMinor == 1)
		nCurrentOS = WIN_XP;

	/* At this point we would like more details */

	osEx.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEX);

	if (GetVersionEx ((LPOSVERSIONINFOA) &osEx) == FALSE) {
		debug_out("TCAPI_E_CANT_GET_OS_VER", TCAPI_E_CANT_GET_OS_VER);
		SetLastError(TCAPI_E_CANT_GET_OS_VER);
		return FALSE;
	}
	
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

	RemoteSession = GetSystemMetrics (SM_REMOTESESSION) != 0;

	// Service pack check & warnings about critical MS issues
	CurrentOSServicePack = osEx.wServicePackMajor;
	switch (nCurrentOS)
	{
		case WIN_2000:
			if (osEx.wServicePackMajor < 3) {
				debug_out("TCAPI_W_LARGE_IDE_2K", TCAPI_W_LARGE_IDE_2K);
				SetLastError(TCAPI_W_LARGE_IDE_2K);
				//TODO: Doc -> check GetLastError() anyway
				return TRUE;
			}
			else
			{
				DWORD val = 0, size = sizeof(val);
				HKEY hkey;

				if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Atapi\\Parameters", 0, KEY_READ, &hkey) == ERROR_SUCCESS)
				{
					if (RegQueryValueEx (hkey, "EnableBigLba", 0, 0, (LPBYTE) &val, &size) != ERROR_SUCCESS || val != 1)
					{
						RegCloseKey (hkey);

						debug_out("TCAPI_W_LARGE_IDE_2K_REGISTRY", TCAPI_W_LARGE_IDE_2K_REGISTRY);
						SetLastError(TCAPI_W_LARGE_IDE_2K_REGISTRY);
						//TODO: Doc -> check GetLastError() anyway
						return TRUE;
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
				{
					debug_out("TCAPI_W_LARGE_IDE_XP", TCAPI_W_LARGE_IDE_XP);
					SetLastError(TCAPI_W_LARGE_IDE_XP);
					//TODO: Doc -> check GetLastError() anyway
					return TRUE;
				}
				else
					RegCloseKey (k);
			}
			break;
	}

	return TRUE;
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

BOOL Is64BitOs ()
{
	static BOOL isWow64 = FALSE;
	static BOOL valid = FALSE;
	typedef BOOL (__stdcall *LPFN_ISWOW64PROCESS ) (HANDLE hProcess,PBOOL Wow64Process);
	LPFN_ISWOW64PROCESS fnIsWow64Process;

	if (valid)
		return isWow64;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress (GetModuleHandle("kernel32"), "IsWow64Process");

	if (fnIsWow64Process != NULL)
		if (!fnIsWow64Process (GetCurrentProcess(), &isWow64))
			isWow64 = FALSE;

	valid = TRUE;
	return isWow64;
}

BOOL ResolveSymbolicLink (const wchar_t *symLinkName, PWSTR targetName)
{
	BOOL bResult;
	DWORD dwResult;
	RESOLVE_SYMLINK_STRUCT resolve;

	memset (&resolve, 0, sizeof(resolve));
	wcscpy ((PWSTR) &resolve.symLinkName, symLinkName);

	bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_RESOLVED_SYMLINK, &resolve,
		sizeof (resolve), &resolve, sizeof (resolve), &dwResult,
		NULL);

	wcscpy (targetName, (PWSTR) &resolve.targetName);

	return bResult;
}

// Returns drive letter number assigned to device (-1 if none)
int GetDiskDeviceDriveLetter (PWSTR deviceName)
{
	int i;
	WCHAR link[MAX_PATH];
	WCHAR target[MAX_PATH];
	WCHAR device[MAX_PATH];

	if (!ResolveSymbolicLink (deviceName, device))
		wcscpy (device, deviceName);

	for (i = 0; i < 26; i++)
	{
		WCHAR drive[] = { (WCHAR) i + 'A', ':', 0 };

		wcscpy (link, L"\\DosDevices\\");
		wcscat (link, drive);

		ResolveSymbolicLink (link, target);

		if (wcscmp (device, target) == 0)
			return i;
	}

	return -1;
}