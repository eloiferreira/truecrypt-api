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
#include <io.h>
#include "Registry.h"
#include "Uac.h"

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

BOOL GetDriveGeometry (const char *deviceName, PDISK_GEOMETRY diskGeometry)
{
	BOOL bResult;
	DWORD dwResult;
	DISK_GEOMETRY_STRUCT dg;

	memset (&dg, 0, sizeof(dg));
	wsprintfW ((PWSTR) &dg.deviceName, L"%hs", deviceName);

	bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_DRIVE_GEOMETRY, &dg,
		sizeof (dg), &dg, sizeof (dg), &dwResult, NULL);

	memcpy (diskGeometry, &dg.diskGeometry, sizeof (DISK_GEOMETRY));
	return bResult;
}

BYTE *MapResource (char *resourceType, int resourceId, PDWORD size)
{
	HGLOBAL hResL; 
	HRSRC hRes;

	hRes = FindResource (NULL, MAKEINTRESOURCE(resourceId), resourceType);
	hResL = LoadResource (NULL, hRes);

	if (size != NULL)
		*size = SizeofResource (NULL, hRes);

	return (BYTE *) LockResource (hResL);
}

// Returns TRUE if the file or directory exists (both may be enclosed in quotation marks).
BOOL FileExists (const char *filePathPtr)
{
	char filePath [TC_MAX_PATH];

	// Strip quotation marks (if any)
	if (filePathPtr [0] == '"')
	{
		strcpy (filePath, filePathPtr + 1);
	}
	else
	{
		strcpy (filePath, filePathPtr);
	}

	// Strip quotation marks (if any)
	if (filePath [strlen (filePath) - 1] == '"')
		filePath [strlen (filePath) - 1] = 0;

	return (_access (filePath, 0) != -1);
}

std::string GetServiceConfigPath (const char *fileName)
{
	char sysPath[TC_MAX_PATH];

	if (Is64BitOs())
	{
		typedef UINT (WINAPI *GetSystemWow64Directory_t) (LPTSTR lpBuffer, UINT uSize);

		GetSystemWow64Directory_t getSystemWow64Directory = (GetSystemWow64Directory_t) GetProcAddress (GetModuleHandle ("kernel32"), "GetSystemWow64DirectoryA");
		getSystemWow64Directory (sysPath, sizeof (sysPath));
	}
	else
		GetSystemDirectory (sysPath, sizeof (sysPath));

	return std::string (sysPath) + "\\" + fileName;
}

BOOL IsPagingFileWildcardActive ()
{
	char pagingFiles[65536];
	DWORD size = sizeof (pagingFiles);
	char *mmKey = "System\\CurrentControlSet\\Control\\Session Manager\\Memory Management";

	if (!ReadLocalMachineRegistryString (mmKey, "PagingFiles", pagingFiles, &size))
	{
		size = sizeof (pagingFiles);
		if (!ReadLocalMachineRegistryMultiString (mmKey, "PagingFiles", pagingFiles, &size))
			size = 0;
	}

	return size > 0 && strstr (pagingFiles, "?:\\") == pagingFiles;
}

BOOL IsPagingFileActive (BOOL checkNonWindowsPartitionsOnly)
{
	// GlobalMemoryStatusEx() cannot be used to determine if a paging file is active

	char data[65536];
	DWORD size = sizeof (data);

	if (IsPagingFileWildcardActive())
		return TRUE;

	if (ReadLocalMachineRegistryMultiString ("System\\CurrentControlSet\\Control\\Session Manager\\Memory Management", "PagingFiles", data, &size)
		&& size > 12 && !checkNonWindowsPartitionsOnly)
		return TRUE;

	if (!IsAdmin())
		return FALSE;
	//TODO: error handling
		//AbortProcess ("UAC_INIT_ERROR");

	for (char drive = 'C'; drive <= 'Z'; ++drive)
	{
		// Query geometry of the drive first to prevent "no medium" pop-ups
		std::string drivePath = "\\\\.\\X:";
		drivePath[4] = drive;

		if (checkNonWindowsPartitionsOnly)
		{
			char sysDir[MAX_PATH];
			if (GetSystemDirectory (sysDir, sizeof (sysDir)) != 0 && toupper (sysDir[0]) == drive)
				continue;
		}

		HANDLE handle = CreateFile (drivePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (handle == INVALID_HANDLE_VALUE)
			continue;

		DISK_GEOMETRY driveInfo;
		DWORD dwResult;

		if (!DeviceIoControl (handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &driveInfo, sizeof (driveInfo), &dwResult, NULL))
		{
			CloseHandle (handle);
			continue;
		}

		CloseHandle (handle);

		// Test if a paging file exists and is locked by another process
		std::string path = "X:\\pagefile.sys";
		path[0] = drive;

		handle = CreateFile (path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

		if (handle != INVALID_HANDLE_VALUE)
			CloseHandle (handle);
		else if (GetLastError() == ERROR_SHARING_VIOLATION)
			return TRUE;
	}

	return FALSE;
}

BOOL RestartComputer (void)
{
	TOKEN_PRIVILEGES tokenPrivil; 
	HANDLE hTkn; 

	if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES, &hTkn))
	{
		return false; 
	}

	LookupPrivilegeValue (NULL, SE_SHUTDOWN_NAME, &tokenPrivil.Privileges[0].Luid); 
	tokenPrivil.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
	tokenPrivil.PrivilegeCount = 1;    

	AdjustTokenPrivileges (hTkn, false, &tokenPrivil, 0, (PTOKEN_PRIVILEGES) NULL, 0); 
	if (GetLastError() != ERROR_SUCCESS) 
		return false; 

	if (!ExitWindowsEx (EWX_REBOOT,
		SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_FLAG_PLANNED)) 
		return false; 

	return true;
}
