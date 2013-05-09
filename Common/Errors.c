/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#include "Tcdefs.h"

#include "OsInfo.h"
#include "Errors.h"
#include "Uac.h"

DWORD handleWin32Error ()
{
	DWORD dwError = GetLastError ();

	// Access denied
	if (dwError == ERROR_ACCESS_DENIED && !IsAdmin ())
	{
		SetLastError (dwError);			// Preserve the original error code after IsAdmin
		return TCAPI_E_ACCESS_DENIED;
	}

	// Api-friendly hardware error explanation
	if (IsDiskError (dwError))
		return MAKE_DISK_ERROR(dwError);

	// Device not ready
	if (dwError == ERROR_NOT_READY) {
		DWORD res = HandleDriveNotReadyError(dwError);
		SetLastError (dwError);				// Preserve the original error code
		return res;
	}

	return MAKE_WINDOWS_ERROR(dwError);
}

BOOL IsDiskError (DWORD error)
{
	return IsDiskReadError (error) || IsDiskWriteError (error);
}

BOOL IsDiskReadError (DWORD error)
{
	return (error == ERROR_CRC
		|| error == ERROR_IO_DEVICE
		|| error == ERROR_BAD_CLUSTERS
		|| error == ERROR_SECTOR_NOT_FOUND
		|| error == ERROR_READ_FAULT
		|| error == ERROR_INVALID_FUNCTION // I/O error may be reported as ERROR_INVALID_FUNCTION by buggy chipset drivers
		|| error == ERROR_SEM_TIMEOUT);	// I/O operation timeout may be reported as ERROR_SEM_TIMEOUT
}


BOOL IsDiskWriteError (DWORD error)
{
	return (error == ERROR_IO_DEVICE
		|| error == ERROR_BAD_CLUSTERS
		|| error == ERROR_SECTOR_NOT_FOUND
		|| error == ERROR_WRITE_FAULT
		|| error == ERROR_INVALID_FUNCTION // I/O error may be reported as ERROR_INVALID_FUNCTION by buggy chipset drivers
		|| error == ERROR_SEM_TIMEOUT);	// I/O operation timeout may be reported as ERROR_SEM_TIMEOUT
}

DWORD HandleDriveNotReadyError (DWORD reportedError)
{
	HKEY hkey = 0;
	DWORD value = 0, size = sizeof (DWORD);
	DWORD result = reportedError;

	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\MountMgr",
		0, KEY_READ, &hkey) != ERROR_SUCCESS)
		return MAKE_WINDOWS_ERROR(result);

	if (RegQueryValueEx (hkey, "NoAutoMount", 0, 0, (LPBYTE) &value, &size) == ERROR_SUCCESS 
		&& value != 0)
	{
		result = TCAPI_W_AUTOMOUNT_DISABLED;
	}
	else if (nCurrentOS == WIN_VISTA && CurrentOSServicePack < 1)
		result = TCAPI_W_ASSIGN_DRIVE_LETTER;
	else
		result = TCAPI_W_DEVICE_NOT_READY;

	RegCloseKey (hkey);
	return result;
}
