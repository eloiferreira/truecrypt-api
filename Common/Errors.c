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

#define MAX_FMT_STRING 1024

void handleWin32Error ()
{
	DWORD dwError = GetLastError ();

	// Access denied
	if (dwError == ERROR_ACCESS_DENIED && !IsAdmin ())
	{
		SetLastError(TCAPI_E_ACCESS_DENIED);
		return;
	}

	// Api-friendly hardware error explanation
	if (IsDiskError (dwError)) {
		SetLastError(MAKE_DISK_ERROR(dwError));
		return;
	}

	// Device not ready
	if (dwError == ERROR_NOT_READY) {
		SetLastError(HandleDriveNotReadyError(dwError));
		return;
	}

	SetLastError(MAKE_WINDOWS_ERROR(dwError));
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

void DebugOut(const char *src, const char *msg, DWORD err_no)
{
	const char *fmt = "%s: %s (0x%X)\n";
	size_t needed = _snprintf(NULL, 0, fmt, src, msg, err_no);
	char *buffer = NULL;

	if (needed >= MAX_FMT_STRING) 
	{
		//TODO: need more informative output
		OutputDebugString("Error string is too long");
		return;
	}
	
	buffer = malloc(needed + 1);
	_snprintf(buffer, needed, fmt, src, msg, err_no);
	buffer[needed] = 0;
	OutputDebugString(buffer);
	free(buffer);
}

int Error (const char *stringId)
{
	//TODO: implementation
	return 0;
}

int ErrorDirect (const wchar_t *errMsg)
{
	//TODO: implementation
	return 0;
}

