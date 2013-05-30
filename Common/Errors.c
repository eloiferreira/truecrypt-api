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

void HandleWin32Error ()
{
	DWORD dwError = GetLastError ();

	// Access denied
	if (dwError == ERROR_ACCESS_DENIED && !IsAdmin ())
	{
		set_error_debug_out(TCAPI_E_ACCESS_DENIED);
		return;
	}

	if (IsDiskError (dwError)) {
		debug_out("Disk error:", dwError);
		return;
	}

	// Device not ready
	if (dwError == ERROR_NOT_READY) {
		// more details in debug output
		HandleDriveNotReadyError(dwError);
		debug_out("Disk not ready:", dwError);
		return;
	}
	handle_win_error;
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

void HandleDriveNotReadyError (DWORD reportedError)
{
	HKEY hkey = 0;
	DWORD value = 0, size = sizeof (DWORD);

	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\MountMgr",
		0, KEY_READ, &hkey) != ERROR_SUCCESS) 
	{
		debug_out("Cant get more info:", GetLastError());
		return;
	}

	if (RegQueryValueEx (hkey, "NoAutoMount", 0, 0, (LPBYTE) &value, &size) == ERROR_SUCCESS 
		&& value != 0)
	{
		debug_out("TCAPI_W_AUTOMOUNT_DISABLED", TCAPI_W_AUTOMOUNT_DISABLED);
	}
	else if (nCurrentOS == WIN_VISTA && CurrentOSServicePack < 1)
		debug_out("TCAPI_W_ASSIGN_DRIVE_LETTER", TCAPI_W_ASSIGN_DRIVE_LETTER);
	else
		debug_out("TCAPI_W_DEVICE_NOT_READY", TCAPI_W_DEVICE_NOT_READY);

	RegCloseKey (hkey);

	// preserve original error
	SetLastError(reportedError);
	return;
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

void HandlePasswordError(void)
{
	//WCHAR szTmp[8192];

	//swprintf (szTmp, (KeyFilesEnable ? "PASSWORD_OR_KEYFILE_WRONG" : "PASSWORD_WRONG");
	//if (CheckCapsLock (hwndDlg, TRUE))
	//	wcscat (szTmp, "PASSWORD_WRONG_CAPSLOCK_ON");

	//if (TCBootLoaderOnInactiveSysEncDrive ())
	//{
	//	swprintf (szTmp, GetString (KeyFilesEnable ? "PASSWORD_OR_KEYFILE_OR_MODE_WRONG" : "PASSWORD_OR_MODE_WRONG"));

	//	if (CheckCapsLock (hwndDlg, TRUE))
	//		wcscat (szTmp, GetString ("PASSWORD_WRONG_CAPSLOCK_ON"));

	//	wcscat (szTmp, GetString ("SYSENC_MOUNT_WITHOUT_PBA_NOTE"));
	//}

	//wstring msg = szTmp;

	//if (KeyFilesEnable && HiddenFilesPresentInKeyfilePath)
	//{
	//	msg += GetString ("HIDDEN_FILES_PRESENT_IN_KEYFILE_PATH");
	//	HiddenFilesPresentInKeyfilePath = FALSE;
	//}

	return;
}
