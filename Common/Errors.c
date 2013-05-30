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
	handle_win_error();
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

void HandleTcError (int code)
{

	switch (code)
	{
	case ERR_OS_ERROR:
		HandleWin32Error ();
		break;
	case ERR_OUTOFMEMORY:
		set_error_debug_out(TCAPI_E_OUTOFMEMORY);
		break;
	case ERR_PASSWORD_WRONG:
		set_error_debug_out(TCAPI_E_WRONG_PASSWORD);
		break;
	case ERR_DRIVE_NOT_FOUND:
		set_error_debug_out(TCAPI_E_DRIVE_NOT_FOUND);
		break;
	case ERR_FILES_OPEN:
		set_error_debug_out(TCAPI_E_FILES_OPEN);
		break;
	case ERR_FILES_OPEN_LOCK:
		set_error_debug_out(TCAPI_E_FILES_OPEN_LOCK);
		break;
	case ERR_VOL_SIZE_WRONG:
		set_error_debug_out(TCAPI_E_VOL_SIZE_WRONG);
		break;
	case ERR_COMPRESSION_NOT_SUPPORTED:
		set_error_debug_out(TCAPI_E_COMPRESSION_NOT_SUPPORTED);
		break;
	case ERR_PASSWORD_CHANGE_VOL_TYPE:
		set_error_debug_out(TCAPI_E_PASSWD_CHANGE_VOL_TYPE);
		break;
	case ERR_VOL_SEEKING:
		set_error_debug_out(TCAPI_E_VOL_SEEKING);
		break;
	case ERR_CIPHER_INIT_FAILURE:
		set_error_debug_out(TCAPI_E_CIPHER_INIT_FAILURE);
		break;
	case ERR_CIPHER_INIT_WEAK_KEY:
		set_error_debug_out(TCAPI_E_CIPHER_INIT_WEAK_KEY);
		break;
	case ERR_VOL_ALREADY_MOUNTED:
		set_error_debug_out(TCAPI_E_VOL_ALREADY_MOUNTED);
		break;
	case ERR_FILE_OPEN_FAILED:
		set_error_debug_out(TCAPI_E_FILE_OPEN_FAILED);
		break;
	case ERR_VOL_MOUNT_FAILED:
		set_error_debug_out(TCAPI_E_MOUNT_FAILED);
		break;
	case ERR_NO_FREE_DRIVES:
		set_error_debug_out(TCAPI_E_NO_FREE_DRIVES);
		break;
	case ERR_ACCESS_DENIED:
		set_error_debug_out(TCAPI_E_ACCESS_DENIED);
		break;
	case ERR_DRIVER_VERSION:
		set_error_debug_out(TCAPI_E_DRIVER_VERSION);
		break;
	case ERR_NEW_VERSION_REQUIRED:
		set_error_debug_out(TCAPI_E_NEW_VERSION_REQIURED);
		break;
	case ERR_SELF_TESTS_FAILED:
		set_error_debug_out(TCAPI_E_SELF_TEST_FAILED);
		break;
	case ERR_VOL_FORMAT_BAD:
		set_error_debug_out(TCAPI_E_VOL_FORMAT_BAD);
		break;
	case ERR_ENCRYPTION_NOT_COMPLETED:
		set_error_debug_out(TCAPI_E_ENCRYPTION_NOT_COMPLETED);
		break;
	case ERR_NONSYS_INPLACE_ENC_INCOMPLETE:
		set_error_debug_out(TCAPI_E_NONSYS_INPLACE_ENCRYPTION_INCOMPLETE);
		break;
	case ERR_SYS_HIDVOL_HEAD_REENC_MODE_WRONG:
		set_error_debug_out(TCAPI_E_SYS_HID_VOL_REENC_MODE_WRONG);
		break;
	case ERR_PARAMETER_INCORRECT:
		set_error_debug_out(TCAPI_E_PARAM_INCORRECT);
		break;
	case ERR_USER_ABORT:
		set_error_debug_out(TCAPI_W_USER_ABORT);
		break;
	case ERR_DONT_REPORT:
		// A non-error
		break;
	default:
		SetLastError(MAKE_TCAPI_ERROR(code));
		debug_out("UNKNOWN TRUECRYPT ERROR", MAKE_TCAPI_ERROR(code));
	}
}
