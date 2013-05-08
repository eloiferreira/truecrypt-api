/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2012 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */
#include "Tcdefs.h"

#include <windowsx.h>
#include <winerror.h>
#include "Errors.h"


DWORD handleWin32Error (HWND hwndDlg)
{
	PWSTR lpMsgBuf;
	DWORD dwError = GetLastError ();

	// Device not ready
	if (dwError == ERROR_NOT_READY)
		HandleDriveNotReadyError();

	SetLastError (dwError);		// Preserve the original error code

	return dwError;
}

void HandleDriveNotReadyError ()
{
	HKEY hkey = 0;
	DWORD value = 0, size = sizeof (DWORD);

	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\MountMgr",
		0, KEY_READ, &hkey) != ERROR_SUCCESS)
		return;

	if (RegQueryValueEx (hkey, "NoAutoMount", 0, 0, (LPBYTE) &value, &size) == ERROR_SUCCESS 
		&& value != 0)
	{
		Warning ("SYS_AUTOMOUNT_DISABLED");
	}
	else if (nCurrentOS == WIN_VISTA && CurrentOSServicePack < 1)
		Warning ("SYS_ASSIGN_DRIVE_LETTER");
	else
		Warning ("DEVICE_NOT_READY_ERROR");

	RegCloseKey (hkey);
}
