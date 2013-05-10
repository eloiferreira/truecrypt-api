/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#include <Shlobj.h>

#include "Uac.h"
#include "OsInfo.h"

BOOL UacElevated = FALSE;

BOOL IsAdmin() {
	return IsUserAnAdmin();
}

BOOL IsUacSupported ()
{
	HKEY hkey;
	DWORD value = 1, size = sizeof (DWORD);

	if (!IsOSAtLeast (WIN_VISTA))
		return FALSE;

	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_READ, &hkey) == ERROR_SUCCESS)
	{
		if (RegQueryValueEx (hkey, "EnableLUA", 0, 0, (LPBYTE) &value, &size) != ERROR_SUCCESS)
			value = 1;

		RegCloseKey (hkey);
	}

	return value != 0;
}
