/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#include <windows.h>
#include "Options.h"
#include "Errors.h"

BOOL bPreserveTimestamp = TRUE;
BOOL bCacheInDriver = FALSE;
BOOL bMountReadOnly = FALSE;
BOOL bMountRemovable = FALSE;

/* NN: Path to TrueCrypt driver. If NULL, denotes use of installed driver, otherwise the one at path. 
Since we load the specified driver only and do not attempt to discover other options, the value of this 
variable defines whether we are working in portable or installed mode. */

char *lpszDriverPath = NULL;

/* This value may changed only by calling ChangeSystemEncryptionStatus(). Only the wizard can change it
(others may still read it though). */
int SystemEncryptionStatus = SYSENC_STATUS_NONE;	

/* Only the wizard can change this value (others may only read it). */
WipeAlgorithmId nWipeMode = TC_WIPE_NONE;

//TODO: Doc -> options should be freed by caller.
BOOL ApplyOptions(PTCAPI_OPTIONS options) {
	int i;
	DWORD pathSize = 0;
	PTCAPI_OPTION option = NULL;

	for (i = 0; i < (int) options->NumberOfOptions; i++) {
		
		option = &options->Options[i];

		switch (option->OptionId) {
		case TC_OPTION_CACHE_PASSWORDS: 
			bCacheInDriver = option->OptionValue;
			break;
		case TC_OPTION_MOUNT_READONLY:
			bMountReadOnly = option->OptionValue;
			break;
		case TC_OPTION_MOUNT_REMOVABLE:
			bMountRemovable = option->OptionValue;
			break;
		case TC_OPTION_PRESERVE_TIMESTAMPS:
			bPreserveTimestamp = option->OptionValue;
			break;
		case TC_OPTION_DRIVER_PATH:
			pathSize = (MAX_PATH + 1);
			lpszDriverPath = malloc(pathSize);
			memset(lpszDriverPath, 0, (pathSize));
			strcpy_s(lpszDriverPath, strlen((const char *)option->OptionValue), (const char *) (option->OptionValue));
			break;
		default:
			SetLastError(TCAPI_E_WRONG_OPTION);
			return FALSE;
		}
	}
	return TRUE;
}

char *GetModPath (char *path, int maxSize)
{
	//GetModuleFileName (NULL, path, maxSize);
	strrchr (_pgmptr, '\\')[1] = 0;
	return path;
}

char *GetConfigPath (char *fileName)
{
	static char path[MAX_PATH * 2] = { 0 };

	if (IsNonInstallMode ())
	{
		GetModPath (path, sizeof (path));
		strcat (path, fileName);

		return path;
	}

	if (SUCCEEDED(SHGetFolderPath (NULL, CSIDL_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, path)))
	{
		strcat (path, "\\TrueCrypt\\");
		CreateDirectory (path, NULL);
		strcat (path, fileName);
	}
	else
		path[0] = 0;

	return path;
}

// Returns NULL if there's any error. Although the buffer can contain binary data, it is always null-terminated.
char *LoadFile (const char *fileName, DWORD *size)
{
	char *buf;
	HANDLE h = CreateFile (fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return NULL;

	*size = GetFileSize (h, NULL);
	buf = (char *) malloc (*size + 1);

	if (buf == NULL)
	{
		CloseHandle (h);
		return NULL;
	}

	ZeroMemory (buf, *size + 1);

	if (!ReadFile (h, buf, *size, size, NULL))
	{
		free (buf);
		buf = NULL;
	}

	CloseHandle (h);
	return buf;
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

BOOL LoadSysEncSettings (void)
{
	DWORD size = 0;
	char *sysEncCfgFileBuf = LoadFile (GetConfigPath (TC_APPD_FILENAME_SYSTEM_ENCRYPTION), &size);
	char *xml = sysEncCfgFileBuf;
	char paramName[100], paramVal[MAX_PATH];

	// Defaults
	int newSystemEncryptionStatus = SYSENC_STATUS_NONE;
	WipeAlgorithmId newnWipeMode = TC_WIPE_NONE;

	if (!FileExists (GetConfigPath (TC_APPD_FILENAME_SYSTEM_ENCRYPTION)))
	{
		SystemEncryptionStatus = newSystemEncryptionStatus;
		nWipeMode = newnWipeMode;
	}

	if (xml == NULL)
	{
		return FALSE;
	}

	while (xml = XmlFindElement (xml, "config"))
	{
		XmlGetAttributeText (xml, "key", paramName, sizeof (paramName));
		XmlGetNodeText (xml, paramVal, sizeof (paramVal));

		if (strcmp (paramName, "SystemEncryptionStatus") == 0)
		{
			newSystemEncryptionStatus = atoi (paramVal);
		}
		else if (strcmp (paramName, "WipeMode") == 0)
		{
			newnWipeMode = (WipeAlgorithmId) atoi (paramVal);
		}

		xml++;
	}

	SystemEncryptionStatus = newSystemEncryptionStatus;
	nWipeMode = newnWipeMode;

	free (sysEncCfgFileBuf);
	return TRUE;
}
