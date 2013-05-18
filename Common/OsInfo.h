/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#ifndef OSINFO_H
#define OSINFO_H

#include "Tcdefs.h"

#define MIN_MOUNTED_VOLUME_DRIVE_NUMBER ('A' - 'A')
#define MAX_MOUNTED_VOLUME_DRIVE_NUMBER ('Z' - 'A')

#define MAX_HOST_DRIVE_NUMBER 64
#define MAX_HOST_PARTITION_NUMBER 32

typedef enum
{
	// IMPORTANT: If you add a new item here, update IsOSVersionAtLeast().

	WIN_UNKNOWN = 0,
	WIN_31,
	WIN_95,
	WIN_98,
	WIN_ME,
	WIN_NT3,
	WIN_NT4,
	WIN_2000,
	WIN_XP,
	WIN_XP64,
	WIN_SERVER_2003,
	WIN_VISTA,
	WIN_SERVER_2008,
	WIN_7,
	WIN_SERVER_2008_R2,
	WIN_8,
	WIN_SERVER_2012
} OSVersionEnum;

#ifdef __cplusplus
extern "C" {
#endif

	extern OSVersionEnum nCurrentOS;
	extern int CurrentOSMajor;
	extern int CurrentOSMinor;
	extern int CurrentOSServicePack;
	extern BOOL IsServerOS;

	DWORD InitOSVersionInfo ();
	BOOL IsOSAtLeast (OSVersionEnum reqMinOS);
	BOOL IsOSVersionAtLeast (OSVersionEnum reqMinOS, int reqMinServicePack);
	BOOL Is64BitOs ();
	BOOL ReadLocalMachineRegistryDword (char *subKey, char *name, DWORD *value);
	uint32 ReadEncryptionThreadPoolFreeCpuCountLimit ();

#ifdef __cplusplus
}
#endif

#endif