/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#ifndef MOUNT_H
#define MOUNT_H

#include <Windows.h>
#include "Password.h"

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct
	{
		BOOL ReadOnly;
		BOOL Removable;
		BOOL ProtectHiddenVolume;
		BOOL PreserveTimestamp;
		BOOL PartitionInInactiveSysEncScope;	/* If TRUE, we are to attempt to mount a partition located on an encrypted system drive without pre-boot authentication. */
		Password ProtectedHidVolPassword;	/* Password of hidden volume to protect against overwriting */
		BOOL UseBackupHeader;
		BOOL RecoveryMode;
	} MountOptions;

	extern MountOptions mountOptions;
	extern MountOptions defaultMountOptions;

#ifdef __cplusplus
};
#endif

#endif