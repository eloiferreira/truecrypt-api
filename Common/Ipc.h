/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#ifndef IPC_H
#define IPC_H

#include <windows.h>

#define TC_MUTEX_NAME_SYSENC				"Global\\TrueCrypt System Encryption Wizard"
#define TC_MUTEX_NAME_NONSYS_INPLACE_ENC	"Global\\TrueCrypt In-Place Encryption Wizard"
#define TC_MUTEX_NAME_APP_SETUP				"Global\\TrueCrypt Setup"
#define TC_MUTEX_NAME_DRIVER_SETUP			"Global\\TrueCrypt Driver Setup"

#ifdef __cplusplus
extern "C" {
#endif

	BOOL CreateDriverSetupMutex (void);
	BOOL CheckDriverSetupMutex (void);
	void CloseDriverSetupMutex (void);
	BOOL IsTrueCryptInstallerRunning (void);
	static BOOL TCCreateMutex (volatile HANDLE *hMutex, char *name);
	static BOOL TCCheckMutex(volatile HANDLE hMutex);
	static void TCCloseMutex (volatile HANDLE *hMutex);
	static BOOL MutexExistsOnSystem (char *name);

#ifdef __cplusplus
}
#endif
#endif