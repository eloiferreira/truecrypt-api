/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#include "Ipc.h"

/* This mutex is used to prevent multiple instances of the wizard or main app from trying to install or
register the driver or from trying to launch it in portable mode at the same time. */
volatile HANDLE hDriverSetupMutex = NULL;

// Mutex handling to prevent multiple instances of the wizard or main app from trying to install
// or register the driver or from trying to launch it in portable mode at the same time.
// Returns TRUE if the mutex is (or had been) successfully acquired (otherwise FALSE). 
BOOL CreateDriverSetupMutex (void)
{
	return TCCreateMutex (&hDriverSetupMutex, TC_MUTEX_NAME_DRIVER_SETUP);
}

BOOL CheckDriverSetupMutex (void)
{
	return TCCheckMutex(&hDriverSetupMutex);
}

void CloseDriverSetupMutex (void)
{
	TCCloseMutex (&hDriverSetupMutex);
}

static BOOL TCCheckMutex(volatile HANDLE hMutex) 
{
	return (hMutex != NULL);
}

// Returns TRUE if the mutex is (or had been) successfully acquired (otherwise FALSE). 
static BOOL TCCreateMutex (volatile HANDLE *hMutex, char *name)
{
	if (TCCheckMutex(*hMutex))
		return TRUE;	// This instance already has the mutex

	*hMutex = CreateMutex (NULL, TRUE, name);
	if (*hMutex == NULL)
	{
		// In multi-user configurations, the OS returns "Access is denied" here when a user attempts
		// to acquire the mutex if another user already has. However, on Vista, "Access is denied" is
		// returned also if the mutex is owned by a process with admin rights while we have none.

		return FALSE;
	}

	if (GetLastError () == ERROR_ALREADY_EXISTS)
	{
		ReleaseMutex (*hMutex);
		CloseHandle (*hMutex);

		*hMutex = NULL;
		return FALSE;
	}

	return TRUE;
}

static void TCCloseMutex (volatile HANDLE *hMutex)
{
	if (*hMutex != NULL)
	{
		if (ReleaseMutex (*hMutex)
			&& CloseHandle (*hMutex))
			*hMutex = NULL;
	}
}

BOOL IsTrueCryptInstallerRunning (void)
{
	return (MutexExistsOnSystem (TC_MUTEX_NAME_APP_SETUP));
}

// Returns TRUE if a process running on the system has the specified mutex (otherwise FALSE). 
static BOOL MutexExistsOnSystem (char *name)
{
	HANDLE hMutex = INVALID_HANDLE_VALUE;

	if (name[0] == 0)
		return FALSE;

	hMutex = OpenMutex (MUTEX_ALL_ACCESS, FALSE, name);

	if (hMutex == NULL)
	{
		if (GetLastError () == ERROR_FILE_NOT_FOUND)
			return FALSE;

		if (GetLastError () == ERROR_ACCESS_DENIED) // On Vista, this is returned if the owner of the mutex is elevated while we are not
			return TRUE;		

		// The call failed and it is not certain whether the mutex exists or not
		return FALSE;
	}

	CloseHandle (hMutex);
	return TRUE;
}
