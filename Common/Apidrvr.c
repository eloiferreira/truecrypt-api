/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#include "Apidrvr.h"
#include "OsInfo.h"
#include "Errors.h"

#ifdef _WIN32

/* Handle to the device driver */
HANDLE hDriver = INVALID_HANDLE_VALUE;

/* This mutex is used to prevent multiple instances of the wizard or main app from trying to install or
register the driver or from trying to launch it in portable mode at the same time. */
volatile HANDLE hDriverSetupMutex = NULL;

BOOL bPortableModeConfirmed = FALSE;		// TRUE if it is certain that the instance is running in portable mode
LONG DriverVersion = 0;

BOOL DriverAttach (void) {
	/* Try to open a handle to the device driver. It will be closed later. */
	BOOL res = FALSE;
	int numTries = 5;

	/* NN: TrueCrypt attempts to CreateFile() first, and if it fails, acquires the mutex 
		and moves on with repeated attempts. We acquire mutex first since it should be 
		available anyway. This allows to keep CreateFile() related processing cleaner. 
		The counter mitigates possibility to hang if another program misbehaves while
		keeping the mutex. */

	while (numTries-- > 0) {
		if (!CreateDriverSetupMutex ()) {
			Sleep (100);	// Wait until the other instance finishes
			continue;
		}
	}
	
	if (!CheckDriverSetupMutex()) {
		SetLastError(TCAPI_E_CANT_ACQUIRE_DRIVER);
		return FALSE;
	}
	
	if (lpszDriverPath == NULL) { /* load installed driver */

		hDriver = CreateFile (WIN32_ROOT_PREFIX, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
			
		CloseDriverSetupMutex ();
			
		if (hDriver == INVALID_HANDLE_VALUE) {

			/* NN: Truecrypt here checks for an inconsistent state between config and driver status and 
				takes additional actions. We, au contraire, are an applied library in one of possibly 
				many TrueCrypt-related  processes, so we have to rely on consistency established by Truecrypt 
				application itself. We will take no action to modify system-wide setup. */

			// No other instance is currently attempting to install, check system encryption state

			(SystemEncryptionStatus != SYSENC_STATUS_NONE) ? 
				SetLastError (TCAPI_E_INCONSISTENT_DRIVER_STATE); : 
				SetLastError(TCAPI_E_DRIVER_NOT_INSTALLED);
			return FALSE;
		} // else we have a driver ready
	} else {
		/* load portable driver */
		// Attempt to load the driver (non-install/portable mode)

		/* TODO: Truecrypt tries this several times in case loaded driver is not of the needed version.
		   Since we provide an option for the developer to choose which driver to load, we'll load 
		   exactly the version requested. */

		res = DriverLoad ();

		CloseDriverSetupMutex ();

		if (res != ERROR_SUCCESS) 
			return FALSE;

		bPortableModeConfirmed = TRUE;

		hDriver = CreateFile (WIN32_ROOT_PREFIX, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (hDriver == INVALID_HANDLE_VALUE) {
			//TODO: Debug output
			SetLastError(TCAPI_E_CANT_LOAD_DRIVER);
			return FALSE;
		}

		if (bPortableModeConfirmed)
			NotifyDriverOfPortableMode ();
	}

	DWORD dwResult;

	BOOL bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_DRIVER_VERSION, NULL, 0, &DriverVersion, sizeof (DriverVersion), &dwResult, NULL);

	if (!bResult)
		bResult = DeviceIoControl (hDriver, TC_IOCTL_LEGACY_GET_DRIVER_VERSION, NULL, 0, &DriverVersion, sizeof (DriverVersion), &dwResult, NULL);

	if (bResult == FALSE)
	{
		//TODO: debug output here
		DriverVersion = 0;
		SetLastError(TCAPI_E_CANT_GET_DRIVER_VER);
		return FALSE;
	}
	else if (DriverVersion != VERSION_NUM)
	{
		DriverUnload ();
		CloseHandle (hDriver);
		hDriver = INVALID_HANDLE_VALUE;

		SetLastError(TCAPI_E_WRONG_DRIVER_VER);
		return FALSE;
	}

	return DriverVersion;
}

// Install and start driver service and mark it for removal (non-install mode)
static int DriverLoad (void)
{
	HANDLE file;
	WIN32_FIND_DATA find;
	SC_HANDLE hManager, hService = NULL;
	char driverPath[TC_MAX_PATH*2];
	BOOL res;
	char *tmp;
	DWORD startType;

	if (ReadLocalMachineRegistryDword ("SYSTEM\\CurrentControlSet\\Services\\truecrypt", "Start", &startType) && startType == SERVICE_BOOT_START) {
		// DriverLoad () is called only when checking whether we are able to load driver in portable mode after we have tried installed mode and failed.
		// Since here we see the service is actually registered, we shouldn't have failed and got to here in the first place, hence the error.
		SetLastError(TCAPI_E_SERVICE_NOT_STARTED);
		return ERR_PARAMETER_INCORRECT;
	}

	GetModuleFileName (NULL, driverPath, sizeof (driverPath));
	tmp = strrchr (driverPath, '\\');
	if (!tmp)
	{
		strcpy (driverPath, ".");
		tmp = driverPath + 1;
	}

	strcpy (tmp, !Is64BitOs () ? "\\truecrypt.sys" : "\\truecrypt-x64.sys");

	file = FindFirstFile (driverPath, &find);

	if (file == INVALID_HANDLE_VALUE)
	{

		SetLastError(TCAPI_E_DRIVER_NOT_FOUND);
		return ERR_DONT_REPORT;
	}

	FindClose (file);

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
	{
		if (GetLastError () == ERROR_ACCESS_DENIED)
		{
			SetLastError(TCAPI_E_NOACCESS_SCM);
			return ERR_DONT_REPORT;
		}

		SetLastError(TCAPI_E_CANT_OPEN_SCM);
		return ERR_OS_ERROR;
	}

	hService = OpenService (hManager, "truecrypt", SERVICE_ALL_ACCESS);
	if (hService != NULL)
	{
		// Remove stale service (driver is not loaded but service exists)
		DeleteService (hService);
		CloseServiceHandle (hService);
		Sleep (500);
	}

	hService = CreateService (hManager, "truecrypt", "truecrypt",
		SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
		driverPath, NULL, NULL, NULL, NULL, NULL);

	if (hService == NULL)
	{
		CloseServiceHandle (hManager);
		SetLastError(TCAPI_E_CANT_CREATE_SERVICE);
		return ERR_OS_ERROR;
	}

	res = StartService (hService, 0, NULL);
	DeleteService (hService);

	CloseServiceHandle (hManager);
	CloseServiceHandle (hService);
	
	if (!res) {
		SetLastError(TCAPI_E_CANT_START_SERVICE);
		return ERR_OS_ERROR;
	}

	return ERROR_SUCCESS;
}

// Tells the driver that it's running in portable mode
static void NotifyDriverOfPortableMode (void)
{
	if (hDriver != INVALID_HANDLE_VALUE)
	{
		DWORD dwResult;

		DeviceIoControl (hDriver, TC_IOCTL_SET_PORTABLE_MODE_STATUS, NULL, 0, NULL, 0, &dwResult, NULL);
	}
}

static int GetDriverRefCount (void)
{
	DWORD dwResult;
	BOOL bResult;
	int refCount;

	bResult = DeviceIoControl (hDriver, TC_IOCTL_GET_DEVICE_REFCOUNT, &refCount, sizeof (refCount), &refCount,
		sizeof (refCount), &dwResult, NULL);

	if (bResult)
		return refCount;
	else
		return -1;
}

static BOOL DriverUnload (void)
{
	MOUNT_LIST_STRUCT driver;
	int refCount;
	int volumesMounted;
	DWORD dwResult;
	BOOL bResult;

	SC_HANDLE hManager, hService = NULL;
	BOOL bRet;
	SERVICE_STATUS status;
	int x;
	BOOL driverUnloaded = FALSE;

	if (hDriver == INVALID_HANDLE_VALUE)
		return TRUE;

	//TODO: shouldnt unload driver if boot encryption is in place, have to check.
	//try
	//{
	//	if (BootEncryption (NULL).GetStatus().DeviceFilterActive)
	//		return FALSE;
	//}
	//catch (...) { }

	// Test for mounted volumes
	bResult = DeviceIoControl (hDriver, TC_IOCTL_IS_ANY_VOLUME_MOUNTED, NULL, 0, &volumesMounted, sizeof (volumesMounted), &dwResult, NULL);

	if (!bResult)
	{
		bResult = DeviceIoControl (hDriver, TC_IOCTL_LEGACY_GET_MOUNTED_VOLUMES, NULL, 0, &driver, sizeof (driver), &dwResult, NULL);
		if (bResult)
			volumesMounted = driver.ulMountedDrives;
	}

	if (bResult)
	{
		if (volumesMounted != 0)
			return FALSE;
	}
	else
		return TRUE;

	// Test for any applications attached to driver
	refCount = GetDriverRefCount ();

	if (refCount > 1)
		return FALSE;

	CloseHandle (hDriver);
	hDriver = INVALID_HANDLE_VALUE;

	// Stop driver service

	hManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager == NULL)
		goto error;

	hService = OpenService (hManager, "truecrypt", SERVICE_ALL_ACCESS);
	if (hService == NULL)
		goto error;

	bRet = QueryServiceStatus (hService, &status);
	if (bRet != TRUE)
		goto error;

	if (status.dwCurrentState != SERVICE_STOPPED)
	{
		ControlService (hService, SERVICE_CONTROL_STOP, &status);

		for (x = 0; x < 10; x++)
		{
			bRet = QueryServiceStatus (hService, &status);
			if (bRet != TRUE)
				goto error;

			if (status.dwCurrentState == SERVICE_STOPPED)
			{
				driverUnloaded = TRUE;
				break;
			}

			Sleep (200);
		}
	}
	else
		driverUnloaded = TRUE;

error:
	if (hService != NULL)
		CloseServiceHandle (hService);

	if (hManager != NULL)
		CloseServiceHandle (hManager);

	if (driverUnloaded)
	{
		hDriver = INVALID_HANDLE_VALUE;
		return TRUE;
	}

	return FALSE;
}

// Mutex handling to prevent multiple instances of the wizard or main app from trying to install
// or register the driver or from trying to launch it in portable mode at the same time.
// Returns TRUE if the mutex is (or had been) successfully acquired (otherwise FALSE). 
static BOOL CreateDriverSetupMutex (void)
{
	return TCCreateMutex (&hDriverSetupMutex, TC_MUTEX_NAME_DRIVER_SETUP);
}

static BOOL CheckDriverSetupMutex (void)
{
	return TCCheckMutex(&hDriverSetupMutex);
}

static void CloseDriverSetupMutex (void)
{
	TCCloseMutex (&hDriverSetupMutex);
}

static BOOL TCCheckMutex(volatile HANDLE *hMutex) {
	return (*hMutex != NULL);
}

// Returns TRUE if the mutex is (or had been) successfully acquired (otherwise FALSE). 
static BOOL TCCreateMutex (volatile HANDLE *hMutex, char *name)
{
	if TCCheckMutex(*hMutex)
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

#endif /* _WIN32 */