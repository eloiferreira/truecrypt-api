/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#include "Mount.h"
#include "BootEncryption.h"
#include "Strings.h"
#include "OsInfo.h"
#include <io.h>
#include "Platform/ForEach.h"
#include <sstream>
#include "Boot/Windows/BootCommon.h"
#include "Uac.h"
#include "Platform/PlatformBase.h"
#include <Dbt.h>
#include <ShlObj.h>

using namespace TrueCrypt;

MountOptions mountOptions;
MountOptions defaultMountOptions;

VOLUME_NOTIFICATIONS_LIST	VolumeNotificationsList;	

int bPrebootPasswordDlgMode = FALSE;
int WrongPwdRetryCounter = 0;
BOOL MultipleMountOperationInProgress = FALSE;
BOOL FavoriteMountOnArrivalInProgress = FALSE;
BOOL MountVolumesAsSystemFavorite = FALSE;
BOOL LastMountedVolumeDirty;
BOOL IgnoreWmDeviceChange = FALSE;
BOOL DeviceChangeBroadcastDisabled = FALSE;
BOOL bForceMount = FALSE;			/* Mount volume even if host file/device already in use */
BOOL bForceUnmount = FALSE;			/* Unmount volume even if it cannot be locked */

BOOL UsePreferences = TRUE;
BOOL bCacheInDriverDefault = FALSE;
BOOL CloseSecurityTokenSessionsAfterMount = FALSE;

Password VolumePassword;			/* Password used for mounting volumes */
Password CmdVolumePassword;			/* Password passed from command line */

//TODO: remove
BOOL Silent = FALSE;

/* To populate these arrays, call GetSysDevicePaths(). If they contain valid paths, bCachedSysDevicePathsValid is TRUE. */
char SysPartitionDevicePath [TC_MAX_PATH];
char SysDriveDevicePath [TC_MAX_PATH];
string ExtraBootPartitionDevicePath;
char bCachedSysDevicePathsValid = FALSE;

BOOL IsMountedVolume (const char *volname)
{
	MOUNT_LIST_STRUCT mlist;
	DWORD dwResult;
	int i;
	char volume[TC_MAX_PATH*2+16];

	strcpy (volume, volname);

	if (strstr (volname, "\\Device\\") != volname)
		sprintf(volume, "\\??\\%s", volname);

	string resolvedPath = VolumeGuidPathToDevicePath (volname);
	if (!resolvedPath.empty())
		strcpy_s (volume, sizeof (volume), resolvedPath.c_str());

	ToUNICODE (volume);

	memset (&mlist, 0, sizeof (mlist));
	DeviceIoControl (hDriver, TC_IOCTL_GET_MOUNTED_VOLUMES, &mlist,
		sizeof (mlist), &mlist, sizeof (mlist), &dwResult,
		NULL);

	for (i=0 ; i<26; i++)
		if (0 == _wcsicmp ((wchar_t *) mlist.wszVolume[i], (WCHAR *)volume))
			return TRUE;

	return FALSE;
}

std::string VolumeGuidPathToDevicePath (std::string volumeGuidPath)
{
	if (volumeGuidPath.find ("\\\\?\\") == 0)
		volumeGuidPath = volumeGuidPath.substr (4);

	if (volumeGuidPath.find ("Volume{") != 0 || volumeGuidPath.rfind ("}\\") != volumeGuidPath.size() - 2)
		return string();

	char volDevPath[TC_MAX_PATH];
	if (QueryDosDevice (volumeGuidPath.substr (0, volumeGuidPath.size() - 1).c_str(), volDevPath, TC_MAX_PATH) == 0)
		return string();

	string partitionPath = HarddiskVolumePathToPartitionPath (volDevPath);

	return partitionPath.empty() ? volDevPath : partitionPath;
}

std::string HarddiskVolumePathToPartitionPath (const std::string &harddiskVolumePath)
{
	wstring volPath = SingleStringToWide (harddiskVolumePath);

	for (int driveNumber = 0; driveNumber < MAX_HOST_DRIVE_NUMBER; driveNumber++)
	{
		for (int partNumber = 0; partNumber < MAX_HOST_PARTITION_NUMBER; partNumber++)
		{
			wchar_t partitionPath[TC_MAX_PATH];
			swprintf_s (partitionPath, ARRAYSIZE (partitionPath), L"\\Device\\Harddisk%d\\Partition%d", driveNumber, partNumber);

			wchar_t resolvedPath[TC_MAX_PATH];
			if (ResolveSymbolicLink (partitionPath, resolvedPath))
			{
				if (volPath == resolvedPath)
					return WideToSingleString (partitionPath);
			}
			else if (partNumber == 0)
				break;
		}
	}

	return string();
}

BOOL VolumePathExists (char *volumePath)
{
	OPEN_TEST_STRUCT openTest;
	char upperCasePath[TC_MAX_PATH];

	UpperCaseCopy (upperCasePath, volumePath);

	if (strstr (upperCasePath, "\\DEVICE\\") == upperCasePath)
		return OpenDevice (volumePath, &openTest, FALSE);

	string path = volumePath;
	if (path.find ("\\\\?\\Volume{") == 0 && path.rfind ("}\\") == path.size() - 2)
	{
		char devicePath[TC_MAX_PATH];
		if (QueryDosDevice (path.substr (4, path.size() - 5).c_str(), devicePath, TC_MAX_PATH) != 0)
			return TRUE;
	}

	return _access (volumePath, 0) == 0;
}

BOOL OpenDevice (const char *lpszPath, OPEN_TEST_STRUCT *driver, BOOL detectFilesystem)
{
	DWORD dwResult;
	BOOL bResult;

	strcpy ((char *) &driver->wszFileName[0], lpszPath);
	ToUNICODE ((char *) &driver->wszFileName[0]);

	driver->bDetectTCBootLoader = FALSE;
	driver->DetectFilesystem = detectFilesystem;

	bResult = DeviceIoControl (hDriver, TC_IOCTL_OPEN_TEST,
		driver, sizeof (OPEN_TEST_STRUCT),
		driver, sizeof (OPEN_TEST_STRUCT),
		&dwResult, NULL);

	if (bResult == FALSE)
	{
		dwResult = GetLastError ();

		if (dwResult == ERROR_SHARING_VIOLATION || dwResult == ERROR_NOT_READY)
		{
			driver->TCBootLoaderDetected = FALSE;
			driver->FilesystemDetected = FALSE;
			return TRUE;
		}
		else
			return FALSE;
	}

	return TRUE;
}

void IncreaseWrongPwdRetryCount (int count)
{
	WrongPwdRetryCounter += count;
}

void ResetWrongPwdRetryCount (void)
{
	WrongPwdRetryCounter = 0;
}

BOOL GetDriveLabel (int driveNo, wchar_t *label, int labelSize)
{
	DWORD fileSystemFlags;
	wchar_t root[] = { L'A' + (wchar_t) driveNo, L':', L'\\', 0 };

	return GetVolumeInformationW (root, label, labelSize / 2, NULL, NULL, &fileSystemFlags, NULL, 0);
}

// Returns 0 if an error occurs or the drive letter (as an upper-case char) of the system partition (e.g. 'C');
char GetSystemDriveLetter (void)
{
	char systemDir [MAX_PATH];

	if (GetSystemDirectory (systemDir, sizeof (systemDir)))
		return (char) (toupper (systemDir [0]));
	else
		return 0;
}

BOOL GetDeviceInfo (const char *deviceName, DISK_PARTITION_INFO_STRUCT *info)
{
	DWORD dwResult;

	memset (info, 0, sizeof(*info));
	wsprintfW ((PWSTR) &info->deviceName, L"%hs", deviceName);

	return DeviceIoControl (hDriver, TC_IOCTL_GET_DRIVE_PARTITION_INFO, info, sizeof (*info), info, sizeof (*info), &dwResult, NULL);
}

std::vector <HostDevice> GetAvailableHostDevices (bool noDeviceProperties, bool singleList, bool noFloppy, bool detectUnencryptedFilesystems)
{
	vector <HostDevice> devices;
	size_t dev0;

	for (int devNumber = 0; devNumber < MAX_HOST_DRIVE_NUMBER; devNumber++)
	{
		for (int partNumber = 0; partNumber < MAX_HOST_PARTITION_NUMBER; partNumber++)
		{
			stringstream strm;
			strm << "\\Device\\Harddisk" << devNumber << "\\Partition" << partNumber;
			string devPathStr (strm.str());
			const char *devPath = devPathStr.c_str();

			OPEN_TEST_STRUCT openTest;
			if (!OpenDevice (devPath, &openTest, detectUnencryptedFilesystems && partNumber != 0))
			{
				if (partNumber == 0)
					break;

				continue;
			}

			HostDevice device;
			device.SystemNumber = devNumber;
			device.Path = devPath;

			PARTITION_INFORMATION partInfo;

			if (GetPartitionInfo (devPath, &partInfo))
			{
				device.Bootable = partInfo.BootIndicator ? true : false;
				device.Size = partInfo.PartitionLength.QuadPart;
			}

			device.HasUnencryptedFilesystem = (detectUnencryptedFilesystems && openTest.FilesystemDetected) ? true : false;

			if (!noDeviceProperties)
			{
				DISK_GEOMETRY geometry;

				wstringstream ws;
				ws << devPathStr.c_str();
				int driveNumber = GetDiskDeviceDriveLetter ((wchar_t *) ws.str().c_str());

				if (driveNumber >= 0)
				{
					device.MountPoint += (char) (driveNumber + 'A');
					device.MountPoint += ":";

					wchar_t name[64];
					if (GetDriveLabel (driveNumber, name, sizeof (name)))
						device.Name = name;

					if (GetSystemDriveLetter() == 'A' + driveNumber)
						device.ContainsSystem = true;
				}

				if (partNumber == 0 && GetDriveGeometry (devPath, &geometry))
					device.Removable = (geometry.MediaType == RemovableMedia);
			}

			if (partNumber == 0)
			{
				devices.push_back (device);
				dev0 = devices.size() - 1;
			}
			else
			{
				// System creates a virtual partition1 for some storage devices without
				// partition table. We try to detect this case by comparing sizes of
				// partition0 and partition1. If they match, no partition of the device
				// is displayed to the user to avoid confusion. Drive letter assigned by
				// system to partition1 is assigned partition0
				if (partNumber == 1 && devices[dev0].Size == device.Size)
				{
					devices[dev0].IsVirtualPartition = true;
					devices[dev0].MountPoint = device.MountPoint;
					devices[dev0].Name = device.Name;
					devices[dev0].Path = device.Path;
					devices[dev0].HasUnencryptedFilesystem = device.HasUnencryptedFilesystem;
					break;
				}

				device.IsPartition = true;
				device.SystemNumber = partNumber;
				device.Removable = devices[dev0].Removable;

				if (device.ContainsSystem)
					devices[dev0].ContainsSystem = true;

				if (singleList)
					devices.push_back (device);

				devices[dev0].Partitions.push_back (device);
			}
		}
	}

	// Vista does not create partition links for dynamic volumes so it is necessary to scan \\Device\\HarddiskVolumeX devices
	if (CurrentOSMajor >= 6)
	{
		for (int devNumber = 0; devNumber < 256; devNumber++)
		{
			stringstream strm;
			strm << "\\Device\\HarddiskVolume" << devNumber;
			string devPathStr (strm.str());
			const char *devPath = devPathStr.c_str();

			OPEN_TEST_STRUCT openTest;
			if (!OpenDevice (devPath, &openTest, detectUnencryptedFilesystems))
				continue;

			DISK_PARTITION_INFO_STRUCT info;
			if (GetDeviceInfo (devPath, &info) && info.IsDynamic)
			{
				HostDevice device;
				device.DynamicVolume = true;
				device.IsPartition = true;
				device.SystemNumber = devNumber;
				device.Path = devPath;
				device.Size = info.partInfo.PartitionLength.QuadPart;
				device.HasUnencryptedFilesystem = (detectUnencryptedFilesystems && openTest.FilesystemDetected) ? true : false;

				if (!noDeviceProperties)
				{
					wstringstream ws;
					ws << devPathStr.c_str();
					int driveNumber = GetDiskDeviceDriveLetter ((wchar_t *) ws.str().c_str());

					if (driveNumber >= 0)
					{
						device.MountPoint += (char) (driveNumber + 'A');
						device.MountPoint += ":";

						wchar_t name[64];
						if (GetDriveLabel (driveNumber, name, sizeof (name)))
							device.Name = name;

						if (GetSystemDriveLetter() == 'A' + driveNumber)
							device.ContainsSystem = true;
					}
				}

				devices.push_back (device);
			}
		}
	}

	return devices;
}

/* Stores the device path of the system partition in SysPartitionDevicePath and the device path of the system drive
in SysDriveDevicePath.
IMPORTANT: As this may take a very long time if called for the first time, it should be called only before performing 
           a dangerous operation (such as header backup restore or formatting a supposedly non-system device) never 
		   at WM_INITDIALOG or any other GUI events -- instead call IsSystemDevicePath (path, hwndDlg, FALSE) for 
		   very fast preliminary GUI checks; also note that right after the "Select Device" dialog exits with an OK 
		   return code, you can use the global flags bSysPartitionSelected and bSysDriveSelected to see if the user
		   selected the system partition/device.
After this function completes successfully, the results are cached for the rest of the session and repeated
executions complete very fast. Returns TRUE if successful (otherwise FALSE). */
BOOL GetSysDevicePaths (void)
{
	if (!bCachedSysDevicePathsValid
		|| strlen (SysPartitionDevicePath) <= 1 
		|| strlen (SysDriveDevicePath) <= 1)
	{
		foreach (const HostDevice &device, GetAvailableHostDevices (false, true))
		{
			if (device.ContainsSystem)
				strcpy_s (device.IsPartition ? SysPartitionDevicePath : SysDriveDevicePath, TC_MAX_PATH, device.Path.c_str()); 
		}

		if (IsOSAtLeast (WIN_7))
		{
			// Find extra boot partition
			foreach (const HostDevice &drive, GetAvailableHostDevices (false, false))
			{
				if (drive.ContainsSystem)
				{
					foreach (const HostDevice &sysDrivePartition, drive.Partitions)
					{
						if (sysDrivePartition.Bootable)
						{
							if (sysDrivePartition.Size <= TC_MAX_EXTRA_BOOT_PARTITION_SIZE)
								ExtraBootPartitionDevicePath = sysDrivePartition.Path;
							break;
						}
					}
					break;
				}
			}
		}

		bCachedSysDevicePathsValid = 1;
	}

	return (bCachedSysDevicePathsValid 
		&& strlen (SysPartitionDevicePath) > 1 
		&& strlen (SysDriveDevicePath) > 1);
}

/* Determines whether the device path is the path of the system partition or of the system drive (or neither). 
If bReliableRequired is TRUE, very fast execution is guaranteed, but the results cannot be relied upon. 
If it's FALSE and the function is called for the first time, execution may take up to one minute but the
results are reliable.
IMPORTANT: As the execution may take a very long time if called for the first time with bReliableRequired set
           to TRUE, it should be called with bReliableRequired set to TRUE only before performing a dangerous
		   operation (such as header backup restore or formatting a supposedly non-system device) never at 
		   WM_INITDIALOG or any other GUI events (use IsSystemDevicePath(path, hwndDlg, FALSE) for fast 
		   preliminary GUI checks; also note that right after the "Select Device" dialog exits with an OK 
		   return code, you can use the global flags bSysPartitionSelected and bSysDriveSelected to see if the
		   user selected the system partition/device).
After this function completes successfully, the results are cached for the rest of the session, bReliableRequired
is ignored (TRUE implied), repeated executions complete very fast, and the results are always reliable. 
Return codes:
1  - it is the system partition path (e.g. \Device\Harddisk0\Partition1)
2  - it is the system drive path (e.g. \Device\Harddisk0\Partition0)
3  - it is the extra boot partition path
0  - it's not the system partition/drive path
-1 - the result can't be determined, isn't reliable, or there was an error. */
int IsSystemDevicePath (char *path, BOOL bReliableRequired)
{
	if (!bCachedSysDevicePathsValid
		&& bReliableRequired)
	{
		if (!GetSysDevicePaths ())
			return -1;
	}

	if (strlen (SysPartitionDevicePath) <= 1 || strlen (SysDriveDevicePath) <= 1)
		return -1;

	if (strncmp (path, SysPartitionDevicePath, max (strlen(path), strlen(SysPartitionDevicePath))) == 0)
		return 1;
	else if (strncmp (path, SysDriveDevicePath, max (strlen(path), strlen(SysDriveDevicePath))) == 0)
		return 2;
	else if (ExtraBootPartitionDevicePath == path)
		return 3;

	return 0;
}

// WARNING: This function may take a long time to complete. To prevent data corruption, it MUST be called before
// mounting a partition (as a regular volume) that is within key scope of system encryption.
// Returns TRUE if the partition can be mounted as a partition within key scope of inactive system encryption.
// If devicePath is empty, the currently selected partition in the GUI is checked.
BOOL CheckSysEncMountWithoutPBA (const char *devicePath)
{
	//BOOL tmpbDevice;
	char szDevicePath [TC_MAX_PATH+1];
	//char szDiskFile [TC_MAX_PATH+1];

	if (strlen (devicePath) < 2)
	{
		set_error_debug_out(TCAPI_E_PARAM_INCORRECT);
		return FALSE;
	}
	else
		strncpy (szDevicePath, devicePath, sizeof (szDevicePath));

	char *partionPortion = strrchr (szDevicePath, '\\');

	if (!partionPortion || !_stricmp (partionPortion, "\\Partition0"))
	{
		// Only partitions are supported (not whole drives)
		set_error_debug_out(TCAPI_E_NO_SYSENC_PARTITION);
		return FALSE;
	}

	try
	{
		BootEncStatus = BootEncObj->GetStatus();

		if (BootEncStatus.DriveMounted)
		{
			int retCode = 0;
			int driveNo;
			char parentDrivePath [TC_MAX_PATH+1];

			if (sscanf (szDevicePath, "\\Device\\Harddisk%d\\Partition", &driveNo) != 1)
			{
				set_error_debug_out(TCAPI_E_INVALID_PATH);
				return FALSE;
			}

			_snprintf (parentDrivePath,
				sizeof (parentDrivePath),
				"\\Device\\Harddisk%d\\Partition0",
				driveNo);

			// This is critical (re-mounting a mounted system volume as a normal volume could cause data corruption)
			// so we force the slower but reliable method
			retCode = IsSystemDevicePath (parentDrivePath, TRUE);

			if (retCode != 2)
				return TRUE;
			else
			{
				// The partition is located on active system drive
				set_error_debug_out(TCAPI_E_NOPBA_MOUNT_ON_ACTIVE_SYSENC_DRIVE);
				return FALSE;
			}
		}
		else
			return TRUE;
	}
	catch (Exception &e)
	{
		// exception sets last error
		e.Show ();
	}

	return FALSE;
}

BOOL IsDriveAvailable (int driveNo)
{
	return (GetLogicalDrives() & (1 << driveNo)) == 0;
}

BOOL IsPasswordCacheEmpty (void)
{
	DWORD dw;
	return !DeviceIoControl (hDriver, TC_IOCTL_GET_PASSWORD_CACHE_STATUS, 0, 0, 0, 0, &dw, 0);
}

BOOL WrongPwdRetryCountOverLimit (void)
{
	return (WrongPwdRetryCounter > TC_TRY_HEADER_BAK_AFTER_NBR_WRONG_PWD_TRIES);
}

void CheckFilesystem (int driveNo, BOOL fixErrors)
{
	wchar_t param[1024];
	char driveRoot[] = { 'A' + (char) driveNo, ':', 0 };

	//TODO: needs testing
	wsprintfW (param, fixErrors ? L"/C chkdsk %hs /F /X & pause" : L"/C chkdsk %hs & pause", driveRoot);
	ShellExecuteW (NULL, (!IsAdmin() && IsUacSupported()) ? L"runas" : L"open", L"cmd.exe", param, NULL, SW_SHOW);
}

// Use only cached passwords if password = NULL
//
// Returns:
// -1 = user aborted mount / error
// 0  = mount failed
// 1  = mount OK
// 2  = mount OK in shared mode
//
// Note that some code calling this relies on the content of the mountOptions struct
// to remain unmodified (don't remove the 'const' without proper revision).

int MountVolume (int driveNo, char *volumePath, Password *password, BOOL cachePassword, BOOL sharedAccess, const MountOptions* const mountOptions, BOOL bReportWrongPassword, BOOL bRetryIfInUse)
{
	MOUNT_STRUCT mount;
	DWORD dwResult;
	BOOL bResult, bDevice;
	char root[MAX_PATH];
	int favoriteMountOnArrivalRetryCount = 0;

	if (mountOptions->PartitionInInactiveSysEncScope)
	{
		if (!CheckSysEncMountWithoutPBA (volumePath))
			return -1;
	}

	if (IsMountedVolume (volumePath))
	{
		set_error_debug_out(TCAPI_E_VOL_ALREADY_MOUNTED);
		return -1;
	}

	if (!IsDriveAvailable (driveNo))
	{
		set_error_debug_out(TCAPI_E_DRIVE_LETTER_UNAVAILABLE);
		return -1;
	}

	// If using cached passwords, check cache status first
	if (password == NULL && IsPasswordCacheEmpty ())
	{
		set_error_debug_out(TCAPI_E_PASSWORD_NULL_AND_NOT_CACHED);
		return 0;
	}

	ZeroMemory (&mount, sizeof (mount));
	mount.bExclusiveAccess = sharedAccess ? FALSE : TRUE;
	mount.SystemFavorite = MountVolumesAsSystemFavorite;
	mount.UseBackupHeader =  mountOptions->UseBackupHeader;
	mount.RecoveryMode = mountOptions->RecoveryMode;

retry:
	mount.nDosDriveNo = driveNo;
	mount.bCache = cachePassword;

	mount.bPartitionInInactiveSysEncScope = FALSE;

	if (password != NULL)
		mount.VolumePassword = *password;
	else
		mount.VolumePassword.Length = 0;

	if (!mountOptions->ReadOnly && mountOptions->ProtectHiddenVolume)
	{
		mount.ProtectedHidVolPassword = mountOptions->ProtectedHidVolPassword;
		mount.bProtectHiddenVolume = TRUE;
	}
	else
		mount.bProtectHiddenVolume = FALSE;

	mount.bMountReadOnly = mountOptions->ReadOnly;
	mount.bMountRemovable = mountOptions->Removable;
	mount.bPreserveTimestamp = mountOptions->PreserveTimestamp;

	mount.bMountManager = TRUE;

	// Windows 2000 mount manager causes problems with remounted volumes
	if (CurrentOSMajor == 5 && CurrentOSMinor == 0)
		mount.bMountManager = FALSE;

	string path = volumePath;
	if (path.find ("\\\\?\\") == 0)
	{
		// Remove \\?\ prefix
		path = path.substr (4);
		strcpy_s (volumePath, TC_MAX_PATH, path.c_str());
	}

	if (path.find ("Volume{") == 0 && path.rfind ("}\\") == path.size() - 2)
	{
		string resolvedPath = VolumeGuidPathToDevicePath (path);

		if (!resolvedPath.empty())
			strcpy_s (volumePath, TC_MAX_PATH, resolvedPath.c_str());
	}

	CreateFullVolumePath ((char *) mount.wszVolume, volumePath, &bDevice);

	if (!bDevice)
	{
		// UNC path
		if (path.find ("\\\\") == 0)
		{
			strcpy_s ((char *)mount.wszVolume, array_capacity (mount.wszVolume), ("UNC" + path.substr (1)).c_str());
		}

		if (GetVolumePathName (volumePath, root, sizeof (root) - 1))
		{
			DWORD bps, flags, d;
			if (GetDiskFreeSpace (root, &d, &bps, &d, &d))
				mount.BytesPerSector = bps;

			// Read-only host filesystem
			if (!mount.bMountReadOnly && GetVolumeInformation (root, NULL, 0,  NULL, &d, &flags, NULL, 0))
				mount.bMountReadOnly = (flags & FILE_READ_ONLY_VOLUME) != 0;
		}
	}

	ToUNICODE ((char *) mount.wszVolume);

	if (mountOptions->PartitionInInactiveSysEncScope)
	{
		if (mount.wszVolume == NULL || swscanf_s ((const wchar_t *) mount.wszVolume,
			WIDE("\\Device\\Harddisk%d\\Partition"),
			&mount.nPartitionInInactiveSysEncScopeDriveNo,
			sizeof(mount.nPartitionInInactiveSysEncScopeDriveNo)) != 1)
		{
			return -1;
		}

		mount.bPartitionInInactiveSysEncScope = TRUE;
	}

	bResult = DeviceIoControl (hDriver, TC_IOCTL_MOUNT_VOLUME, &mount,
		sizeof (mount), &mount, sizeof (mount), &dwResult, NULL);

	burn (&mount.VolumePassword, sizeof (mount.VolumePassword));
	burn (&mount.ProtectedHidVolPassword, sizeof (mount.ProtectedHidVolPassword));

	if (bResult == FALSE)
	{
		// Volume already open by another process
		if (GetLastError () == ERROR_SHARING_VIOLATION)
		{
			if (FavoriteMountOnArrivalInProgress && ++favoriteMountOnArrivalRetryCount < 10)
			{
				Sleep (500);
				goto retry;
			}

			if (mount.bExclusiveAccess == FALSE)
			{
				set_error_debug_out(TCAPI_E_FILE_IN_USE);
				return -1;
			}
			else
			{
				if (bRetryIfInUse)
				{
					mount.bExclusiveAccess = FALSE;
					goto retry;
				}
			}

			return -1;
		}

		if (!MultipleMountOperationInProgress || GetLastError() != ERROR_NOT_READY) 
			handleWin32Error ();

		return -1;
	}

	if (mount.nReturnCode != 0)
	{
		if (mount.nReturnCode == ERR_PASSWORD_WRONG)
		{
			// Do not report wrong password, if not instructed to 
			if (bReportWrongPassword)
			{
				IncreaseWrongPwdRetryCount (1);		// We increase the count here only if bReportWrongPassword is TRUE, because "Auto-Mount All Devices" and other callers do it separately

				if (WrongPwdRetryCountOverLimit () 
					&& !mount.UseBackupHeader)
				{
					// Retry using embedded header backup (if any)
					mount.UseBackupHeader = TRUE;
					goto retry;
				}

				if (bDevice && mount.bProtectHiddenVolume)
				{
					int driveNo;

					if (sscanf (volumePath, "\\Device\\Harddisk%d\\Partition", &driveNo) == 1)
					{
						OPEN_TEST_STRUCT openTestStruct;
						memset (&openTestStruct, 0, sizeof (openTestStruct));

						openTestStruct.bDetectTCBootLoader = TRUE;
						_snwprintf ((wchar_t *) openTestStruct.wszFileName, array_capacity (openTestStruct.wszFileName), L"\\Device\\Harddisk%d\\Partition0", driveNo);

						DWORD dwResult;
						if (DeviceIoControl (hDriver, TC_IOCTL_OPEN_TEST, &openTestStruct, sizeof (OPEN_TEST_STRUCT), &openTestStruct, sizeof (OPEN_TEST_STRUCT), &dwResult, NULL) && openTestStruct.TCBootLoaderDetected)
							HandlePasswordError();
						else
							set_error_debug_out(mount.nReturnCode);
					}
				}
				else
					set_error_debug_out(mount.nReturnCode);
			}

			return 0;
		}

		set_error_debug_out(mount.nReturnCode);

		return 0;
	}

	// Mount successful

	if (mount.UseBackupHeader != mountOptions->UseBackupHeader
		&& mount.UseBackupHeader)
	{
		if (bReportWrongPassword) 
			set_error_debug_out(TCAPI_W_HEADER_DAMAGED_BACKUP_USED);
	}

	LastMountedVolumeDirty = mount.FilesystemDirty;

	//if (mount.FilesystemDirty)
	//{
	//	wchar_t msg[1024];
	//	wchar_t mountPoint[] = { L'A' + (wchar_t) driveNo, L':', 0 };
	//	//wsprintfW (msg, GetString ("MOUNTED_VOLUME_DIRTY"), mountPoint);

	//	//TODO:
	//	//if (AskWarnYesNoStringTopmost (msg) == IDYES)
	//	//	CheckFilesystem (driveNo, TRUE);
	//}

	//TODO:
	//if (mount.VolumeMountedReadOnlyAfterAccessDenied
	//	&& !Silent
	//	&& !bDevice
	//	&& !FileHasReadOnlyAttribute (volumePath)
	//	&& !IsFileOnReadOnlyFilesystem (volumePath))
	//{
	//	wchar_t msg[1024];
	//	wchar_t mountPoint[] = { L'A' + (wchar_t) driveNo, L':', 0 };
	//	wsprintfW (msg, GetString ("MOUNTED_CONTAINER_FORCED_READ_ONLY"), mountPoint);

	//	WarningDirect (msg);
	//}

	//TODO:
	//if (mount.VolumeMountedReadOnlyAfterAccessDenied
	//	&& !Silent
	//	&& bDevice)
	//{
	//	wchar_t msg[1024];
	//	wchar_t mountPoint[] = { L'A' + (wchar_t) driveNo, L':', 0 };
	//	wsprintfW (msg, GetString ("MOUNTED_DEVICE_FORCED_READ_ONLY"), mountPoint);

	//	WarningDirect (msg);
	//}

	//TODO:
	//if (mount.VolumeMountedReadOnlyAfterDeviceWriteProtected
	//	&& !Silent
	//	&& strstr (volumePath, "\\Device\\Harddisk") == volumePath)
	//{
	//	wchar_t msg[1024];
	//	wchar_t mountPoint[] = { L'A' + (wchar_t) driveNo, L':', 0 };
	//	wsprintfW (msg, GetString ("MOUNTED_DEVICE_FORCED_READ_ONLY_WRITE_PROTECTION"), mountPoint);

	//	WarningDirect (msg);

	//	if (CurrentOSMajor >= 6
	//		&& strstr (volumePath, "\\Device\\HarddiskVolume") != volumePath
	//		&& AskNoYes ("ASK_REMOVE_DEVICE_WRITE_PROTECTION") == IDYES)
	//	{
	//		RemoveDeviceWriteProtection (hwndDlg, volumePath);
	//	}
	//}

	ResetWrongPwdRetryCount ();

	BroadcastDeviceChange (DBT_DEVICEARRIVAL, driveNo, 0);

	if (mount.bExclusiveAccess == FALSE)
		return 2;

	return 1;
}

void BroadcastDeviceChange (WPARAM message, int nDosDriveNo, DWORD driveMap)
{
	DEV_BROADCAST_VOLUME dbv;
	DWORD_PTR dwResult;
	LONG eventId = 0;
	int i;

	if (DeviceChangeBroadcastDisabled)
		return;

	if (message == DBT_DEVICEARRIVAL)
		eventId = SHCNE_DRIVEADD;
	else if (message == DBT_DEVICEREMOVECOMPLETE)
		eventId = SHCNE_DRIVEREMOVED;
	else if (IsOSAtLeast (WIN_7) && message == DBT_DEVICEREMOVEPENDING) // Explorer on Windows 7 holds open handles of all drives when 'Computer' is expanded in navigation pane. SHCNE_DRIVEREMOVED must be used as DBT_DEVICEREMOVEPENDING is ignored.
		eventId = SHCNE_DRIVEREMOVED;

	if (driveMap == 0)
		driveMap = (1 << nDosDriveNo);

	if (eventId != 0)
	{
		for (i = 0; i < 26; i++)
		{
			if (driveMap & (1 << i))
			{
				char root[] = { (char) i + 'A', ':', '\\', 0 };
				SHChangeNotify (eventId, SHCNF_PATH, root, NULL);

				if (nCurrentOS == WIN_2000 && RemoteSession)
				{
					char target[32];
					wsprintf (target, "%ls%c", TC_MOUNT_PREFIX, i + 'A');
					root[2] = 0;

					if (message == DBT_DEVICEARRIVAL)
						DefineDosDevice (DDD_RAW_TARGET_PATH, root, target);
					else if (message == DBT_DEVICEREMOVECOMPLETE)
						DefineDosDevice (DDD_RAW_TARGET_PATH| DDD_REMOVE_DEFINITION
						| DDD_EXACT_MATCH_ON_REMOVE, root, target);
				}
			}
		}
	}

	dbv.dbcv_size = sizeof (dbv); 
	dbv.dbcv_devicetype = DBT_DEVTYP_VOLUME; 
	dbv.dbcv_reserved = 0;
	dbv.dbcv_unitmask = driveMap;
	dbv.dbcv_flags = 0; 

	UINT timeOut = 1000;

	// SHChangeNotify() works on Vista, so the Explorer does not require WM_DEVICECHANGE
	if (CurrentOSMajor >= 6)
		timeOut = 100;

	IgnoreWmDeviceChange = TRUE;
	SendMessageTimeout (HWND_BROADCAST, WM_DEVICECHANGE, message, (LPARAM)(&dbv), SMTO_ABORTIFHUNG, timeOut, &dwResult);

	// Explorer prior Vista sometimes fails to register a new drive
	if (CurrentOSMajor < 6 && message == DBT_DEVICEARRIVAL)
		SendMessageTimeout (HWND_BROADCAST, WM_DEVICECHANGE, message, (LPARAM)(&dbv), SMTO_ABORTIFHUNG, 200, &dwResult);

	IgnoreWmDeviceChange = FALSE;
}

// Checks whether the file extension is not used for executable files or similarly problematic, which often
// causes Windows and antivirus software to interfere with the container.
BOOL CheckFileExtension (char *fileName)
{
	int i = 0;
	char *ext = strrchr (fileName, '.');
	static char *problemFileExt[] = {
		// These are protected by the Windows Resource Protection
		".asa", ".asp", ".aspx", ".ax", ".bas", ".bat", ".bin", ".cer", ".chm", ".clb", ".cmd", ".cnt", ".cnv",
		".com", ".cpl", ".cpx", ".crt", ".csh", ".dll", ".drv", ".dtd", ".exe", ".fxp", ".grp", ".h1s", ".hlp",
		".hta", ".ime", ".inf", ".ins", ".isp", ".its", ".js", ".jse", ".ksh", ".lnk", ".mad", ".maf", ".mag",
		".mam", ".man", ".maq", ".mar", ".mas", ".mat", ".mau", ".mav", ".maw", ".mda", ".mdb", ".mde", ".mdt",
		".mdw", ".mdz", ".msc", ".msi", ".msp", ".mst", ".mui", ".nls", ".ocx", ".ops", ".pal", ".pcd", ".pif",
		".prf", ".prg", ".pst", ".reg", ".scf", ".scr", ".sct", ".shb", ".shs", ".sys", ".tlb", ".tsp", ".url",
		".vb", ".vbe", ".vbs", ".vsmacros", ".vss", ".vst", ".vsw", ".ws", ".wsc", ".wsf", ".wsh", ".xsd", ".xsl",
		// These additional file extensions are usually watched by antivirus programs
		".386", ".acm", ".ade", ".adp", ".ani", ".app", ".asd", ".asf", ".asx", ".awx", ".ax", ".boo", ".bz2", ".cdf",
		".class", ".dhtm", ".dhtml",".dlo", ".emf", ".eml", ".flt", ".fot", ".gz", ".hlp", ".htm", ".html", ".ini", 
		".j2k", ".jar", ".jff", ".jif", ".jmh", ".jng", ".jp2", ".jpe", ".jpeg", ".jpg", ".lsp", ".mod", ".nws",
		".obj", ".olb", ".osd", ".ov1", ".ov2", ".ov3", ".ovl", ".ovl", ".ovr", ".pdr", ".pgm", ".php", ".pkg",
		".pl", ".png", ".pot", ".pps", ".ppt", ".ps1", ".ps1xml", ".psc1", ".rar", ".rpl", ".rtf", ".sbf", ".script", ".sh", ".sha", ".shtm",
		".shtml", ".spl", ".swf", ".tar", ".tgz", ".tmp", ".ttf", ".vcs", ".vlm", ".vxd", ".vxo", ".wiz", ".wll", ".wmd",
		".wmf",	".wms", ".wmz", ".wpc", ".wsc", ".wsh", ".wwk", ".xhtm", ".xhtml", ".xl", ".xml", ".zip", ".7z", 0};

		if (!ext)
			return FALSE;

		while (problemFileExt[i])
		{
			if (!_stricmp (ext, problemFileExt[i++]))
				return TRUE;
		}

		return FALSE;
}

// Returns the mode of operation in which the volume mounted as the specified drive letter is encrypted. 
int GetModeOfOperationByDriveNo (int nDosDriveNo)
{
	VOLUME_PROPERTIES_STRUCT prop;
	DWORD dwResult;

	memset (&prop, 0, sizeof(prop));
	prop.driveNo = nDosDriveNo;

	if (DeviceIoControl (hDriver, TC_IOCTL_GET_VOLUME_PROPERTIES, &prop, sizeof (prop), &prop, sizeof (prop), &dwResult, NULL))
	{
		return prop.mode;
	}

	return 0;
}

// Returns the block size (in bits) of the cipher with which the volume mounted as the
// specified drive letter is encrypted. In case of a cascade of ciphers with different
// block sizes the function returns the smallest block size.
int GetCipherBlockSizeByDriveNo (int nDosDriveNo)
{
	VOLUME_PROPERTIES_STRUCT prop;
	DWORD dwResult;

	int blockSize = 0, cipherID;

	memset (&prop, 0, sizeof(prop));
	prop.driveNo = nDosDriveNo;

	if (DeviceIoControl (hDriver, TC_IOCTL_GET_VOLUME_PROPERTIES, &prop, sizeof (prop), &prop, sizeof (prop), &dwResult, NULL))
	{
		for (cipherID = EAGetLastCipher (prop.ea);
			cipherID != 0;
			cipherID = EAGetPreviousCipher (prop.ea, cipherID))
		{
			if (blockSize > 0)
				blockSize = min (blockSize, CipherGetBlockSize (cipherID) * 8);
			else
				blockSize = CipherGetBlockSize (cipherID) * 8;
		}
	}

	return blockSize;
}

BOOL Mount (HWND hwndDlg, int nDosDriveNo, char *szFileName, Password VolumePassword)
{
	BOOL status = FALSE;
	//char fileName[MAX_PATH];
	int mounted = 0, modeOfOperation;
	//TODO: 
	BOOL bCacheInDriver = FALSE;

	bPrebootPasswordDlgMode = mountOptions.PartitionInInactiveSysEncScope;

	//if (nDosDriveNo == 0)
	//	nDosDriveNo = HIWORD (GetSelectedLong (GetDlgItem (hwndDlg, IDC_DRIVELIST))) - 'A';

	//if (!MultipleMountOperationInProgress)
	//	VolumePassword.Length = 0;

	if (szFileName == NULL)
	{
		//TODO: Error
	}

	if (strlen(szFileName) == 0)
	{
		status = FALSE;
		goto ret;
	}

	if (IsMountedVolume (szFileName))
	{
		//TODO: Error
		//Warning ("VOL_ALREADY_MOUNTED");
		status = FALSE;
		goto ret;
	}

	if (!VolumePathExists (szFileName))
	{
		if (!MultipleMountOperationInProgress)
			handleWin32Error ();

		status = FALSE;
		goto ret;
	}

	ResetWrongPwdRetryCount ();

	// First try cached passwords and if they fail ask user for a new one
	//WaitCursor ();

	mounted = MountVolume (nDosDriveNo, szFileName, NULL, bCacheInDriver, bForceMount, &mountOptions, FALSE, TRUE);

	//TODO: keyfiles support
	// If keyfiles are enabled, test empty password first
	//if (!mounted && KeyFilesEnable && FirstKeyFile)
	//{
	//	Password emptyPassword;
	//	emptyPassword.Length = 0;

	//	KeyFilesApply (&emptyPassword, FirstKeyFile);
	//	mounted = MountVolume (hwndDlg, nDosDriveNo, szFileName, &emptyPassword, bCacheInDriver, bForceMount, &mountOptions, Silent, FALSE);

	//	burn (&emptyPassword, sizeof (emptyPassword));
	//}

	// Test password and/or keyfiles used for the previous volume
	if (!mounted && MultipleMountOperationInProgress && VolumePassword.Length != 0)
		mounted = MountVolume (nDosDriveNo, szFileName, &VolumePassword, bCacheInDriver, bForceMount, &mountOptions, FALSE, TRUE);

	if (mounted)
	{
		//TODO: Errors
		// Check for deprecated CBC mode
		modeOfOperation = GetModeOfOperationByDriveNo (nDosDriveNo);
		if (modeOfOperation == CBC || modeOfOperation == OUTER_CBC)
			Error("WARN_CBC_MODE");

		// Check for deprecated 64-bit-block ciphers
		if (GetCipherBlockSizeByDriveNo (nDosDriveNo) == 64)
			Error("WARN_64_BIT_BLOCK_CIPHER");

		// Check for problematic file extensions (exe, dll, sys)
		if (CheckFileExtension(szFileName))
			Error("EXE_FILE_EXTENSION_MOUNT_WARNING");
	}

	while (mounted == 0)
	{
		if (CmdVolumePassword.Length > 0)
		{
			VolumePassword = CmdVolumePassword;
		}
		else if (!Silent)
		{
			//TODO:
			//strcpy (PasswordDlgVolume, szFileName);

			//if (!AskVolumePassword (hwndDlg, &VolumePassword, NULL, TRUE))
			//	goto ret;
		}

		//WaitCursor ();

		//TODO: Keyfiles support
		//if (KeyFilesEnable)
		//	KeyFilesApply (&VolumePassword, FirstKeyFile);

		mounted = MountVolume (nDosDriveNo, szFileName, &VolumePassword, bCacheInDriver, bForceMount, &mountOptions, TRUE, TRUE);
		//NormalCursor ();

		// Check for deprecated CBC mode
		modeOfOperation = GetModeOfOperationByDriveNo (nDosDriveNo);
		if (modeOfOperation == CBC || modeOfOperation == OUTER_CBC)
			Error("WARN_CBC_MODE");

		// Check for deprecated 64-bit-block ciphers
		if (GetCipherBlockSizeByDriveNo (nDosDriveNo) == 64)
			Error("WARN_64_BIT_BLOCK_CIPHER");

		//TODO:
		// Check for legacy non-ASCII passwords
		//if (mounted > 0 && !KeyFilesEnable && !CheckPasswordCharEncoding (NULL, &VolumePassword))
		//	Error("UNSUPPORTED_CHARS_IN_PWD_RECOM");

		// Check for problematic file extensions (exe, dll, sys)
		if (mounted > 0 && CheckFileExtension (szFileName))
			Error("EXE_FILE_EXTENSION_MOUNT_WARNING");

		if (!MultipleMountOperationInProgress)
			burn (&VolumePassword, sizeof (VolumePassword));

		burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));

		if (CmdVolumePassword.Length > 0 || Silent)
			break;
	}

	if (mounted > 0)
	{
		status = TRUE;

		//TODO:
		//if (mountOptions.ProtectHiddenVolume)
		//	Info ("HIDVOL_PROT_WARN_AFTER_MOUNT");
	}

ret:
	if (!MultipleMountOperationInProgress)
		burn (&VolumePassword, sizeof (VolumePassword));

	burn (&mountOptions.ProtectedHidVolPassword, sizeof (mountOptions.ProtectedHidVolPassword));

	//TODO:
	//RestoreDefaultKeyFilesParam ();

	if (UsePreferences)
		bCacheInDriver = bCacheInDriverDefault;

	//TODO:
	//if (status && CloseSecurityTokenSessionsAfterMount && !MultipleMountOperationInProgress)
	//	SecurityToken::CloseAllSessions();

	return status;
}

BOOL UnmountVolume (HWND hwndDlg, int nDosDriveNo, BOOL forceUnmount)
{
	int result;
	BOOL forced = forceUnmount;
	int dismountMaxRetries = UNMOUNT_MAX_AUTO_RETRIES;

//retry:
	BroadcastDeviceChange (DBT_DEVICEREMOVEPENDING, nDosDriveNo, 0);

	do
	{
		result = DriverUnmountVolume (hwndDlg, nDosDriveNo, forced);

		if (result == ERR_FILES_OPEN)
			Sleep (UNMOUNT_AUTO_RETRY_DELAY);
		else
			break;

	} while (--dismountMaxRetries > 0);

	if (result != 0)
	{
		if (result == ERR_FILES_OPEN && !Silent)
		{
			//TODO:
			//if (IDYES == AskWarnYesNoTopmost ("UNMOUNT_LOCK_FAILED"))
			//{
				//forced = TRUE;
				//goto retry;
			//}

			if (IsOSAtLeast (WIN_7))
			{
				// Undo SHCNE_DRIVEREMOVED
				char root[] = { (char) nDosDriveNo + 'A', ':', '\\', 0 };
				SHChangeNotify (SHCNE_DRIVEADD, SHCNF_PATH, root, NULL);
			}

			return FALSE;
		}

		Error ("UNMOUNT_FAILED");

		return FALSE;
	} 

	BroadcastDeviceChange (DBT_DEVICEREMOVECOMPLETE, nDosDriveNo, 0);

	return TRUE;
}

int DriverUnmountVolume (HWND hwndDlg, int nDosDriveNo, BOOL forced)
{
	UNMOUNT_STRUCT unmount;
	DWORD dwResult;

	BOOL bResult;

	unmount.nDosDriveNo = nDosDriveNo;
	unmount.ignoreOpenFiles = forced;

	bResult = DeviceIoControl (hDriver, TC_IOCTL_DISMOUNT_VOLUME, &unmount,
		sizeof (unmount), &unmount, sizeof (unmount), &dwResult, NULL);

	if (bResult == FALSE)
	{
		handleWin32Error ();
		return 1;
	}

	if (unmount.nReturnCode == ERR_SUCCESS
		&& unmount.HiddenVolumeProtectionTriggered
		&& !VolumeNotificationsList.bHidVolDamagePrevReported [nDosDriveNo])
	{
		//wchar_t msg[4096];

		VolumeNotificationsList.bHidVolDamagePrevReported [nDosDriveNo] = TRUE;
		//swprintf (msg, GetString ("DAMAGE_TO_HIDDEN_VOLUME_PREVENTED"), nDosDriveNo + 'A');
		//SetForegroundWindow (hwndDlg);
		//MessageBoxW (hwndDlg, msg, lpszTitle, MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
	}

	return unmount.nReturnCode;
}