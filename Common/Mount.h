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
#include <string>
#include <vector>
#include "BootEncryption.h"

#ifdef __cplusplus

extern "C" {
#endif

	// After the user receives the "Incorrect password" error this number of times in a row, we should automatically
	// try using the embedded header backup (if any). This ensures that the "Incorrect password" message is reported faster
	// initially (most such errors are really caused by supplying an incorrect password, not by header corruption).
#define TC_TRY_HEADER_BAK_AFTER_NBR_WRONG_PWD_TRIES		2
#define UNMOUNT_MAX_AUTO_RETRIES 30
#define UNMOUNT_AUTO_RETRY_DELAY 50

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

	struct HostDevice
	{
		HostDevice ()
			:
		Bootable (false),
			ContainsSystem (false),
			DynamicVolume (false),
			Floppy (false),
			IsPartition (false),
			IsVirtualPartition (false),
			HasUnencryptedFilesystem (false),
			Removable (false),
			Size (0)
		{
		}

		~HostDevice () { }

		bool Bootable;
		bool ContainsSystem;
		bool DynamicVolume;
		bool Floppy;
		bool IsPartition;
		bool IsVirtualPartition;
		bool HasUnencryptedFilesystem;
		std::string MountPoint;
		std::wstring Name;
		std::string Path;
		bool Removable;
		uint64 Size;
		uint32 SystemNumber;

		std::vector <HostDevice> Partitions;
	};

	extern MountOptions mountOptions;
	extern MountOptions defaultMountOptions;

	typedef struct
	{
		BOOL bHidVolDamagePrevReported[26];
	} VOLUME_NOTIFICATIONS_LIST;

	extern VOLUME_NOTIFICATIONS_LIST VolumeNotificationsList;

	BOOL IsMountedVolume (const char *volname);
	BOOL VolumePathExists (char *volumePath);
	BOOL OpenDevice (const char *lpszPath, OPEN_TEST_STRUCT *driver, BOOL detectFilesystem);
	void IncreaseWrongPwdRetryCount (int count);
	void ResetWrongPwdRetryCount (void);
	BOOL GetSysDevicePaths (void);
	int IsSystemDevicePath (char *path, BOOL bReliableRequired);
	BOOL CheckSysEncMountWithoutPBA (const char *devicePath);
	BOOL IsDriveAvailable (int driveNo);
	BOOL IsPasswordCacheEmpty (void);
	BOOL WrongPwdRetryCountOverLimit (void);
	void CheckFilesystem (int driveNo, BOOL fixErrors);
	int MountVolume (int driveNo, char *volumePath, Password *password, BOOL cachePassword, BOOL sharedAccess, const MountOptions* const mountOptions, BOOL bReportWrongPassword, BOOL bRetryIfInUse);
	void BroadcastDeviceChange (WPARAM message, int nDosDriveNo, DWORD driveMap);
	BOOL CheckFileExtension (char *fileName);
	int GetModeOfOperationByDriveNo (int nDosDriveNo);
	int GetCipherBlockSizeByDriveNo (int nDosDriveNo);
	BOOL Mount (HWND hwndDlg, int nDosDriveNo, char *szFileName, Password VolumePassword);
	BOOL GetDriveLabel (int driveNo, wchar_t *label, int labelSize);
	char GetSystemDriveLetter (void);
	BOOL GetDeviceInfo (const char *deviceName, DISK_PARTITION_INFO_STRUCT *info);
	BOOL UnmountVolume (HWND hwndDlg, int nDosDriveNo, BOOL forceUnmount);
	int DriverUnmountVolume (HWND hwndDlg, int nDosDriveNo, BOOL forced);

#ifdef __cplusplus
}

std::string VolumeGuidPathToDevicePath (std::string volumeGuidPath);
std::string HarddiskVolumePathToPartitionPath (const std::string &harddiskVolumePath);
std::vector <HostDevice> GetAvailableHostDevices (bool noDeviceProperties = false, bool singleList = false, bool noFloppy = true, bool detectUnencryptedFilesystems = false);

#endif

#endif