/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#ifndef BOOT_ENCRYPTION_H
#define BOOT_ENCRYPTION_H

#include "Tcdefs.h"
#include "Exception.h"
#include "Volumes.h"
#include "Apidrvr.h"

#ifdef __cplusplus

#include <string>
#include <list>

using namespace std;

namespace TrueCrypt
{
	class File
	{
	public:
		File () : FileOpen (false) { }
		File (string path, bool readOnly = false, bool create = false);
		~File () { Close(); }

		void Close ();
		DWORD Read (byte *buffer, DWORD size);
		void Write (byte *buffer, DWORD size);
		void SeekAt (int64 position);

	protected:
		bool Elevated;
		bool FileOpen;
		uint64 FilePointerPosition;
		HANDLE Handle;
		bool IsDevice;
		string Path;
	};

	class Device : public File
	{
	public:
		Device (string path, bool readOnly = false);
	};

	class Buffer
	{
	public:
		Buffer (size_t size) : DataSize (size)
		{
			DataPtr = new byte[size];
			if (!DataPtr)
				throw bad_alloc();
		}

		~Buffer () { delete[] DataPtr; }
		byte *Ptr () const { return DataPtr; }
		size_t Size () const { return DataSize; }

	protected:
		byte *DataPtr;
		size_t DataSize;
	};

	struct Partition
	{
		string DevicePath;
		PARTITION_INFORMATION Info;
		string MountPoint;
		size_t Number;
		BOOL IsGPT;
		wstring VolumeNameId;
	};

	typedef list <Partition> PartitionList;

#pragma pack (push)
#pragma pack(1)

	struct PartitionEntryMBR
	{
		byte BootIndicator;

		byte StartHead;
		byte StartCylSector;
		byte StartCylinder;

		byte Type;

		byte EndHead;
		byte EndSector;
		byte EndCylinder;

		uint32 StartLBA;
		uint32 SectorCountLBA;
	};

	struct MBR
	{
		byte Code[446];
		PartitionEntryMBR Partitions[4];
		uint16 Signature;
	};

#pragma pack (pop)

	struct SystemDriveConfiguration
	{
		string DeviceKernelPath;
		string DevicePath;
		int DriveNumber;
		Partition DrivePartition;
		bool ExtraBootPartitionPresent;
		int64 InitialUnallocatedSpace;
		PartitionList Partitions;
		Partition SystemPartition;
		int64 TotalUnallocatedSpace;
		bool SystemLoaderPresent;
	};

	class BootEncryption
	{
	public:
		BootEncryption (void);
		~BootEncryption ();

		enum FilterType
		{
			DriveFilter,
			VolumeFilter,
			DumpFilter
		};
		void CallDriver (DWORD ioctl, void *input = nullptr, DWORD inputSize = 0, void *output = nullptr, DWORD outputSize = 0);
		Partition GetPartitionForHiddenOS ();
		void InvalidateCachedSysDriveProperties ();
		SystemDriveConfiguration GetSystemDriveConfiguration ();
		DWORD GetDriverServiceStartType ();
		void SetDriverServiceStartType (DWORD startType);
		void ProbeRealSystemDriveSize ();
		string GetTempPath ();
		uint16 GetInstalledBootLoaderVersion ();
		bool IsBootLoaderOnDrive (char *devicePath);
		BootEncryptionStatus GetStatus ();
		void GetVolumeProperties (VOLUME_PROPERTIES_STRUCT *properties);
		bool IsHiddenSystemRunning ();
		BOOL IsHiddenOSRunning (void);
		bool SystemDriveContainsPartitionType (byte type);
		bool SystemDriveContainsExtendedPartition ();
		bool SystemDriveContainsNonStandardPartitions ();
		bool SystemDriveIsDynamic ();
		bool SystemPartitionCoversWholeDrive ();
		void ReadBootSectorConfig (byte *config, size_t bufLength, byte *userConfig = nullptr, string *customUserMessage = nullptr, uint16 *bootLoaderVersion = nullptr);
		void WriteBootSectorConfig (const byte newConfig[]);
		void WriteBootSectorUserConfig (byte userConfig, const string &customUserMessage);
		unsigned int GetHiddenOSCreationPhase ();
		void SetHiddenOSCreationPhase (unsigned int newPhase);
		void StartDecoyOSWipe (WipeAlgorithmId wipeAlgorithm);
		void AbortDecoyOSWipe ();
		DecoySystemWipeStatus GetDecoyOSWipeStatus ();
		void CheckDecoyOSWipeResult ();
		void WipeHiddenOSCreationConfig ();
		void InstallBootLoader (bool preserveUserConfig = false, bool hiddenOSCreation = false);
		string GetSystemLoaderBackupPath ();
		void RenameDeprecatedSystemLoaderBackup ();
		void CreateRescueIsoImage (bool initialSetup, const string &isoImagePath);
		bool IsCDDrivePresent ();
		bool VerifyRescueDisk ();
		void AbortSetup ();
		void AbortSetupWait ();
		void RegisterFilterDriver (bool registerDriver, FilterType filterType);
		void RegisterSystemFavoritesService (BOOL registerService);
		void SetDriverConfigurationFlag (uint32 flag, bool state);
		void WriteLocalMachineRegistryDwordValue (char *keyPath, char *valueName, DWORD value);
		void CheckRequirements ();
		void CheckRequirementsHiddenOS ();
		void InitialSecurityChecksForHiddenOS ();
		int ChangePassword (Password *oldPassword, Password *newPassword, int pkcs5);
		void CheckEncryptionSetupResult ();
		void RegisterBootDriver (bool hiddenSystem);
		void Install (bool hiddenSystem);
		void Deinstall (bool displayWaitDialog = false);
		void PrepareHiddenOSCreation (int ea, int mode, int pkcs5);
		void PrepareInstallation (bool systemPartitionOnly, Password &password, int ea, int mode, int pkcs5, const string &rescueIsoImagePath);
		bool IsPagingFileActive (BOOL checkNonWindowsPartitionsOnly);
		void RestrictPagingFilesToSystemPartition ();
		void StartDecryption (BOOL discardUnreadableEncryptedSectors);
		void StartEncryption (WipeAlgorithmId wipeAlgorithm, bool zeroUnreadableSectors);
		void CopyFileAdmin (const string &sourceFile, const string &destinationFile);
		void DeleteFileAdmin (const string &file);
		void WriteBootDriveSector (uint64 offset, byte *data);
		bool RestartComputer (void);

	protected:
		static const uint32 RescueIsoImageSize = 1835008; // Size of ISO9660 image with bootable emulated 1.44MB floppy disk image
		PartitionList GetDrivePartitions (int driveNumber);
		string GetWindowsDirectory ();
		wstring GetRemarksOnHiddenOS ();
		DISK_GEOMETRY GetDriveGeometry (int driveNumber);
		uint32 GetChecksum (byte *data, size_t size);
		void CreateBootLoaderInMemory (byte *buffer, size_t bufferSize, bool rescueDisk, bool hiddenOSCreation = false);
		void CreateVolumeHeader (uint64 volumeSize, uint64 encryptedAreaStart, Password *password, int ea, int mode, int pkcs5);
		void InstallVolumeHeader ();
		void BackupSystemLoader ();
		void RestoreSystemLoader ();
		void RegisterFilter (bool registerFilter, FilterType filterType, const GUID *deviceClassGuid = nullptr);


		SystemDriveConfiguration DriveConfig;
		int SelectedEncryptionAlgorithmId;
		Partition HiddenOSCandidatePartition;
		byte *RescueIsoImage;
		byte RescueVolumeHeader[TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE];
		byte VolumeHeader[TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE];
		bool DriveConfigValid;
		bool RealSystemDriveSizeValid;
		bool RescueVolumeHeaderValid;
		bool VolumeHeaderValid;
	};

#define TC_ABORT_TRANSFORM_WAIT_INTERVAL	10

#define MIN_HIDDENOS_DECOY_PARTITION_SIZE_RATIO_NTFS	2.1
#define MIN_HIDDENOS_DECOY_PARTITION_SIZE_RATIO_FAT		1.05

#define TC_SYS_BOOT_LOADER_BACKUP_NAME			"Original System Loader"
#define TC_SYS_BOOT_LOADER_BACKUP_NAME_LEGACY	"Original System Loader.bak"	// Deprecated to prevent removal by some "cleaners"

#define TC_SYSTEM_FAVORITES_SERVICE_NAME				TC_APP_NAME "SystemFavorites"
#define	TC_SYSTEM_FAVORITES_SERVICE_LOAD_ORDER_GROUP	"Event Log"
#define TC_SYSTEM_FAVORITES_SERVICE_CMDLINE_OPTION		"/systemFavoritesService"

}

#endif

#endif