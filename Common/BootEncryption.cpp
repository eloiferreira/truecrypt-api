/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#include "BootEncryption.h"
#include "Uac.h"
#include "Apidrvr.h"
#include "OsInfo.h"
#include "Platform/PlatformBase.h"
#include "Platform/ForEach.h"
#include "Platform/Finally.h"
#include <Windows.h>
#include <io.h>
#include "Strings.h"
#include "boot/Windows/BootCommon.h"

namespace TrueCrypt
{
	 /* NN: TrueCrypt impements COM-based elevation in order to perform privileged
	 functions. Although this dll strives to perform most of these functions as well,
	 elevation of execution level is left upon controlling application. This decision 
	 is based on following reasoning:
	 1. While COM-based is the most flexible elevation approach and TC rightly uses it 
	 for elevation on demand, this dll might be used both in "completely administrative" 
	 and per-function elevating apllications so it should not impose its ways on the
	 developer.
	 2. There is little dll-specific uac-related documentation in MSDN and most 
	 reasonable conclusion from available information is that it's exe's responsibility
	 to handle uac whether through manifest or programmatically using COM or ShellExecute.
	 3. The fact that exactly the same code is called before and after elevation 
	 makes its separation from elevation itself quite appropriate. */

#define SRC_POS (__FUNCTION__ ":" TC_TO_STRING(__LINE__))

	File::File (string path, bool readOnly, bool create) : Elevated (false), FileOpen (false)
	{
		Handle = CreateFile (path.c_str(),
			readOnly ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, create ? CREATE_ALWAYS : OPEN_EXISTING,
			FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_WRITE_THROUGH, NULL);

		if (Handle == INVALID_HANDLE_VALUE) {
			handle_win_error;
			throw_sys_if(true);
		}

		FileOpen = true;
		FilePointerPosition = 0;
		IsDevice = false;
		Path = path;
	}

	void File::Close ()
	{
		if (FileOpen)
		{
			CloseHandle (Handle);
			FileOpen = false;
		}
	}

	DWORD File::Read (byte *buffer, DWORD size)
	{
		DWORD bytesRead;

		if (!ReadFile (Handle, buffer, size, &bytesRead, NULL)) {
			handle_win_error;
			throw_sys_if(true);
		}
		//FilePointerPosition += bytesRead;
		return bytesRead;
	}

	void File::SeekAt (int64 position)
	{
		FilePointerPosition = position;

		LARGE_INTEGER pos;
		pos.QuadPart = position;
		if (!SetFilePointerEx (Handle, pos, NULL, FILE_BEGIN)) {
			handle_win_error;
			throw_sys_if(true);
		}
	}
	
	void File::Write (byte *buffer, DWORD size)
	{
		DWORD bytesWritten;

		try
		{
			if (!WriteFile (Handle, buffer, size, &bytesWritten, NULL) || bytesWritten != size) {
				handle_win_error;
				throw_sys_if(true);
			}
			//FilePointerPosition += bytesWritten;
		}
		catch (SystemException &e)
		{
			if (!IsDevice || e.ErrorCode != ERROR_WRITE_PROTECT)
				throw;

			BootEncryption bootEnc = BootEncryption();

			while (size >= TC_SECTOR_SIZE_BIOS)
			{
				//bootEnc.WriteBootDriveSector (FilePointerPosition, buffer);

				FilePointerPosition += TC_SECTOR_SIZE_BIOS;
				buffer += TC_SECTOR_SIZE_BIOS;
				size -= TC_SECTOR_SIZE_BIOS;
			}
		}
	}

	Device::Device (string path, bool readOnly)
	{
		FileOpen = false;
		Elevated = false;

		Handle = CreateFile ((string ("\\\\.\\") + path).c_str(),
			readOnly ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
			FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_WRITE_THROUGH, NULL);

		if (Handle == INVALID_HANDLE_VALUE) {
			handle_win_error;
			throw_sys_if(true);
		}

		FileOpen = true;
		FilePointerPosition = 0;
		IsDevice = true;
		Path = path;
	}

	BootEncryption::BootEncryption (void)
		: DriveConfigValid (false),
		RealSystemDriveSizeValid (false),
		RescueIsoImage (nullptr),
		RescueVolumeHeaderValid (false),
		SelectedEncryptionAlgorithmId (0),
		VolumeHeaderValid (false)
	{
	}

	BootEncryption::~BootEncryption ()
	{
		if (RescueIsoImage)
			delete[] RescueIsoImage;
	}

	void BootEncryption::CallDriver (DWORD ioctl, void *input, DWORD inputSize, void *output, DWORD outputSize)
	{
		DWORD bytesReturned;
		
		if (!DeviceIoControl (hDriver, ioctl, input, inputSize, output, outputSize, &bytesReturned, NULL)) {
			handle_win_error;
			throw_sys_if(true);
		}
	}

	void BootEncryption::InvalidateCachedSysDriveProperties ()
	{
		DriveConfigValid = false;
		RealSystemDriveSizeValid = false;
	}

	PartitionList BootEncryption::GetDrivePartitions (int driveNumber)
	{
		PartitionList partList;

		for (int partNumber = 0; partNumber < 64; ++partNumber)
		{
			stringstream partPath;
			partPath << "\\Device\\Harddisk" << driveNumber << "\\Partition" << partNumber;

			DISK_PARTITION_INFO_STRUCT diskPartInfo;
			_snwprintf (diskPartInfo.deviceName, array_capacity (diskPartInfo.deviceName), L"%hs", partPath.str().c_str());

			try
			{
				CallDriver (TC_IOCTL_GET_DRIVE_PARTITION_INFO, &diskPartInfo, sizeof (diskPartInfo), &diskPartInfo, sizeof (diskPartInfo));
			}
			catch (...)
			{
				continue;
			}

			Partition part;
			part.DevicePath = partPath.str();
			part.Number = partNumber;
			part.Info = diskPartInfo.partInfo;
			part.IsGPT = diskPartInfo.IsGPT;

			// Mount point
			wstringstream ws;
			ws << partPath.str().c_str();
			int driveNumber = GetDiskDeviceDriveLetter ((wchar_t *) ws.str().c_str());

			if (driveNumber >= 0)
			{
				part.MountPoint += (char) (driveNumber + 'A');
				part.MountPoint += ":";
			}

			// Volume ID
			wchar_t volumePath[TC_MAX_PATH];
			if (ResolveSymbolicLink ((wchar_t *) ws.str().c_str(), volumePath))
			{
				wchar_t volumeName[TC_MAX_PATH];
				HANDLE fh = FindFirstVolumeW (volumeName, array_capacity (volumeName));
				if (fh != INVALID_HANDLE_VALUE)
				{
					do
					{
						wstring volumeNameStr = volumeName;
						wchar_t devicePath[TC_MAX_PATH];

						if (QueryDosDeviceW (volumeNameStr.substr (4, volumeNameStr.size() - 1 - 4).c_str(), devicePath, array_capacity (devicePath)) != 0
							&& wcscmp (volumePath, devicePath) == 0)
						{
							part.VolumeNameId = volumeName;
							break;
						}

					} while (FindNextVolumeW (fh, volumeName, array_capacity (volumeName)));

					FindVolumeClose (fh);
				}
			}

			partList.push_back (part);
		}

		return partList;
	}

	string BootEncryption::GetWindowsDirectory ()
	{
		char buf[MAX_PATH];
		throw_sys_if (GetSystemDirectory (buf, sizeof (buf)) == 0);

		return string (buf);
	}

	SystemDriveConfiguration BootEncryption::GetSystemDriveConfiguration ()
	{
		if (DriveConfigValid)
			return DriveConfig;

		SystemDriveConfiguration config;

		string winDir = GetWindowsDirectory();

		// Scan all drives
		for (int driveNumber = 0; driveNumber < 32; ++driveNumber)
		{
			bool windowsFound = false;
			bool activePartitionFound = false;
			config.ExtraBootPartitionPresent = false;
			config.SystemLoaderPresent = false;

			PartitionList partitions = GetDrivePartitions (driveNumber);
			foreach (const Partition &part, partitions)
			{
				if (!part.MountPoint.empty()
					&& (_access ((part.MountPoint + "\\bootmgr").c_str(), 0) == 0 || _access ((part.MountPoint + "\\ntldr").c_str(), 0) == 0))
				{
					config.SystemLoaderPresent = true;
				}
				else if (!part.VolumeNameId.empty()
					&& (_waccess ((part.VolumeNameId + L"\\bootmgr").c_str(), 0) == 0 || _waccess ((part.VolumeNameId + L"\\ntldr").c_str(), 0) == 0))
				{
					config.SystemLoaderPresent = true;
				}

				if (!windowsFound && !part.MountPoint.empty() && ToUpperCase (winDir).find (ToUpperCase (part.MountPoint)) == 0)
				{
					config.SystemPartition = part;
					windowsFound = true;
				}

				if (!activePartitionFound && part.Info.BootIndicator)
				{
					activePartitionFound = true;

					if (part.Info.PartitionLength.QuadPart > 0 && part.Info.PartitionLength.QuadPart <= TC_MAX_EXTRA_BOOT_PARTITION_SIZE)
						config.ExtraBootPartitionPresent = true;
				}
			}

			if (windowsFound)
			{
				config.DriveNumber = driveNumber;

				stringstream ss;
				ss << "PhysicalDrive" << driveNumber;
				config.DevicePath = ss.str();

				stringstream kernelPath;
				kernelPath << "\\Device\\Harddisk" << driveNumber << "\\Partition0";
				config.DeviceKernelPath = kernelPath.str();

				config.DrivePartition = partitions.front();
				partitions.pop_front();
				config.Partitions = partitions;

				config.InitialUnallocatedSpace = 0x7fffFFFFffffFFFFull;
				config.TotalUnallocatedSpace = config.DrivePartition.Info.PartitionLength.QuadPart;

				foreach (const Partition &part, config.Partitions)
				{
					if (part.Info.StartingOffset.QuadPart < config.InitialUnallocatedSpace)
						config.InitialUnallocatedSpace = part.Info.StartingOffset.QuadPart;

					config.TotalUnallocatedSpace -= part.Info.PartitionLength.QuadPart;
				}

				DriveConfig = config;
				DriveConfigValid = true;
				return DriveConfig;
			}
		}

		throw ParameterIncorrect (SRC_POS);
	}

	wstring BootEncryption::GetRemarksOnHiddenOS ()
	{
		return (wstring (L"\n\n \
						  TWO_SYSTEMS_IN_ONE_PARTITION_REMARK\
						  \n\n\
						  FOR_MORE_INFO_ON_PARTITIONS"));
	}

	// Finds the first partition physically located behind the active one and returns its properties
	Partition BootEncryption::GetPartitionForHiddenOS ()
	{
		Partition candidatePartition;

		memset (&candidatePartition, 0, sizeof(candidatePartition));

		// The user may have modified/added/deleted partitions since the time the partition table was last scanned
		InvalidateCachedSysDriveProperties();

		SystemDriveConfiguration config = GetSystemDriveConfiguration ();
		bool activePartitionFound = false;
		bool candidateForHiddenOSFound = false;

		if (config.SystemPartition.IsGPT)
			throw ParameterIncorrect (SRC_POS);	// It is assumed that CheckRequirements() had been called

		// Find the first active partition on the system drive 
		foreach (const Partition &partition, config.Partitions)
		{
			if (partition.Info.BootIndicator)
			{
				if (partition.Info.PartitionNumber != config.SystemPartition.Number)
				{
					// If there is an extra boot partition, the system partition must be located right behind it
					if (IsOSAtLeast (WIN_7) && config.ExtraBootPartitionPresent)
					{
						int64 minOffsetFound = config.DrivePartition.Info.PartitionLength.QuadPart;
						Partition bootPartition = partition;
						Partition partitionBehindBoot;

						foreach (const Partition &partition, config.Partitions)
						{
							if (partition.Info.StartingOffset.QuadPart > bootPartition.Info.StartingOffset.QuadPart
								&& partition.Info.StartingOffset.QuadPart < minOffsetFound)
							{
								minOffsetFound = partition.Info.StartingOffset.QuadPart;
								partitionBehindBoot = partition;
							}
						}

						if (minOffsetFound != config.DrivePartition.Info.PartitionLength.QuadPart
							&& partitionBehindBoot.Number == config.SystemPartition.Number)
						{
							activePartitionFound = true;
							break;
						}
					}

					//TODO:
					throw ErrorException (/*wstring ("SYSTEM_PARTITION_NOT_ACTIVE") + GetRemarksOnHiddenOS()*/);
				}

				activePartitionFound = true;
				break;
			}
		}

		/* WARNING: Note that the partition number at the end of a device path (\Device\HarddiskY\PartitionX) must
		NOT be used to find the first partition physically located behind the active one. The reason is that the 
		user may have deleted and created partitions during this session and e.g. the second partition could have 
		a higer number than the third one. */

		
		// Find the first partition physically located behind the active partition
		if (activePartitionFound)
		{
			int64 minOffsetFound = config.DrivePartition.Info.PartitionLength.QuadPart;

			foreach (const Partition &partition, config.Partitions)
			{
				if (partition.Info.StartingOffset.QuadPart > config.SystemPartition.Info.StartingOffset.QuadPart
					&& partition.Info.StartingOffset.QuadPart < minOffsetFound)
				{
					minOffsetFound = partition.Info.StartingOffset.QuadPart;

					candidatePartition = partition;

					candidateForHiddenOSFound = true;
				}
			}

			if (!candidateForHiddenOSFound)
			{
				//TODO:
				throw ErrorException (/* wstring (GetString ("NO_PARTITION_FOLLOWS_BOOT_PARTITION")) + GetRemarksOnHiddenOS() */);
			}

			if (config.SystemPartition.Info.PartitionLength.QuadPart > TC_MAX_FAT_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS)
			{
				if ((double) candidatePartition.Info.PartitionLength.QuadPart / config.SystemPartition.Info.PartitionLength.QuadPart < MIN_HIDDENOS_DECOY_PARTITION_SIZE_RATIO_NTFS)
				{
					//TODO:
					throw ErrorException (/* wstring (GetString ("PARTITION_TOO_SMALL_FOR_HIDDEN_OS_NTFS")) + GetRemarksOnHiddenOS() */);
				}
			}
			else if ((double) candidatePartition.Info.PartitionLength.QuadPart / config.SystemPartition.Info.PartitionLength.QuadPart < MIN_HIDDENOS_DECOY_PARTITION_SIZE_RATIO_FAT)
			{
				throw ErrorException (/* wstring (GetString ("PARTITION_TOO_SMALL_FOR_HIDDEN_OS")) + GetRemarksOnHiddenOS() */);
			}
		}
		else
		{
			// No active partition on the system drive
			//TODO:
			throw ErrorException (/* "SYSTEM_PARTITION_NOT_ACTIVE" */);
		}

		HiddenOSCandidatePartition = candidatePartition;
		return candidatePartition;
	}}