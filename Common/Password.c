/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#include "Tcdefs.h"

#include "Crypto.h"
#include "Volumes.h"
#include "Password.h"
#include "Pkcs5.h"
#include "Endian.h"
#include "Random.h"
#include "Options.h"
#include "Uac.h"
#include "Errors.h"

#include <io.h>

BOOL IsPageLocked(LPVOID pRef, SIZE_T dwSize) {

	int res = VirtualUnlock(pRef, dwSize);
	if (res == 0) {
		int err = GetLastError();
		if (err == ERROR_NOT_LOCKED) {
			SetLastError(TCAPI_E_PAGE_NOT_LOCKED);
			return FALSE;
		}
	}
	if (!VirtualLock(pRef, dwSize)) {
		//TODO: might supply original GetLastError() value for debug here
		SetLastError(TCAPI_E_PAGE_CANT_LOCK);
		return FALSE;
	}
	return TRUE;
}

BOOL ValidatePassword(const char *szPassword, const char *szVerify, BOOL keyFilesEnabled) {
	/* TrueCrypt tries to make password handling more secure through using locked VM pages and 
	not making any text copies other than in stack with subsequent burn. We here are in a dll so 
	we dont know where the password came from and how securely its handled by the application.
	We can impose a requirement to pass the password here on a locked page and check if it's indeed 
	locked. At least this would require some effort on behalf of developer and might also keep him 
	from unnecessarily multiplying copies of the password. Since I couldn't find a straight way 
	to check if a page is locked from user mode (a driver can check for MDL_PAGES_LOCKED), here is 
	a feeble attempt to infer it while unlocking, which removes the page from working set and it 
	*might* theoretically get paged before we lock it again. This is completely speculative though.
	Perhaps more appropriate way would be to provide an AllocatePassword routine which does it the 
	right way so the user wouldn't have to care about the details. */

	int lenPass, lenVerify = 0;

	lenPass = strlen(szPassword);
	lenVerify = strlen(szVerify);

	if (!IsPageLocked((LPVOID)szPassword, lenPass) || !IsPageLocked((LPVOID)szVerify, lenVerify)) {
		//TODO: DOC -> See GetLastError()
		return FALSE;
	}

	if (lenPass != lenVerify) {
		SetLastError(TCAPI_E_PASS_LENGTH_NOT_EQUAL);
		return FALSE;
	}

	if ((lenPass < MIN_PASSWORD) && !keyFilesEnabled) {
		SetLastError(TCAPI_E_PASS_TOO_SHORT);
		return FALSE;
	}

	if (strcmp(szPassword, szVerify) != 0) {
		SetLastError(TCAPI_E_PASS_NOT_EQUAL);
		return FALSE;
	}

	if (lenPass < PASSWORD_LEN_WARNING) {
		SetLastError(TCAPI_W_WEAK_PASSWORD);
		//TODO: DOC -> Check GetLastError in either case
		return FALSE;
	}

	return TRUE;
}

BOOL CheckPasswordCharEncoding (HWND hPassword, Password *ptrPw)
{
	int i, len = 0;
	
	if (hPassword == NULL)
	{
		unsigned char *pw;
		len = ptrPw->Length;
		pw = (unsigned char *) ptrPw->Text;

		for (i = 0; i < len; i++)
		{
			if (pw[i] >= 0x7f || pw[i] < 0x20)	// A non-ASCII or non-printable character?
				return FALSE;
		}
	}
	else
	{
		wchar_t s[MAX_PASSWORD + 1];
		//TODO:
		//len = GetWindowTextLength (hPassword);

		if (len > MAX_PASSWORD)
			return FALSE; 

		//TODO:
		//GetWindowTextW (hPassword, s, sizeof (s) / sizeof (wchar_t));

		for (i = 0; i < len; i++)
		{
			if (s[i] >= 0x7f || s[i] < 0x20)	// A non-ASCII or non-printable character?
				break;
		}

		burn (s, sizeof(s));

		if (i < len)
			return FALSE; 
	}

	return TRUE;
}

int ChangePwd (char *lpszVolume, Password *oldPassword, Password *newPassword, int pkcs5, HWND hwndDlg)
{
	int nDosLinkCreated = 1, nStatus = ERR_OS_ERROR;
	char szDiskFile[TC_MAX_PATH], szCFDevice[TC_MAX_PATH];
	char szDosDevice[TC_MAX_PATH];
	char buffer[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
	PCRYPTO_INFO cryptoInfo = NULL, ci = NULL;
	void *dev = INVALID_HANDLE_VALUE;
	DWORD dwError;
	DWORD bytesRead;
	BOOL bDevice;
	unsigned __int64 hostSize = 0;
	int volumeType;
	int wipePass;
	FILETIME ftCreationTime;
	FILETIME ftLastWriteTime;
	FILETIME ftLastAccessTime;
	BOOL bTimeStampValid = FALSE;
	LARGE_INTEGER headerOffset;
	BOOL backupHeader;
	DISK_GEOMETRY driveInfo;

	if (oldPassword->Length == 0 || newPassword->Length == 0) return -1;

	CreateFullVolumePath (szDiskFile, lpszVolume, &bDevice);

	if (bDevice == FALSE)
	{
		strcpy (szCFDevice, szDiskFile);
	}
	else
	{
		nDosLinkCreated = FakeDosNameForDevice (szDiskFile, szDosDevice, szCFDevice, FALSE);
		
		if (nDosLinkCreated != 0)
			goto error;
	}

	dev = CreateFile (szCFDevice, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (dev == INVALID_HANDLE_VALUE) 
		goto error;

	if (bDevice)
	{
		/* This is necessary to determine the hidden volume header offset */

		PARTITION_INFORMATION diskInfo;
		DWORD dwResult;
		BOOL bResult;

		bResult = DeviceIoControl (dev, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
			&driveInfo, sizeof (driveInfo), &dwResult, NULL);

		if (!bResult)
			goto error;

		bResult = GetPartitionInfo (lpszVolume, &diskInfo);

		if (bResult)
		{
			hostSize = diskInfo.PartitionLength.QuadPart;
		}
		else
		{
			hostSize = driveInfo.Cylinders.QuadPart * driveInfo.BytesPerSector *
				driveInfo.SectorsPerTrack * driveInfo.TracksPerCylinder;
		}

		if (hostSize == 0)
		{
			nStatus = ERR_VOL_SIZE_WRONG;
			goto error;
		}
	}
	else
	{
		LARGE_INTEGER fileSize;
		if (!GetFileSizeEx (dev, &fileSize))
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		hostSize = fileSize.QuadPart;
	}

	if (Randinit ())
		goto error;

	if (!bDevice && bPreserveTimestamp)
	{
		if (GetFileTime ((HANDLE) dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime) == 0)
			bTimeStampValid = FALSE;
		else
			bTimeStampValid = TRUE;
	}

	for (volumeType = TC_VOLUME_TYPE_NORMAL; volumeType < TC_VOLUME_TYPE_COUNT; volumeType++)
	{
		// Seek the volume header
		switch (volumeType)
		{
		case TC_VOLUME_TYPE_NORMAL:
			headerOffset.QuadPart = TC_VOLUME_HEADER_OFFSET;
			break;

		case TC_VOLUME_TYPE_HIDDEN:
			if (TC_HIDDEN_VOLUME_HEADER_OFFSET + TC_VOLUME_HEADER_SIZE > hostSize)
				continue;

			headerOffset.QuadPart = TC_HIDDEN_VOLUME_HEADER_OFFSET;
			break;

		case TC_VOLUME_TYPE_HIDDEN_LEGACY:
			if (bDevice && driveInfo.BytesPerSector != TC_SECTOR_SIZE_LEGACY)
				continue;

			headerOffset.QuadPart = hostSize - TC_HIDDEN_VOLUME_HEADER_OFFSET_LEGACY;
			break;
		}

		if (!SetFilePointerEx ((HANDLE) dev, headerOffset, NULL, FILE_BEGIN))
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		/* Read in volume header */
		if (!ReadEffectiveVolumeHeader (bDevice, dev, (byte *)buffer, &bytesRead))
		{
			nStatus = ERR_OS_ERROR;
			goto error;
		}

		if (bytesRead != sizeof (buffer))
		{
			// Windows may report EOF when reading sectors from the last cluster of a device formatted as NTFS 
			memset (buffer, 0, sizeof (buffer));
		}

		/* Try to decrypt the header */

		nStatus = ReadVolumeHeader (FALSE, buffer, oldPassword, &cryptoInfo, NULL);
		if (nStatus == ERR_CIPHER_INIT_WEAK_KEY)
			nStatus = 0;	// We can ignore this error here

		if (nStatus == ERR_PASSWORD_WRONG)
		{
			continue;		// Try next volume type
		}
		else if (nStatus != 0)
		{
			cryptoInfo = NULL;
			goto error;
		}
		else 
			break;
	}

	if (nStatus != 0)
	{
		cryptoInfo = NULL;
		goto error;
	}

	if (cryptoInfo->HeaderFlags & TC_HEADER_FLAG_ENCRYPTED_SYSTEM)
	{
		nStatus = ERR_SYS_HIDVOL_HEAD_REENC_MODE_WRONG;
		goto error;
	}

	// Change the PKCS-5 PRF if requested by user
	if (pkcs5 != 0)
		cryptoInfo->pkcs5 = pkcs5;

	RandSetHashFunction (cryptoInfo->pkcs5);

	UserEnrichRandomPool (hwndDlg);

	/* Re-encrypt the volume header */ 
	backupHeader = FALSE;

	while (TRUE)
	{
		/* The header will be re-encrypted PRAND_DISK_WIPE_PASSES times to prevent adversaries from using 
		techniques such as magnetic force microscopy or magnetic force scanning tunnelling microscopy
		to recover the overwritten header. According to Peter Gutmann, data should be overwritten 22
		times (ideally, 35 times) using non-random patterns and pseudorandom data. However, as users might
		impatiently interupt the process (etc.) we will not use the Gutmann's patterns but will write the
		valid re-encrypted header, i.e. pseudorandom data, and there will be many more passes than Guttman
		recommends. During each pass we will write a valid working header. Each pass will use the same master
		key, and also the same header key, secondary key (XTS), etc., derived from the new password. The only
		item that will be different for each pass will be the salt. This is sufficient to cause each "version"
		of the header to differ substantially and in a random manner from the versions written during the
		other passes. */

		/* NN: Gutmann specifically says here: http://www.cs.auckland.ac.nz/~pgut001/pubs/secure_del.html#Epilogue 
		that 35 times in reality is never needed, and, most importantly, current high-density technology
		on disk hdd media would not reallistically allow to recover any data even after only 'a few passes of 
		random scrubbing' rewrites. Flash media, SSD drives are whole another story. Here is another his 
		article on this topic: http://www.cypherpunks.to/~peter/usenix01.pdf. This said not to diminish 
		TrueCrypt effort to practice most stringent approach on security, but just to keep in mind a correct 
		perspective on the topic. */

		for (wipePass = 0; wipePass < PRAND_DISK_WIPE_PASSES; wipePass++)
		{
			// Prepare new volume header
			nStatus = CreateVolumeHeaderInMemory (FALSE,
				buffer,
				cryptoInfo->ea,
				cryptoInfo->mode,
				newPassword,
				cryptoInfo->pkcs5,
				(char *)cryptoInfo->master_keydata,
				&ci,
				cryptoInfo->VolumeSize.Value,
				(volumeType == TC_VOLUME_TYPE_HIDDEN || volumeType == TC_VOLUME_TYPE_HIDDEN_LEGACY) ? cryptoInfo->hiddenVolumeSize : 0,
				cryptoInfo->EncryptedAreaStart.Value,
				cryptoInfo->EncryptedAreaLength.Value,
				cryptoInfo->RequiredProgramVersion,
				cryptoInfo->HeaderFlags,
				cryptoInfo->SectorSize,
				wipePass < PRAND_DISK_WIPE_PASSES - 1);

			if (ci != NULL)
				crypto_close (ci);

			if (nStatus != 0)
				goto error;

			if (!SetFilePointerEx ((HANDLE) dev, headerOffset, NULL, FILE_BEGIN))
			{
				nStatus = ERR_OS_ERROR;
				goto error;
			}

			if (!WriteEffectiveVolumeHeader (bDevice, dev, (byte *)buffer))
			{
				nStatus = ERR_OS_ERROR;
				goto error;
			}

			if (bDevice
				&& !cryptoInfo->LegacyVolume
				&& !cryptoInfo->hiddenVolume
				&& cryptoInfo->HeaderVersion == 4
				&& (cryptoInfo->HeaderFlags & TC_HEADER_FLAG_NONSYS_INPLACE_ENC) != 0
				&& (cryptoInfo->HeaderFlags & ~TC_HEADER_FLAG_NONSYS_INPLACE_ENC) == 0)
			{
				nStatus = WriteRandomDataToReservedHeaderAreas (dev, cryptoInfo, cryptoInfo->VolumeSize.Value, !backupHeader, backupHeader);
				if (nStatus != ERR_SUCCESS)
					goto error;
			}

			FlushFileBuffers (dev);
		}

		if (backupHeader || cryptoInfo->LegacyVolume)
			break;
			
		backupHeader = TRUE;
		headerOffset.QuadPart += hostSize - TC_VOLUME_HEADER_GROUP_SIZE;
	}

	/* Password successfully changed */
	nStatus = 0;

error:
	dwError = GetLastError ();

	burn (buffer, sizeof (buffer));

	if (cryptoInfo != NULL)
		crypto_close (cryptoInfo);

	if (bTimeStampValid)
		SetFileTime (dev, &ftCreationTime, &ftLastAccessTime, &ftLastWriteTime);

	if (dev != INVALID_HANDLE_VALUE)
		CloseHandle ((HANDLE) dev);

	if (nDosLinkCreated == 0)
		RemoveFakeDosName (szDiskFile, szDosDevice);

	RandStop (FALSE);

	SetLastError (dwError);

	if (nStatus == ERR_OS_ERROR && dwError == ERROR_ACCESS_DENIED
		&& bDevice
		&& !UacElevated
		&& IsUacSupported ())
		return nStatus;

	if (nStatus != 0)
		SetLastError(nStatus);

	return nStatus;
}