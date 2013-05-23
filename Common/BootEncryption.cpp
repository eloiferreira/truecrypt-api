/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#include "BootEncryption.h"
#include "Uac.h"
#include <atlbase.h>

namespace TrueCrypt
{

#define SRC_POS (__FUNCTION__ ":" TC_TO_STRING(__LINE__))

	class Elevator
	{
	public:

		static void AddReference ()
		{
			++ReferenceCount;
		}

		static void CallDriver (DWORD ioctl, void *input, DWORD inputSize, void *output, DWORD outputSize)
		{
			Elevate();

			CComBSTR inputBstr;
			if (input && inputBstr.AppendBytes ((const char *) input, inputSize) != S_OK)
				throw ParameterIncorrect (SRC_POS);

			CComBSTR outputBstr;
			if (output && outputBstr.AppendBytes ((const char *) output, outputSize) != S_OK)
				throw ParameterIncorrect (SRC_POS);

			DWORD result = ElevatedComInstance->CallDriver (ioctl, inputBstr, &outputBstr);

			if (output)
				memcpy (output, *(void **) &outputBstr, outputSize);

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}
		}

		static void CopyFile (const string &sourceFile, const string &destinationFile)
		{
			Elevate();

			DWORD result = ElevatedComInstance->CopyFile (CComBSTR (sourceFile.c_str()), CComBSTR (destinationFile.c_str()));

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}
		}

		static void DeleteFile (const string &file)
		{
			Elevate();

			DWORD result = ElevatedComInstance->DeleteFile (CComBSTR (file.c_str()));

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}
		}

		static void ReadWriteFile (BOOL write, BOOL device, const string &filePath, byte *buffer, uint64 offset, uint32 size, DWORD *sizeDone)
		{
			Elevate();

			CComBSTR bufferBstr;
			if (bufferBstr.AppendBytes ((const char *) buffer, size) != S_OK)
				throw ParameterIncorrect (SRC_POS);
			DWORD result = ElevatedComInstance->ReadWriteFile (write, device, CComBSTR (filePath.c_str()), &bufferBstr, offset, size, sizeDone);

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}

			if (!write)
				memcpy (buffer, (BYTE *) bufferBstr.m_str, size);
		}

		static BOOL IsPagingFileActive (BOOL checkNonWindowsPartitionsOnly)
		{
			Elevate();

			return ElevatedComInstance->IsPagingFileActive (checkNonWindowsPartitionsOnly);
		}

		static void WriteLocalMachineRegistryDwordValue (char *keyPath, char *valueName, DWORD value)
		{
			Elevate();

			DWORD result = ElevatedComInstance->WriteLocalMachineRegistryDwordValue (CComBSTR (keyPath), CComBSTR (valueName), value);

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}
		}

		//TODO:
		//static void RegisterFilterDriver (bool registerDriver, BootEncryption::FilterType filterType)
		//{
		//	Elevate();

		//	DWORD result = ElevatedComInstance->RegisterFilterDriver (registerDriver ? TRUE : FALSE, filterType);
		//	if (result != ERROR_SUCCESS)
		//	{
		//		SetLastError (result);
		//		throw SystemException();
		//	}
		//}

		static void RegisterSystemFavoritesService (BOOL registerService)
		{
			Elevate();

			DWORD result = ElevatedComInstance->RegisterSystemFavoritesService (registerService);
			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}
		}

		static void Release ()
		{
			if (--ReferenceCount == 0 && ElevatedComInstance)
			{
				ElevatedComInstance->Release();
				ElevatedComInstance = nullptr;
				CoUninitialize ();
			}
		}

		static void SetDriverServiceStartType (DWORD startType)
		{
			Elevate();

			DWORD result = ElevatedComInstance->SetDriverServiceStartType (startType);
			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException();
			}
		}

	protected:
		static void Elevate ()
		{
			if (IsAdmin())
			{
				SetLastError (ERROR_ACCESS_DENIED);
				throw SystemException();
			}

			if (!ElevatedComInstance || ElevatedComInstanceThreadId != GetCurrentThreadId())
			{
				CoInitialize (NULL);
				ElevatedComInstance = GetElevatedInstance (GetActiveWindow() ? GetActiveWindow() : MainDlg);
				ElevatedComInstanceThreadId = GetCurrentThreadId();
			}
		}

		static ITrueCryptApiCom *ElevatedComInstance;
		static DWORD ElevatedComInstanceThreadId;
		static int ReferenceCount;
	};

	ITrueCryptApiCom *Elevator::ElevatedComInstance;

	DWORD Elevator::ElevatedComInstanceThreadId;
	int Elevator::ReferenceCount = 0;

	File::File (string path, bool readOnly, bool create) : Elevated (false), FileOpen (false)
	{
		Handle = CreateFile (path.c_str(),
			readOnly ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, create ? CREATE_ALWAYS : OPEN_EXISTING,
			FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_WRITE_THROUGH, NULL);

		try
		{
			throw_sys_if (Handle == INVALID_HANDLE_VALUE);
		}
		catch (SystemException &)
		{
			if (GetLastError() == ERROR_ACCESS_DENIED && IsUacSupported())
				Elevated = true;
			else
				throw;
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
			if (!Elevated)
				CloseHandle (Handle);

			FileOpen = false;
		}
	}

	DWORD File::Read (byte *buffer, DWORD size)
	{
		DWORD bytesRead;

		if (Elevated)
		{
			DWORD bytesRead;

			Elevator::ReadWriteFile (false, IsDevice, Path, buffer, FilePointerPosition, size, &bytesRead);
			FilePointerPosition += bytesRead;
			return bytesRead;
		}

		throw_sys_if (!ReadFile (Handle, buffer, size, &bytesRead, NULL));
		return bytesRead;
	}

}