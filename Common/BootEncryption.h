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

#ifdef __cplusplus

#include <string>

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
}

#endif

#endif