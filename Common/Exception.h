/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Common_Exception
#define TC_HEADER_Common_Exception

#include "Errors.h"

#ifdef __cplusplus 

namespace TrueCrypt
{
	struct Exception
	{
		virtual void Show () const = 0;
	};

	struct SystemException : public Exception
	{
		SystemException () : ErrorCode (GetLastError()) { }

		void Show () const
		{
			debug_out("SystemException", ErrorCode);
		}

		DWORD ErrorCode;
	};

	struct ErrorException : public Exception
	{
		ErrorException () : ErrorCode (GetLastError()) { }

		void Show () const
		{
			debug_out("ErrorException", ErrorCode);
		}

		DWORD ErrorCode;
	};

	struct ParameterIncorrect : public Exception
	{
		ParameterIncorrect (const char *srcPos) : SrcPos (srcPos) { }

		void Show () const
		{
			SetLastError(TCAPI_E_PARAM_INCORRECT);
			debug_out(SrcPos, TCAPI_E_PARAM_INCORRECT);
		}

		const char *SrcPos;
	};

	struct TimeOut : public Exception
	{
		TimeOut (const char *srcPos) : SrcPos (srcPos) { }

		void Show () const { 
			SetLastError(TCAPI_E_TIMEOUTEXCEPTION);
			debug_out(SrcPos, TCAPI_E_TIMEOUTEXCEPTION);
		}

		const char *SrcPos;
	};

	struct UserAbort : public Exception
	{
		UserAbort (const char *srcPos) : SrcPos (srcPos) { }

		void Show () const {
			SetLastError(TCAPI_E_USER_ABORT_EXCEPTION);
			debug_out(SrcPos, TCAPI_E_USER_ABORT_EXCEPTION);
		}

		const char *SrcPos;
	};
}

#define throw_sys_if(condition) do { if (condition) throw SystemException(); } while (false)

#endif

#endif // TC_HEADER_Common_Exception
