/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#include "Tcdefs.h"

#include "Strings.h"
#include <Windows.h>
#include <string.h>
#include <ctype.h>
#include "Platform/PlatformBase.h"
#include "Exception.h"
#include "Platform/ForEach.h"

using namespace TrueCrypt;

void LowerCaseCopy (char *lpszDest, const char *lpszSource)
{
	int i = strlen (lpszSource);

	lpszDest[i] = 0;
	while (--i >= 0)
	{
		lpszDest[i] = (char) tolower (lpszSource[i]);
	}

}

void UpperCaseCopy (char *lpszDest, const char *lpszSource)
{
	int i = strlen (lpszSource);

	lpszDest[i] = 0;
	while (--i >= 0)
	{
		lpszDest[i] = (char) toupper (lpszSource[i]);
	}
}

BOOL BufferContainsString (const byte *buffer, size_t bufferSize, const char *str)
{
	size_t strLen = strlen (str);

	if (bufferSize < strLen)
		return FALSE;

	bufferSize -= strLen;

	for (size_t i = 0; i < bufferSize; ++i)
	{
		if (memcmp (buffer + i, str, strLen) == 0)
			return TRUE;
	}

	return FALSE;
}

#pragma warning(push)
#pragma warning(disable:4702)

void *err_malloc (size_t size)
{
	void *z = (void *) TCalloc (size);
	if (z)
		return z;
	TC_THROW_FATAL_EXCEPTION;
	return 0;
}

#pragma warning(pop)


char *err_strdup (char *lpszText)
{
	int j = (strlen (lpszText) + 1) * sizeof (char);
	char *z = (char *) err_malloc (j);
	memmove (z, lpszText, j);
	return z;
}

/*****************************************************************************
  ToSBCS: converts a unicode string to Single Byte Character String (SBCS).
  ***************************************************************************/

void ToSBCS (LPWSTR lpszText)
{
	int j = wcslen (lpszText);
	if (j == 0)
	{
		strcpy ((char *) lpszText, "");
		return;
	}
	else
	{
		char *lpszNewText = (char *) err_malloc (j + 1);
		j = WideCharToMultiByte (CP_ACP, 0L, lpszText, -1, lpszNewText, j + 1, NULL, NULL);
		if (j > 0)
			strcpy ((char *) lpszText, lpszNewText);
		else
			strcpy ((char *) lpszText, "");
		free (lpszNewText);
	}
}

/*****************************************************************************
  ToUNICODE: converts a SBCS string to a UNICODE string.
  ***************************************************************************/

void ToUNICODE (char *lpszText)
{
	int j = strlen (lpszText);
	if (j == 0)
	{
		wcscpy ((LPWSTR) lpszText, (LPWSTR) WIDE (""));
		return;
	}
	else
	{
		LPWSTR lpszNewText = (LPWSTR) err_malloc ((j + 1) * 2);
		j = MultiByteToWideChar (CP_ACP, 0L, lpszText, -1, lpszNewText, j + 1);
		if (j > 0)
			wcscpy ((LPWSTR) lpszText, lpszNewText);
		else
			wcscpy ((LPWSTR) lpszText, (LPWSTR) WIDE (""));
		free (lpszNewText);
	}
}

std::wstring SingleStringToWide (const std::string &singleString)
{
	if (singleString.empty())
		return std::wstring();

	WCHAR wbuf[65536];
	int wideLen = MultiByteToWideChar (CP_ACP, 0, singleString.c_str(), -1, wbuf, array_capacity (wbuf) - 1);
	throw_sys_if (wideLen == 0);

	wbuf[wideLen] = 0;
	return wbuf;
}


std::wstring Utf8StringToWide (const std::string &utf8String)
{
	if (utf8String.empty())
		return std::wstring();

	WCHAR wbuf[65536];
	int wideLen = MultiByteToWideChar (CP_UTF8, 0, utf8String.c_str(), -1, wbuf, array_capacity (wbuf) - 1);
	throw_sys_if (wideLen == 0);

	wbuf[wideLen] = 0;
	return wbuf;
}


std::string WideToUtf8String (const std::wstring &wideString)
{
	if (wideString.empty())
		return std::string();

	char buf[65536];
	int len = WideCharToMultiByte (CP_UTF8, 0, wideString.c_str(), -1, buf, array_capacity (buf) - 1, NULL, NULL);
	throw_sys_if (len == 0);

	buf[len] = 0;
	return buf;
}


std::string WideToSingleString (const std::wstring &wideString)
{
	if (wideString.empty())
		return std::string();

	char buf[65536];
	int len = WideCharToMultiByte (CP_ACP, 0, wideString.c_str(), -1, buf, array_capacity (buf) - 1, NULL, NULL);
	throw_sys_if (len == 0);

	buf[len] = 0;
	return buf;
}


std::string StringToUpperCase (const std::string &str)
{
	string upperCase (str);
	_strupr ((char *) upperCase.c_str());
	return upperCase;
}

std::string ToUpperCase (const std::string &str)
{
	string u;
	foreach (char c, str)
	{
		u += (char) toupper (c);
	}

	return u;
}

