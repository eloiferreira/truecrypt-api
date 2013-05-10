/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#ifndef PASSWORD_H
#define PASSWORD_H

// User text input limits
#define MIN_PASSWORD			1		// Minimum possible password length
#define MAX_PASSWORD			64		// Maximum possible password length

#define PASSWORD_LEN_WARNING	20		// Display a warning when a password is shorter than this

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct
	{
		// Modifying this structure can introduce incompatibility with previous versions
		unsigned __int32 Length;
		unsigned char Text[MAX_PASSWORD + 1];
		char Pad[3]; // keep 64-bit alignment
	} Password;

#if defined(_WIN32) && !defined(TC_WINDOWS_DRIVER)

	BOOL CheckPasswordLength (HWND hwndDlg, HWND hwndItem);		
	BOOL CheckPasswordCharEncoding (HWND hPassword, Password *ptrPw);			
	int ChangePwd (char *lpszVolume, Password *oldPassword, Password *newPassword, int pkcs5, HWND hwndDlg);

#endif	// defined(_WIN32) && !defined(TC_WINDOWS_DRIVER)

#ifdef __cplusplus
}
#endif

#endif