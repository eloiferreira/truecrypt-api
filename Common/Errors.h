/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2010 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#define TCE_FACILITY_API 7UL

#define STATUS_SEVERITY_SUCCESS			0x0
#define STATUS_SEVERITY_INFORMATIONAL	0x1
#define STATUS_SEVERITY_WARNING			0x2
#define STATUS_SEVERITY_ERROR			0x3


/* MAKE_ERRORCODE macro defines application-specific error codes according to NTSTATUS structure
(http://msdn.microsoft.com/en-us/library/cc231200.aspx) and MSDN SetLastError recommendation.
*/
#define MAKE_ERRORCODE(severity, error_code)\
	(DWORD)((unsigned long)(severity)<<30 | 1UL<<29 | TCE_FACILITY_API<<16 | (unsigned long)(error_code))

/* TrueCrypt API related error codes */
#define TCE_API_SUCCESS			MAKE_ERRORCODE(STATUS_SEVERITY_SUCCESS, 0)

#ifdef __cplusplus
extern "C" {
#endif

DWORD handleWin32Error ( HWND hwndDlg );

#ifdef __cplusplus
}
#endif