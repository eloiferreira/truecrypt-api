/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#define STATUS_SEVERITY_SUCCESS			0x0UL
#define STATUS_SEVERITY_INFORMATIONAL	0x1UL
#define STATUS_SEVERITY_WARNING			0x2UL
#define STATUS_SEVERITY_ERROR			0x3UL

#define FACILITY_TCAPI					0x500UL

/* MAKE_ERRORCODE macro defines application-specific error codes according to NTSTATUS structure
(http://msdn.microsoft.com/en-us/library/cc231200.aspx) and MSDN SetLastError recommendation. */

#define MAKE_ERROR(severity, facility, error_code)\
	(DWORD)(severity<<30 | 1UL<<29 | (unsigned long)(facility)<<16 | (unsigned long)(error_code))

#define MAKE_DISK_ERROR(error_code)\
	MAKE_ERROR(STATUS_SEVERITY_ERROR, FACILITY_STORAGE, error_code)

#define MAKE_DISK_WARNING(error_code)\
	MAKE_ERROR(STATUS_SEVERITY_WARNING, FACILITY_STORAGE, error_code)

#define MAKE_WINDOWS_ERROR(error_code)\
	MAKE_ERROR(STATUS_SEVERITY_ERROR, FACILITY_WINDOWS, error_code)

/* Translated system error codes */

#define TCAPI_E_ACCESS_DENIED			MAKE_ERROR(STATUS_SEVERITY_ERROR, FACILITY_SECURITY, ERROR_ACCESS_DENIED)

/* Storage related error codes*/

#define TCAPI_E_CRC						MAKE_DISK_ERROR(ERROR_CRC)
#define TCAPI_E_IO_DEVICE				MAKE_DISK_ERROR(ERROR_IO_DEVICE)
#define TCAPI_E_BAD_CLUSTERS			MAKE_DISK_ERROR(ERROR_BAD_CLUSTERS)
#define TCAPI_E_SECTOR_NOT_FOUND		MAKE_DISK_ERROR(ERROR_SECTOR_NOT_FOUND)
#define TCAPI_E_READ_FAULT				MAKE_DISK_ERROR(ERROR_READ_FAULT)
#define TCAPI_E_WRITE_FAULT				MAKE_DISK_ERROR(ERROR_WRITE_FAULT)
#define TCAPI_E_INVALID_FUNCTION		MAKE_DISK_ERROR(ERROR_INVALID_FUNCTION)
#define TCAPI_E_SEM_TIMEOUT				MAKE_DISK_ERROR(ERROR_SEM_TIMEOUT)

/* TrueCrypt API related error codes.
Only these codes use FACILITY_TCAPI facility, all others 
should reuse appropriate system-defined facility*/

#define TCAPI_S_BASE	0x0UL
#define TCAPI_I_BASE	0xF0UL
#define TCAPI_W_BASE	0xF00UL
#define TCAPI_E_BASE	0xF000UL

#define MAKE_TCAPI_SUCCESS(error_code)\
	MAKE_ERROR(STATUS_SEVERITY_SUCCESS, FACILITY_TCAPI, TCAPI_S_BASE + (unsigned long)error_code)

#define MAKE_TCAPI_INFO(error_code)\
	MAKE_ERROR(STATUS_SEVERITY_INFORMATIONAL, FACILITY_TCAPI, TCAPI_I_BASE + (unsigned long)error_code)

#define MAKE_TCAPI_WARNING(error_code)\
	MAKE_ERROR(STATUS_SEVERITY_WARNING, FACILITY_TCAPI, TCAPI_W_BASE + (unsigned long)error_code)

#define MAKE_TCAPI_ERROR(error_code)\
	MAKE_ERROR(STATUS_SEVERITY_ERROR, FACILITY_TCAPI, TCAPI_E_BASE + (unsigned long)error_code)


#define TCAPI_S_SUCCESS					MAKE_TCAPI_SUCCESS(0)

#define TCAPI_I_INFO					MAKE_TCAPI_INFO(1)

#define TCAPI_E_ERROR					MAKE_TCAPI_ERROR(1)

#define TCAPI_W_AUTOMOUNT_DISABLED		MAKE_TCAPI_WARNING(1)
#define TCAPI_W_ASSIGN_DRIVE_LETTER		MAKE_TCAPI_WARNING(2)
#define TCAPI_W_DEVICE_NOT_READY		MAKE_TCAPI_WARNING(3)



//SYS_ASSIGN_DRIVE_LETTER
#ifdef __cplusplus
extern "C" {
#endif

DWORD handleWin32Error();

#ifdef __cplusplus
}
#endif