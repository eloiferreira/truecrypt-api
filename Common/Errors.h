/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#ifndef ERRORS_H
#define ERRORS_H

#include <windows.h>
#include <winerror.h>

//TODO: To be replaced with proper error handling
#define TC_THROW_FATAL_EXCEPTION	*(char *) 0 = 0

#define STATUS_SEVERITY_SUCCESS			0x0UL
#define STATUS_SEVERITY_INFORMATIONAL	0x1UL
#define STATUS_SEVERITY_WARNING			0x2UL
#define STATUS_SEVERITY_ERROR			0x3UL

#define FACILITY_TCAPI					0x500UL

/* MAKE_ERRORCODE macro defines application-specific error codes according to NTSTATUS structure
(http://msdn.microsoft.com/en-us/library/cc231200.aspx) and MSDN SetLastError recommendation. */

#define MAKE_ERROR(severity, facility, error_code)\
	(DWORD)(severity<<30 | 1UL<<29 | (unsigned long)(facility)<<16 | (unsigned long)(error_code))

/* Translated system error codes */

static const DWORD TCAPI_E_ACCESS_DENIED			= MAKE_ERROR(STATUS_SEVERITY_ERROR, FACILITY_SECURITY, ERROR_ACCESS_DENIED);

/* Storage related error codes*/

//static const DWORD TCAPI_E_CRC						= MAKE_DISK_ERROR(ERROR_CRC);
//static const DWORD TCAPI_E_IO_DEVICE				= MAKE_DISK_ERROR(ERROR_IO_DEVICE);
//static const DWORD TCAPI_E_BAD_CLUSTERS				= MAKE_DISK_ERROR(ERROR_BAD_CLUSTERS);
//static const DWORD TCAPI_E_SECTOR_NOT_FOUND			= MAKE_DISK_ERROR(ERROR_SECTOR_NOT_FOUND);
//static const DWORD TCAPI_E_READ_FAULT				= MAKE_DISK_ERROR(ERROR_READ_FAULT);
//static const DWORD TCAPI_E_WRITE_FAULT				= MAKE_DISK_ERROR(ERROR_WRITE_FAULT);
//static const DWORD TCAPI_E_INVALID_FUNCTION			= MAKE_DISK_ERROR(ERROR_INVALID_FUNCTION);
//static const DWORD TCAPI_E_SEM_TIMEOUT				= MAKE_DISK_ERROR(ERROR_SEM_TIMEOUT);

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


static const DWORD TCAPI_S_SUCCESS										= MAKE_TCAPI_SUCCESS(0);

static const DWORD TCAPI_I_INFO											= MAKE_TCAPI_INFO(1);

static const DWORD TCAPI_E_ERROR										= MAKE_TCAPI_ERROR(1);

static const DWORD TCAPI_E_CANT_GET_OS_VER								= MAKE_TCAPI_ERROR(2);
static const DWORD TCAPI_E_UNSUPPORTED_OS								= MAKE_TCAPI_ERROR(3);
static const DWORD TCAPI_E_UNKNOWN_OS									= MAKE_TCAPI_ERROR(4);
static const DWORD TCAPI_E_PAGE_NOT_LOCKED								= MAKE_TCAPI_ERROR(5);
static const DWORD TCAPI_E_PAGE_CANT_LOCK								= MAKE_TCAPI_ERROR(6);
static const DWORD TCAPI_E_PASS_LENGTH_NOT_EQUAL						= MAKE_TCAPI_ERROR(7);
static const DWORD TCAPI_E_PASS_TOO_SHORT								= MAKE_TCAPI_ERROR(8);
static const DWORD TCAPI_E_PASS_NOT_EQUAL								= MAKE_TCAPI_ERROR(9);
static const DWORD TCAPI_E_NOT_ENOUGH_RANDOM_DATA						= MAKE_TCAPI_ERROR(10);
static const DWORD TCAPI_E_NOT_INITIALIZED								= MAKE_TCAPI_ERROR(11);
static const DWORD TCAPI_E_WRONG_OPTION									= MAKE_TCAPI_ERROR(12);
static const DWORD TCAPI_E_CANT_START_ENCPOOL							= MAKE_TCAPI_ERROR(13);
static const DWORD TCAPI_E_DRIVER_ALREADY_INSTALLED						= MAKE_TCAPI_ERROR(14);
static const DWORD TCAPI_E_DRIVER_NOT_FOUND								= MAKE_TCAPI_ERROR(15);
static const DWORD TCAPI_E_CANT_OPEN_SCM								= MAKE_TCAPI_ERROR(16);
static const DWORD TCAPI_E_NOACCESS_SCM									= MAKE_TCAPI_ERROR(17);
static const DWORD TCAPI_E_CANT_CREATE_SERVICE							= MAKE_TCAPI_ERROR(18);
static const DWORD TCAPI_E_CANT_START_SERVICE							= MAKE_TCAPI_ERROR(19);
static const DWORD TCAPI_E_CANT_GET_DRIVER_VER							= MAKE_TCAPI_ERROR(20);
static const DWORD TCAPI_E_WRONG_DRIVER_VER								= MAKE_TCAPI_ERROR(21);
static const DWORD TCAPI_E_CANT_LOAD_DRIVER								= MAKE_TCAPI_ERROR(22);
static const DWORD TCAPI_E_INCONSISTENT_DRIVER_STATE					= MAKE_TCAPI_ERROR(23);
static const DWORD TCAPI_E_CANT_ACQUIRE_DRIVER							= MAKE_TCAPI_ERROR(24);
static const DWORD TCAPI_E_DRIVER_NOT_INSTALLED							= MAKE_TCAPI_ERROR(25);
static const DWORD TCAPI_E_CANT_OPEN_SERVICE							= MAKE_TCAPI_ERROR(26);
static const DWORD TCAPI_E_CANT_QUERY_SERVICE							= MAKE_TCAPI_ERROR(27);
static const DWORD TCAPI_E_TC_INSTALLER_RUNNING							= MAKE_TCAPI_ERROR(28);
static const DWORD TCAPI_E_TC_CONFIG_CORRUPTED							= MAKE_TCAPI_ERROR(29);
static const DWORD TCAPI_E_VOL_ALREADY_MOUNTED							= MAKE_TCAPI_ERROR(30);
static const DWORD TCAPI_E_PARAM_INCORRECT								= MAKE_TCAPI_ERROR(31);
static const DWORD TCAPI_E_NO_SYSENC_PARTITION							= MAKE_TCAPI_ERROR(32);
static const DWORD TCAPI_E_INVALID_PATH									= MAKE_TCAPI_ERROR(33);
static const DWORD TCAPI_E_NOPBA_MOUNT_ON_ACTIVE_SYSENC_DRIVE			= MAKE_TCAPI_ERROR(34);
static const DWORD TCAPI_E_DRIVE_LETTER_UNAVAILABLE						= MAKE_TCAPI_ERROR(35);
static const DWORD TCAPI_E_PASSWORD_NULL_AND_NOT_CACHED					= MAKE_TCAPI_ERROR(36);
static const DWORD TCAPI_E_FILE_IN_USE									= MAKE_TCAPI_ERROR(37);
static const DWORD TCAPI_E_TIMEOUTEXCEPTION								= MAKE_TCAPI_ERROR(38);
static const DWORD TCAPI_E_USER_ABORT_EXCEPTION							= MAKE_TCAPI_ERROR(39);  // TODO: might be no need in this
static const DWORD TCAPI_E_UNMOUNT_FAILED								= MAKE_TCAPI_ERROR(40);
static const DWORD TCAPI_E_WHOLE_DRIVE_ENCRYPTION_PREVENTED_BY_DRIVERS	= MAKE_TCAPI_ERROR(41);
static const DWORD TCAPI_E_OUTOFMEMORY									= MAKE_TCAPI_ERROR(42);
static const DWORD TCAPI_E_WRONG_PASSWORD								= MAKE_TCAPI_ERROR(43);
static const DWORD TCAPI_E_DRIVE_NOT_FOUND								= MAKE_TCAPI_ERROR(44);
static const DWORD TCAPI_E_FILES_OPEN									= MAKE_TCAPI_ERROR(45);
static const DWORD TCAPI_E_FILES_OPEN_LOCK								= MAKE_TCAPI_ERROR(46);
static const DWORD TCAPI_E_VOL_SIZE_WRONG								= MAKE_TCAPI_ERROR(47);
static const DWORD TCAPI_E_COMPRESSION_NOT_SUPPORTED					= MAKE_TCAPI_ERROR(48);
static const DWORD TCAPI_E_PASSWD_CHANGE_VOL_TYPE						= MAKE_TCAPI_ERROR(49);
static const DWORD TCAPI_E_VOL_SEEKING									= MAKE_TCAPI_ERROR(50);
static const DWORD TCAPI_E_CIPHER_INIT_FAILURE							= MAKE_TCAPI_ERROR(51);
static const DWORD TCAPI_E_CIPHER_INIT_WEAK_KEY							= MAKE_TCAPI_ERROR(52);
static const DWORD TCAPI_E_FILE_OPEN_FAILED								= MAKE_TCAPI_ERROR(53);
static const DWORD TCAPI_E_MOUNT_FAILED									= MAKE_TCAPI_ERROR(54);
static const DWORD TCAPI_E_NO_FREE_DRIVES								= MAKE_TCAPI_ERROR(55);
static const DWORD TCAPI_E_DRIVER_VERSION								= MAKE_TCAPI_ERROR(56);
static const DWORD TCAPI_E_NEW_VERSION_REQIURED							= MAKE_TCAPI_ERROR(57);
static const DWORD TCAPI_E_SELF_TEST_FAILED								= MAKE_TCAPI_ERROR(58);
static const DWORD TCAPI_E_VOL_FORMAT_BAD								= MAKE_TCAPI_ERROR(59);
static const DWORD TCAPI_E_ENCRYPTION_NOT_COMPLETED						= MAKE_TCAPI_ERROR(60);
static const DWORD TCAPI_E_NONSYS_INPLACE_ENCRYPTION_INCOMPLETE			= MAKE_TCAPI_ERROR(61);
static const DWORD TCAPI_E_SYS_HID_VOL_REENC_MODE_WRONG					= MAKE_TCAPI_ERROR(62);

static const DWORD TCAPI_W_AUTOMOUNT_DISABLED			= MAKE_TCAPI_WARNING(1);
static const DWORD TCAPI_W_ASSIGN_DRIVE_LETTER			= MAKE_TCAPI_WARNING(2);
static const DWORD TCAPI_W_DEVICE_NOT_READY				= MAKE_TCAPI_WARNING(3);
static const DWORD TCAPI_W_LARGE_IDE_2K					= MAKE_TCAPI_WARNING(4);
static const DWORD TCAPI_W_LARGE_IDE_2K_REGISTRY		= MAKE_TCAPI_WARNING(5);
static const DWORD TCAPI_W_LARGE_IDE_XP					= MAKE_TCAPI_WARNING(6);
static const DWORD TCAPI_W_WEAK_PASSWORD				= MAKE_TCAPI_WARNING(7);
static const DWORD TCAPI_W_STALE_SERVICE				= MAKE_TCAPI_WARNING(8);
static const DWORD TCAPI_W_DRIVER_NOT_LOADED			= MAKE_TCAPI_WARNING(9);
static const DWORD TCAPI_W_VOLUMES_STILL_MOUNTED		= MAKE_TCAPI_WARNING(10);
static const DWORD TCAPI_W_APPS_STILL_ATTACHED			= MAKE_TCAPI_WARNING(11);
static const DWORD TCAPI_W_HEADER_DAMAGED_BACKUP_USED	= MAKE_TCAPI_WARNING(12);
static const DWORD TCAPI_W_CBC_MODE						= MAKE_TCAPI_WARNING(13);
static const DWORD TCAPI_W_64_BIT_BLOCK_CIPHER			= MAKE_TCAPI_WARNING(14);
static const DWORD TCAPI_W_FILE_EXTENSION				= MAKE_TCAPI_WARNING(15);
static const DWORD TCAPI_W_USER_ABORT					= MAKE_TCAPI_WARNING(16);

#define debug_out(msg, err_no) do { DebugOut(__FUNCTION__, msg, err_no); } while (0)
#define set_error_debug_out(error) do { SetLastError(error); DebugOut(__FUNCTION__, #error, error); } while (0);
#define handle_win_error() do {DWORD err = GetLastError(); debug_out("WINDOWS_ERROR", err); } while (0)

#ifdef __cplusplus
extern "C" {
#endif

	void DebugOut(const char *src, const char *msg, DWORD err_no);
	BOOL IsDiskError (DWORD error);
	BOOL IsDiskReadError (DWORD error);
	BOOL IsDiskWriteError (DWORD error);
	void HandleWin32Error();
	void HandleDriveNotReadyError (DWORD reportedError);
	void HandlePasswordError(void);
	void HandleTcError (int code);

#ifdef __cplusplus
}
#endif

#endif