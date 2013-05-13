/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#include "Apidrvr.h"

#ifdef _WIN32

/* Handle to the device driver */
HANDLE hDriver = INVALID_HANDLE_VALUE;

int DriverAttach (void) {
	return 0;
}

#endif /* _WIN32 */