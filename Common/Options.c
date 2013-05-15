/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#include <windows.h>
#include "Options.h"
#include "Errors.h"

BOOL bPreserveTimestamp = TRUE;
BOOL bCacheInDriver = FALSE;
BOOL bMountReadOnly = FALSE;
BOOL bMountRemovable = FALSE;

BOOL ApplyOptions(PTCAPI_OPTIONS options) {
	int i;
	PTCAPI_OPTION option = NULL;

	for (i = 0; i < (int) options->NumberOfOptions; i++) {
		
		option = &options->Options[i];

		switch (option->OptionId) {
		case TC_OPTION_CACHE_PASSWORDS: 
			bCacheInDriver = option->OptionValue;
			break;
		case TC_OPTION_MOUNT_READONLY:
			bMountReadOnly = option->OptionValue;
			break;
		case TC_OPTION_MOUNT_REMOVABLE:
			bMountRemovable = option->OptionValue;
			break;
		case TC_OPTION_PRESERVE_TIMESTAMPS:
			bPreserveTimestamp = option->OptionValue;
			break;
		default:
			SetLastError(TCAPI_E_WRONG_OPTION);
			return FALSE;
		}
	}
	return TRUE;
}