/* Legal Notice: Portions of the source code contained in this file were 
derived from the source code of TrueCrypt 7.1a which is Copyright (c) 2003-2013 
TrueCrypt Developers Association and is governed by the TrueCrypt License 3.0. 
Modifications and additions to the original source code (contained in this file) 
and all other portions of this file are Copyright (c) 2013 Nic Nilov and are 
governed by license terms which are TBD. */

#ifndef STRINGS_H
#define STRINGS_H

#ifdef __cplusplus
extern "C" {
#endif
	
	void LowerCaseCopy (char *lpszDest, const char *lpszSource);
	void UpperCaseCopy (char *lpszDest, const char *lpszSource);

#ifdef __cplusplus
}
#endif

#endif