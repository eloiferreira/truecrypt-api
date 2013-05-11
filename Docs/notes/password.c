======================================================================================================
VerifyPasswordAndUpdate(...)
======================================================================================================
When copying password to supplied buffer, overrun is possible as no check on buffer size is performed.

Why first parameter is unsigned char * and the second is char * although both are used identically?