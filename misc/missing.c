#include <stdio.h>
#include <stdarg.h>

#include "sysdep.h"

#ifndef HAVE_SNPRINTF

int snprintf(char * str, int size, const char * format, ...)
{
    char buf[16384];
    va_list va;
    va_start(va, format);
    /* !!! Danger, buffer overflow.  Get a C99 compiler! */
    vsprintf(buf, format, va);
    va_end(va);
    strncpy(str, buf, size);
    return strlen(buf);
}

#endif
