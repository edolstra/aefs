#include <string.h>

#include "corefs.h"


int coreNameCompSens(octet * p, octet * q)
{
   return strcmp(p, q);
}


int coreNameCompInSens(octet * p, octet * q)
{
   return stricmp(p, q);
}
