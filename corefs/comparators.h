#ifndef _COMPARATORS_H
#define _COMPARATORS_H

#include "types.h"

typedef int (* CoreNameComp)(octet *, octet *);

int coreNameCompSens(octet *, octet *);
int coreNameCompInSens(octet *, octet *);

#endif /* !_COMPARATORS_H */
