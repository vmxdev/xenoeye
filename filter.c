#include <stdio.h>

#include "filter.h"

void
mkerror(struct query_input *i, char *msg)
{
	i->error = 1;
	sprintf(i->errmsg, "Line %d, col %d: %s", i->line, i->col, msg);
}

