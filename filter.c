#include <stdio.h>

#include "filter.h"

void
mkerror(struct filter_input *f, char *msg)
{
	f->error = 1;
	sprintf(f->errmsg, "Line %d, col %d: %s", f->line, f->col, msg);
}

