#ifndef xe_debug_h_included
#define xe_debug_h_included

#include <stdio.h>

/* debug options */
struct xe_debug
{
	int print_flows;
	int print_to_syslog;
	FILE *fout;
};

#endif

