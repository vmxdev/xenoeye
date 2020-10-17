#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../filter.h"

int
main()
{
	struct filter_input q;
	struct filter_expr *e;

	memset(&q, 0, sizeof(struct filter_input));

	q.s = "Src host 1.2.3.4 and (PORT 12345 or 54321) or "\
		"dst host 4.3.2.1";
	e = parse_filter(&q);
	if (!e) {
		printf("Filter allocation failed\n");
		return EXIT_FAILURE;
	}

	if (q.error) {
		printf("Parse error: %s\n", q.errmsg);
		return EXIT_FAILURE;
	}

	filter_dump(e, stdout);

	filter_free(e);

	return EXIT_SUCCESS;
}

