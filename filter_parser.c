#include "filter.h"

static int
accept(struct query_input *i, enum TOKEN_ID token)
{
	if (i->current_token.id != token) {
		return 0;
	}

	read_token(i);

	if (i->error) {
		return 0;
	}

	return 1;
}

static int
expect(struct query_input *i, enum TOKEN_ID token)
{
	if (!accept(i, token)) {
		/* unexpected token */ 
		return 0;
	}

	return 1;
}

static void
qualifier_without_dir(struct query_input *i)
{
	if (accept(i, HOST)) {
		if (!expect(i, ID)) {
			mkerror(i, "Expected address");
			return;
		}
	} else if (accept(i, NET)) {
		if (!expect(i, ID)) {
			mkerror(i, "Expected address");
			return;
		}
	} else if (accept(i, PORT)) {
	} else {
		mkerror(i, "Expected HOST, NET or PORT");
		return;
	}

}

void
parse_filter(struct query_input *i)
{
	int not = 0;

	read_token(i);
	if (accept(i, NOT)) {
		not = 1;
	} else if (accept(i, SRC)) {
		qualifier_without_dir(i);
	} else if (accept(i, DST)) {
		qualifier_without_dir(i);
	} else if (accept(i, HOST)) {
		if (!expect(i, ID)) {
			mkerror(i, "Expected address after HOST");
			return;
		}
	} else if (accept(i, NET)) {
		if (!expect(i, ID)) {
			mkerror(i, "Expected address after NET");
			return;
		}
	} else {
		mkerror(i, "Unexpected token");
	}
}

