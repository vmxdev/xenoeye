#include <stdio.h>
#include "filter.h"

static int expression(struct filter_input *q);

static int
accept(struct filter_input *i, enum TOKEN_ID token)
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
expect(struct filter_input *i, enum TOKEN_ID token)
{
	if (!accept(i, token)) {
		/* unexpected token */ 
		return 0;
	}

	return 1;
}

static int
id(struct filter_input *q)
{
	if (!expect(q, ID)) {
		mkerror(q, "Expected ID");
		return 0;
	}

	/* optional OR's */
	for (;;) {
		if (!accept(q, OR)) {
			break;
		}

		if (accept(q, ID)) {
			continue;
		}
		expression(q);
	}

	return 1;
}

static int
rule_without_direction(struct filter_input *q)
{
	if (accept(q, HOST)) {
		return id(q);
	} else if (accept(q, NET)) {
		return id(q);
	} else if (accept(q, PORT)) {
		return id(q);
	}

	return 0;
}

static int
rule(struct filter_input *q)
{
	if (rule_without_direction(q)) {
		return 1;
	}

	if (accept(q, SRC)) {
		return rule(q);
	} else if (accept(q, DST)) {
		return rule(q);
	} else {
		return 0;
	}
}

static int
factor(struct filter_input *f)
{
	if (rule(f)) {
		/* */
	} else if (accept(f, LPAREN)) {
		if (!expression(f)) {
			return 0;
		}
		if (!expect(f, RPAREN)) {
			mkerror(f, "Expected ')' after expression");
			return 0;
		}
	} else {
		mkerror(f, "Syntax error");
		return 0;
	}

	return 1;
}

static int
term(struct filter_input *f)
{
	if (!factor(f)) {
		return 0;
	}

	while (accept(f, AND)) {
		if (!factor(f)) {
			return 0;
		}
	}

	return 1;
}

static int
expression(struct filter_input *f)
{
	if (accept(f, NOT)) {
		/* inverse */
	}

	if (!term(f)) {
		return 0;
	}

	while (accept(f, OR)) {
		if (!term(f)) {
			return 0;
		}
	}

	return 1;
}

void
parse_filter(struct filter_input *q)
{
	read_token(q);
	if (q->error) {
		return;
	}

	if (q->end) {
		/* allow empty filter */
		return;
	}

	if (!expression(q)) {
		return;
	}

	if (!q->end) {
		char err[ERR_MSG_LEN];

		sprintf(err, "Unexpected token '%s' after expression",
			q->current_token.data.str);
		mkerror(q, err);
	}
}

