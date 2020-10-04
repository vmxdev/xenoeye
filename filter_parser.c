#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filter.h"

static int expression(struct filter_input *q, struct filter_expr *e);

static int
filter_add_simple_filter(struct filter_expr *e, enum FILTER_SIMPLE_TYPE type)
{
	struct filter_op *tmpfo;
	struct filter_simple *fs;

	fs = malloc(sizeof(struct filter_simple));
	if (!fs) {
		goto fail_filter_malloc;
	}
	fs->type = type;
	fs->n = 0;
	fs->data = NULL;


	tmpfo = realloc(e->filter, sizeof(struct filter_op) * (e->n + 1));
	if (!tmpfo) {
		goto fail_realloc;
	}
	e->filter = tmpfo;

	e->filter[e->n].op = FILTER_OP_SIMPLE;
	e->filter[e->n].arg = fs;
	e->n++;

	return 1;

fail_realloc:
	free(fs);
fail_filter_malloc:
	return 0;
}

static int
filter_add_to_simple_filter(struct filter_expr *e, struct token *tok)
{
	struct filter_op *fo;
	struct filter_simple *fs;
	union filter_simple_data *tmpfsd;

	if (e->n < 1) {
		return 0;
	}

	fo = &(e->filter[e->n - 1]);
	if (fo->op != FILTER_OP_SIMPLE) {
		return 0;
	}

	fs = fo->arg;
	tmpfsd = realloc(fs->data,
		sizeof(union filter_simple_data) * (fs->n + 1));
	if (!tmpfsd) {
		return 0;
	}

	fs->data = tmpfsd;
	fs->n++;

	return 1;
}

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
id(struct filter_input *q, struct filter_expr *e)
{
	if (!expect(q, ID)) {
		mkerror(q, "Expected ID");
		return 0;
	}

	filter_add_to_simple_filter(e, &q->current_token);

	/* optional OR's */
	for (;;) {
		if (!accept(q, OR)) {
			break;
		}

		if (accept(q, ID)) {
			continue;
		}
		expression(q, e);
	}

	return 1;
}

static int
rule_without_direction(struct filter_input *q, struct filter_expr *e)
{
	if (accept(q, HOST)) {
		filter_add_simple_filter(e, FILTER_SIMPLE_NET);
		return id(q, e);
	} else if (accept(q, NET)) {
		filter_add_simple_filter(e, FILTER_SIMPLE_NET);
		return id(q, e);
	} else if (accept(q, PORT)) {
		filter_add_simple_filter(e, FILTER_SIMPLE_PORT);
		return id(q, e);
	}

	return 0;
}

static int
rule(struct filter_input *q, struct filter_expr *e)
{
	if (rule_without_direction(q, e)) {
		return 1;
	}

	if (accept(q, SRC)) {
		return rule(q, e);
	} else if (accept(q, DST)) {
		return rule(q, e);
	} else {
		return 0;
	}
}

static int
factor(struct filter_input *f, struct filter_expr *e)
{
	if (rule(f, e)) {
		/* */
	} else if (accept(f, LPAREN)) {
		if (!expression(f, e)) {
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
term(struct filter_input *f, struct filter_expr *e)
{
	if (!factor(f, e)) {
		return 0;
	}

	while (accept(f, AND)) {
		if (!factor(f, e)) {
			return 0;
		}
	}

	return 1;
}

static int
expression(struct filter_input *f, struct filter_expr *e)
{
	if (accept(f, NOT)) {
		/* inverse */
	}

	if (!term(f, e)) {
		return 0;
	}

	while (accept(f, OR)) {
		if (!term(f, e)) {
			return 0;
		}
	}

	return 1;
}

struct filter_expr *
parse_filter(struct filter_input *f)
{
	struct filter_expr *e;

	e = malloc(sizeof(struct filter_expr));
	if (!e) {
		return NULL;
	}
	memset(e, 0, sizeof(struct filter_expr));

	read_token(f);
	if (f->error) {
		return e;
	}

	if (f->end) {
		/* allow empty filter */
		return e;
	}

	if (!expression(f, e)) {
		return e;
	}

	if (!f->end) {
		char err[ERR_MSG_LEN];

		sprintf(err, "Unexpected token '%s' after expression",
			f->current_token.data.str);
		mkerror(f, err);
	}

	return e;
}

