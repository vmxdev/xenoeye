#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filter.h"


#define READ_TOKEN_CHECK(I)      \
do {                             \
	read_token(I);           \
	if (I->error) {          \
		return 0;        \
	}                        \
} while (0)


static int expression(struct filter_input *q, struct filter_expr *e);

static int
accept(struct filter_input *i, enum TOKEN_ID token)
{
	if (i->current_token.id != token) {
		return 0;
	}

	READ_TOKEN_CHECK(i);

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
id(struct filter_input *f, struct filter_expr *e, enum FILTER_BASIC_TYPE type)
{
	if ((f->current_token.id != ID)
		&& (f->current_token.id != INT_RANGE)) {

		mkerror(f, "Expected ID, INT or INT_RANGE");
		return 0;
	}

	filter_add_to_basic_filter(f, e, &f->current_token, type);

	READ_TOKEN_CHECK(f);

	/* optional OR's */
	for (;;) {
		if (!accept(f, OR)) {
			break;
		}

		if ((f->current_token.id == ID)
			|| (f->current_token.id == INT_RANGE)) {

			filter_add_to_basic_filter(f, e, &f->current_token,
				type);

			READ_TOKEN_CHECK(f);
			continue;
		}
		READ_TOKEN_CHECK(f);

		expression(f, e);
		filter_add_op(e, FILTER_OP_OR);
	}

	return 1;
}

static int
rule_without_direction(struct filter_input *q, struct filter_expr *e, int dir)
{

	if (0) {

#define FIELD(NAME, STR, TYPE, SRC, DST)                              \
	} else if (accept(q, NAME)) {                                 \
		filter_add_basic_filter(e, FILTER_BASIC_##TYPE,       \
			FILTER_BASIC_NAME_##NAME, dir);               \
		return id(q, e, FILTER_BASIC_##TYPE);
#include "filter.def"

	}

	return 0;
}

static int
rule(struct filter_input *q, struct filter_expr *e)
{
	if (rule_without_direction(q, e, FILTER_BASIC_DIR_BOTH)) {
		return 1;
	}

	if (accept(q, SRC)) {
		return rule_without_direction(q, e, FILTER_BASIC_DIR_SRC);
	} else if (accept(q, DST)) {
		return rule_without_direction(q, e, FILTER_BASIC_DIR_DST);
	} else {
		return 0;
	}
}

static int
factor(struct filter_input *f, struct filter_expr *e)
{
	if (rule(f, e)) {
		/* ok */
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
		filter_add_op(e, FILTER_OP_AND);
	}

	return 1;
}

static int
expression(struct filter_input *f, struct filter_expr *e)
{
	if (accept(f, NOT)) {
		/* inverse */
		if (!filter_add_op(e, FILTER_OP_NOT)) {
			return 0;
		}
	}

	if (!term(f, e)) {
		return 0;
	}

	while (accept(f, OR)) {
		if (!term(f, e)) {
			return 0;
		}
		filter_add_op(e, FILTER_OP_OR);
	}

	return 1;
}

struct filter_expr *
parse_filter(struct filter_input *f)
{
	struct filter_expr *e;

	e = calloc(1, sizeof(struct filter_expr));
	if (!e) {
		return NULL;
	}

	READ_TOKEN_CHECK(f);

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

static int
field_without_direction(struct filter_input *in, struct field *fld, char *err,
	int dir)
{
	if (0) {

#define FIELD(NAME, STR, TYPE, SRC, DST)                                      \
	} else if (accept(in, NAME)) {                                        \
		strcpy(fld->name, STR);                                       \
		fld->direction = dir;                                         \
		fld->type = FILTER_BASIC_##TYPE;                              \
		if (dir == FILTER_BASIC_DIR_BOTH) {                           \
			if (strcmp(#SRC, #DST) != 0) {                        \
				sprintf(err, "This field requires direction");\
				return 0;                                     \
			}                                                     \
		}                                                             \
		return 1;
#include "filter.def"

	}

	sprintf(err, "Unknown field '%s'", in->current_token.data.str);
	return 0;
}

static int
field_without_order(struct filter_input *in, struct field *fld, char *err)
{
	if (accept(in, BITS)) {
		strcpy(fld->name, "bits");
		fld->direction = FILTER_BASIC_DIR_BOTH;
		fld->type = 0;
		return 1;
	}
	if (accept(in, PACKETS)) {
		strcpy(fld->name, "packets");
		fld->direction = FILTER_BASIC_DIR_BOTH;
		fld->type = 0;
		return 1;
	}
	if (accept(in, OCTETS)) {
		strcpy(fld->name, "octets");
		fld->direction = FILTER_BASIC_DIR_BOTH;
		fld->type = 0;
		return 1;
	}

	if (field_without_direction(in, fld, err, FILTER_BASIC_DIR_BOTH)) {
		return 1;
	}

	if (accept(in, SRC)) {
		return field_without_direction(in, fld, err, 
			FILTER_BASIC_DIR_SRC);
	} else if (accept(in, DST)) {
		return field_without_direction(in, fld, err,
			FILTER_BASIC_DIR_DST);
	}

	return 0;
}

int
parse_field(char *s, struct field *fld, char *err)
{
	struct filter_input in;

	memset(&in, 0, sizeof(struct filter_input));
	in.s = s;
	in.line = 1;

	READ_TOKEN_CHECK((&in));
	if (in.end) {
		sprintf(err, "Empty field not allowed");
		return 0;
	}

	if (!field_without_order(&in, fld, err)) {
		return 0;
	}

	fld->descending = 0;
	if (accept(&in, DESC)) {
		fld->descending = 1;
	} else if (accept(&in, ASC)) {
		/* default */
	}

	if (!in.end) {
		sprintf(err, "Extra symbols after field name");
		return 0;
	}

	return 1;
}

