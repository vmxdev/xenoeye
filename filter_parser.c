#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include "filter.h"
#include "netflow.h"


#define READ_TOKEN_CHECK(I)      \
do {                             \
	read_token(I);           \
	if (I->error) {          \
		return 0;        \
	}                        \
} while (0)


static int expression(struct filter_input *q, struct filter_expr *e);

static int
accept_(struct filter_input *i, enum TOKEN_ID token)
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
	if (!accept_(i, token)) {
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
		if (!accept_(f, OR)) {
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
	} else if (accept_(q, NAME)) {                                \
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

	if (accept_(q, SRC)) {
		return rule_without_direction(q, e, FILTER_BASIC_DIR_SRC);
	} else if (accept_(q, DST)) {
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
	} else if (accept_(f, LPAREN)) {
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

	while (accept_(f, AND)) {
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
	if (accept_(f, NOT)) {
		/* inverse */
		if (!filter_add_op(e, FILTER_OP_NOT)) {
			return 0;
		}
	}

	if (!term(f, e)) {
		return 0;
	}

	while (accept_(f, OR)) {
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
field_map_nf_flow_info(struct field *fld, const char *name)
{
	if (0) {

#define FIELD(NAME, DESC, FLDTYPE, FLDID, SIZEMIN, SIZEMAX)                   \
	} else if (strcmp(#NAME, name) == 0) {                                \
		fld->nf_offset = offsetof(struct nf_flow_info, NAME);         \
		fld->size = SIZEMAX;                                          \
		return 1;
#include "netflow.def"

	}

	return 0;
}

static int
field_without_direction(struct filter_input *in, struct field *fld, char *err,
	int dir)
{
	if (0) {

#define FIELD(NAME, STR, TYPE, SRC, DST)                                      \
	} else if (accept_(in, NAME)) {                                       \
		fld->type = FILTER_BASIC_##TYPE;                              \
		fld->id = NAME;                                               \
		if (dir == FILTER_BASIC_DIR_BOTH) {                           \
			if (strcmp(#SRC, #DST) != 0) {                        \
				sprintf(err, "This field requires direction");\
				return 0;                                     \
			}                                                     \
			return field_map_nf_flow_info(fld, #SRC);             \
		} else if (dir == FILTER_BASIC_DIR_SRC) {                     \
			return field_map_nf_flow_info(fld, #SRC);             \
		} else {                                                      \
			return field_map_nf_flow_info(fld, #DST);             \
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
	/* check if field is aggregatable */
#define AGGR_FIELD(IN, FLD, NAME, NF_FIELD, SCALE)                            \
do {                                                                          \
	if (accept_(IN, NAME)) {                                              \
		FLD->id = NAME;                                               \
		FLD->type = FILTER_BASIC_RANGE;                               \
		FLD->size = sizeof(uint64_t);                                 \
		FLD->nf_offset = offsetof(struct nf_flow_info, NF_FIELD);     \
		FLD->aggr = 1;                                                \
		FLD->scale = SCALE;                                           \
		return 1;                                                     \
	}                                                                     \
} while (0)

	AGGR_FIELD(in, fld, OCTETS, in_bytes, 1);
	AGGR_FIELD(in, fld, BITS, in_bytes, 8);
	AGGR_FIELD(in, fld, PACKETS, in_pkts, 1);

#undef AGGR_FIELD

	/* field from list 'filter.def' */
	if (field_without_direction(in, fld, err, FILTER_BASIC_DIR_BOTH)) {
		return 1;
	}

	/* optional SRC/DST */
	if (accept_(in, SRC)) {
		return field_without_direction(in, fld, err, 
			FILTER_BASIC_DIR_SRC);
	} else if (accept_(in, DST)) {
		return field_without_direction(in, fld, err,
			FILTER_BASIC_DIR_DST);
	}

	return 0;
}

/*
 * Try to parse field. Field is given in form '[src/dst] field [asc/desc]'
 * for example 'src host asc' or 'bits desc'
 */
int
parse_field(char *s, struct field *fld, char *err)
{
	struct filter_input in;

	memset(&in, 0, sizeof(struct filter_input));
	in.s = s;
	in.line = 1;

	memset(fld, 0, sizeof(struct field));

	READ_TOKEN_CHECK((&in));
	if (in.end) {
		sprintf(err, "Empty field not allowed");
		return 0;
	}

	/* parse field without ASC/DESC suffix */
	if (!field_without_order(&in, fld, err)) {
		return 0;
	}

	/* optional order */
	fld->descending = 0;
	if (accept_(&in, DESC)) {
		fld->descending = 1;
	} else if (accept_(&in, ASC)) {
		/* default */
	}

	if (!in.end) {
		sprintf(err, "Extra symbols after field name");
		return 0;
	}

	return 1;
}

