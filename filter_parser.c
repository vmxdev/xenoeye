#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <ctype.h>

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

	for (;;) {
		if (!accept_(f, OR)) {
			/* optional OR's */
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
nf_field_to_off(const char *name, unsigned int *off, unsigned int *size)
{
	if (0) {
#define FIELD(NAME, DESC, FLDTYPE, FLDID, SIZEMIN, SIZEMAX)           \
	} else if (strcmp(#NAME, name) == 0) {                        \
		*off = offsetof(struct nf_flow_info, NAME);           \
		*size = SIZEMAX;                                      \
		return 1;
#include "netflow.def"
	}

	return 0;
}

static int
nf_aggr_field_off_size(struct filter_input *q, unsigned int *off,
	unsigned int *size)
{
	if (0) {

#define FIELD(NAME, STR, FLD, SCALE)                                  \
	} else if (accept_(q, NAME)) {                                \
		return nf_field_to_off(#FLD, off, size);
#include "filter-ag.def"

	}

	return 0;
}

static int
nf_field_off_size(struct filter_input *in, unsigned int *off,
	unsigned int *size, int dir)
{
	if (0) {

#define FIELD(NAME, STR, TYPE, SRC, DST)                                     \
	} else if (accept_(in, NAME)) {                                      \
		if (dir == FILTER_BASIC_DIR_SRC) {                           \
			return nf_field_to_off(#SRC, off, size);             \
		} else if (dir == FILTER_BASIC_DIR_DST) {                    \
			return nf_field_to_off(#DST, off, size);             \
		} else {                                                     \
			if (strcmp(#SRC, #DST) != 0) {                       \
				mkerror(in, "This field requires direction");\
				return 0;                                    \
			}                                                    \
			return nf_field_to_off(#SRC, off, size);             \
		}
#include "filter.def"

	}

	return 0;
}

static int
function_div_parse(struct filter_input *in, struct function_div *div)
{
	if (!accept_(in, DIV)) {
		return 0;
	}

	if (!accept_(in, LPAREN)) {
		mkerror(in, "Expected '(' after 'div'");
		return 0;
	}

	if (!nf_aggr_field_off_size(in, &div->dividend_off,
		&div->dividend_size)) {

		mkerror(in, "Expected aggregable field name");
		return 0;
	}

	if (!accept_(in, COMMA)) {
		mkerror(in, "Expected ',' after field name");
		return 0;
	}

	if (!nf_aggr_field_off_size(in, &div->divisor_off,
		&div->divisor_size)) {

		mkerror(in, "Expected aggregable field name after comma");
		return 0;
	}

	if (!accept_(in, RPAREN)) {
		mkerror(in, "Expected ')'");
		return 0;
	}

	return 1;
}

static int
function_div(struct filter_input *in, struct filter_expr *e)
{
	struct function_div div;
	struct filter_basic *fb;

	if (!function_div_parse(in, &div)) {
		return 0;
	}

	if (!filter_add_basic_filter(e, FILTER_BASIC_RANGE,
			FILTER_BASIC_NAME_DIV,
			FILTER_BASIC_DIR_NONE)) {

		return 0;
	}

	fb = e->filter[e->n - 1].arg;
	fb->func_data.div = malloc(sizeof(struct function_div));
	if (!fb->func_data.div) {
		return 0;
	}

	*fb->func_data.div = div;

	fb->is_func = 1;

	return id(in, e, FILTER_BASIC_RANGE);
}


static int
function_min_parse(struct filter_input *in, struct function_min *min)
{
	if (!accept_(in, MIN)) {
		return 0;
	}

	if (!accept_(in, LPAREN)) {
		mkerror(in, "Expected '(' after 'min'");
		return 0;
	}

	/* arg1 */
	if (accept_(in, SRC)) {
		if (!nf_field_off_size(in, &min->arg1_off, &min->arg1_size,
			FILTER_BASIC_DIR_SRC)) {

			return 0;
		}
	} else if (accept_(in, DST)) {
		if (!nf_field_off_size(in, &min->arg1_off, &min->arg1_size,
			FILTER_BASIC_DIR_DST)) {

			return 0;
		}
	} else {
		if (!nf_field_off_size(in, &min->arg1_off, &min->arg1_size,
			FILTER_BASIC_DIR_BOTH)) {

			return 0;
		}
	}


	if (!accept_(in, COMMA)) {
		mkerror(in, "Expected ',' after field name");
		return 0;
	}

	/* arg2 */
	if (accept_(in, SRC)) {
		if (!nf_field_off_size(in, &min->arg2_off, &min->arg2_size,
			FILTER_BASIC_DIR_SRC)) {

			return 0;
		}
	} else if (accept_(in, DST)) {
		if (!nf_field_off_size(in, &min->arg2_off, &min->arg2_size,
			FILTER_BASIC_DIR_DST)) {

			return 0;
		}
	} else {
		if (!nf_field_off_size(in, &min->arg2_off, &min->arg2_size,
			FILTER_BASIC_DIR_BOTH)) {

			return 0;
		}
	}

	if (!accept_(in, RPAREN)) {
		mkerror(in, "Expected ')'");
		return 0;
	}

	return 1;
}


static int
function_min(struct filter_input *in, struct filter_expr *e)
{
	struct function_min min;
	struct filter_basic *fb;

	if (!function_min_parse(in, &min)) {
		return 0;
	}

	if (!filter_add_basic_filter(e, FILTER_BASIC_RANGE,
			FILTER_BASIC_NAME_MIN,
			FILTER_BASIC_DIR_NONE)) {

		return 0;
	}

	fb = e->filter[e->n - 1].arg;
	fb->func_data.min = malloc(sizeof(struct function_min));
	if (!fb->func_data.min) {
		return 0;
	}

	*fb->func_data.min = min;

	fb->is_func = 1;

	return id(in, e, FILTER_BASIC_RANGE);
}



static int
rule(struct filter_input *q, struct filter_expr *e)
{
	if (function_div(q, e)) {
		return 1;
	}

	if (function_min(q, e)) {
		return 1;
	}

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
	int inverse = 0;

	if (accept_(f, NOT)) {
		inverse = 1;
	}

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

	if (inverse) {
		if (!filter_add_op(e, FILTER_OP_NOT)) {
			return 0;
		}
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


static void
field_mk_names(struct filter_input *in, char *s,
	struct field *fld, const char *sfx)
{
	size_t len;
	size_t i;

	len = in->s - s;
	/* copy name */
	memcpy(fld->name, s, len);
	fld->name[len] = '\0';
	if (sfx) {
		/* remove suffix */
		size_t slen = strlen(sfx);
		if (strcasecmp(fld->name + len - slen, sfx) == 0) {
			*(fld->name + len - slen) = '\0';
		}
		/* remove white space at string tail */
		for (;;) {
			size_t nlen = strlen(fld->name);
			if (nlen <= 1) {
				break;
			}

			if (fld->name[nlen - 1] != ' ') {
				break;
			}

			fld->name[nlen - 1] = '\0';
		}
	}

	len = strlen(fld->name);
	for (i=0; i<len; i++) {
		if (isalnum(fld->name[i])) {
			fld->sql_name[i] = fld->name[i];
		} else {
			fld->sql_name[i] = '_';
		}
	}
	fld->sql_name[len] = '\0';
}

static int
field_without_order(struct filter_input *in, struct field *fld, char *err)
{
	/* check if field is aggregable */
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

/* fields from 'filter-ag.def' */
#define FIELD(NAME, STR, FLD, SCALE)                                          \
	AGGR_FIELD(in, fld, NAME, FLD, SCALE);
#include "filter-ag.def"

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

	if (function_div_parse(&in, &fld->func_data.div)) {
		fld->is_func = 1;
		fld->id = DIV;
		fld->type = FILTER_BASIC_RANGE;
		fld->size = sizeof(uint64_t);
	} else if (function_min_parse(&in, &fld->func_data.min)) {
		fld->is_func = 1;
		fld->id = MIN;
		fld->type = FILTER_BASIC_RANGE;
		fld->size = sizeof(uint64_t);
	} else {
		/* parse field without ASC/DESC suffix */
		if (!field_without_order(&in, fld, err)) {
			return 0;
		}
	}

	/* optional order */
	fld->descending = 0;
	if (accept_(&in, DESC)) {
		fld->descending = 1;
		field_mk_names(&in, s, fld, "desc");
	} else if (accept_(&in, ASC)) {
		/* default order */
		field_mk_names(&in, s, fld, "asc");
	} else {
		/* no order */
		field_mk_names(&in, s, fld, NULL);
	}

	if (!in.end) {
		sprintf(err, "Extra symbols after field name");
		return 0;
	}

	return 1;
}

