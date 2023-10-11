/*
 * xenoeye
 *
 * Copyright (c) 2023, Vladimir Misyurov
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */
#include <stdlib.h>

#include "filter.h"
#include "netflow.h"

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


/* div */
int
function_div_parse(struct filter_input *in, struct function_div *div,
	enum TOKEN_ID *tok)
{
	if (accept_(in, DIV)) {
		*tok = DIV;
	} else if (accept_(in, DIV_L)) {
		*tok = DIV_L;
		div->is_log = 1;
	} else if (accept_(in, DIV_R)) {
		*tok = DIV_R;
	} else {
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

	if ((*tok == DIV_L) || (*tok == DIV_R)) {
		int k;
		if (!accept_(in, COMMA)) {
			mkerror(in, "Expected ',' after second field name");
			return 0;
		}

		k = in->current_token.data.range.low;
		if (!accept_(in, INT_RANGE)) {
			mkerror(in, "Expected INT");
			return 0;
		}
		div->k = k;
	}

	if (!accept_(in, RPAREN)) {
		mkerror(in, "Expected ')'");
		return 0;
	}

	return 1;
}

int
function_div(struct filter_input *in, struct filter_expr *e,
	enum TOKEN_ID *tok)
{
	struct function_div div;
	struct filter_basic *fb;

	div.is_log = 0;
	div.k = 1;
	if (!function_div_parse(in, &div, tok)) {
		return 0;
	}

	if (*tok == DIV) {
		if (!filter_add_basic_filter(e, FILTER_BASIC_RANGE,
				FILTER_BASIC_NAME_DIV,
				FILTER_BASIC_DIR_NONE)) {

			return 0;
		}
	} else if (*tok == DIV_L) {
		if (!filter_add_basic_filter(e, FILTER_BASIC_RANGE,
				FILTER_BASIC_NAME_DIV_L,
				FILTER_BASIC_DIR_NONE)) {

			return 0;
		}
	} else if (*tok == DIV_R) {
		if (!filter_add_basic_filter(e, FILTER_BASIC_RANGE,
				FILTER_BASIC_NAME_DIV_R,
				FILTER_BASIC_DIR_NONE)) {

			return 0;
		}
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

/* min */
static int
parse_nonaggr_field(struct filter_input *in, unsigned int *off,
	unsigned int *size)
{
	if (accept_(in, SRC)) {
		if (!nf_field_off_size(in, off, size, FILTER_BASIC_DIR_SRC)) {
			return 0;
		}
	} else if (accept_(in, DST)) {
		if (!nf_field_off_size(in, off, size, FILTER_BASIC_DIR_DST)) {
			return 0;
		}
	} else {
		if (!nf_field_off_size(in, off, size, FILTER_BASIC_DIR_BOTH)) {
			return 0;
		}
	}

	return 1;
}


int
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
	if (!parse_nonaggr_field(in, &min->arg1_off, &min->arg1_size)) {
		mkerror(in, "Incorrect field name");
		return 0;
	}

	if (!accept_(in, COMMA)) {
		mkerror(in, "Expected ',' after field name");
		return 0;
	}

	/* arg2 */
	if (!parse_nonaggr_field(in, &min->arg2_off, &min->arg2_size)) {
		mkerror(in, "Incorrect field name after comma");
		return 0;
	}

	if (!accept_(in, RPAREN)) {
		mkerror(in, "Expected ')'");
		return 0;
	}

	return 1;
}


int
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

int
function_mfreq_parse(struct filter_input *in, struct function_mfreq *mfreq)
{
	if (!accept_(in, MFREQ)) {
		return 0;
	}

	if (!accept_(in, LPAREN)) {
		mkerror(in, "Expected '(' after 'mfreq'");
		return 0;
	}

	/* arg1 */
	if (!parse_nonaggr_field(in, &mfreq->arg1_off, &mfreq->arg1_size)) {
		mkerror(in, "Incorrect field name");
		return 0;
	}

	if (mfreq->arg1_size > sizeof(uint16_t)) {
		LOG("Field is too big for mfreq");
	}

	if (!accept_(in, COMMA)) {
		mkerror(in, "Expected ',' after field name");
		return 0;
	}

	/* arg2 */
	if (!parse_nonaggr_field(in, &mfreq->arg2_off, &mfreq->arg2_size)) {
		mkerror(in, "Incorrect field name after comma");
		return 0;
	}

	if (mfreq->arg2_size > sizeof(uint16_t)) {
		LOG("Field is too big for mfreq");
	}

	if (!accept_(in, RPAREN)) {
		mkerror(in, "Expected ')'");
		return 0;
	}

	/* init freqmap */
	mfreq->freqmap = calloc(UINT16_MAX + 1, sizeof(uint64_t));
	if (!mfreq->freqmap) {
		LOG("calloc() failed");
		return 0;
	}

	return 1;
}


int
function_mfreq(struct filter_input *in, struct filter_expr *e)
{
	struct function_mfreq mfreq;
	struct filter_basic *fb;

	if (!function_mfreq_parse(in, &mfreq)) {
		return 0;
	}

	if (!filter_add_basic_filter(e, FILTER_BASIC_RANGE,
			FILTER_BASIC_NAME_MFREQ,
			FILTER_BASIC_DIR_NONE)) {

		return 0;
	}

	fb = e->filter[e->n - 1].arg;
	fb->func_data.mfreq = malloc(sizeof(struct function_mfreq));
	if (!fb->func_data.mfreq) {
		return 0;
	}

	*fb->func_data.mfreq = mfreq;

	fb->is_func = 1;

	return id(in, e, FILTER_BASIC_RANGE);
}

/* geo */
int
function_geoip_parse(struct filter_input *in, struct function_geoip *geoip,
	enum TOKEN_ID *tok)
{
	memset(geoip, 0, sizeof(struct function_geoip));

	if (0) {

#define DO(FIELD, SIZE)                            \
	} else if (accept_(in, FIELD)) {           \
		geoip->field = GEOIP_##FIELD;      \
		*tok = FIELD;
FOR_LIST_OF_GEOIP_FIELDS
#undef DO

	} else {
		return 0;
	}

	if (!accept_(in, LPAREN)) {
		mkerror(in, "Expected '(' after GeoIP function");
		return 0;
	}

	/* arg */
	if (!parse_nonaggr_field(in, &geoip->ip_off, &geoip->ip_size)) {
		mkerror(in, "Incorrect field name");
		return 0;
	}

	/* check args? */
	if (!accept_(in, RPAREN)) {
		mkerror(in, "Expected ')'");
		return 0;
	}

	return 1;
}


int
function_geoip(struct filter_input *in, struct filter_expr *e)
{
	struct function_geoip geoip;
	struct filter_basic *fb;
	enum TOKEN_ID tok;

	if (!function_geoip_parse(in, &geoip, &tok)) {
		return 0;
	}


	if (0) {

#define DO(FIELD, SIZE)                                               \
	} else if (tok == FIELD) {                                    \
		if (!filter_add_basic_filter(e, FILTER_BASIC_STRING,  \
				FILTER_BASIC_NAME_##FIELD,            \
				FILTER_BASIC_DIR_NONE)) {             \
			return 0;                                     \
		}
FOR_LIST_OF_GEOIP_FIELDS
#undef DO
	} /* end if */

	fb = e->filter[e->n - 1].arg;
	fb->func_data.geoip = malloc(sizeof(struct function_geoip));
	if (!fb->func_data.geoip) {
		return 0;
	}

	*fb->func_data.geoip = geoip;

	fb->is_func = 1;

	return id(in, e, FILTER_BASIC_STRING);
}

/* as */
int
function_as_parse(struct filter_input *in, struct function_as *as,
	enum TOKEN_ID *tok)
{
	memset(as, 0, sizeof(struct function_as));

	if (accept_(in, ASN)) {
		as->num = 1;
		*tok = ASN;
	} else if (accept_(in, ASD)) {
		as->num = 0;
		*tok = ASD;
	} else {
		return 0;
	}

	if (!accept_(in, LPAREN)) {
		mkerror(in, "Expected '(' after AS function");
		return 0;
	}

	/* arg */
	if (!parse_nonaggr_field(in, &as->ip_off, &as->ip_size)) {
		mkerror(in, "Incorrect field name");
		return 0;
	}

	/* check args? */
	if (!accept_(in, RPAREN)) {
		mkerror(in, "Expected ')'");
		return 0;
	}

	return 1;
}


int
function_as(struct filter_input *in, struct filter_expr *e)
{
	struct function_as as;
	struct filter_basic *fb;
	enum TOKEN_ID tok;

	if (!function_as_parse(in, &as, &tok)) {
		return 0;
	}

	if (tok == ASN) {
		if (!filter_add_basic_filter(e, FILTER_BASIC_RANGE,
				FILTER_BASIC_NAME_ASN,
				FILTER_BASIC_DIR_NONE)) {
			return 0;
		}
	} else {
		if (!filter_add_basic_filter(e, FILTER_BASIC_STRING,
				FILTER_BASIC_NAME_ASD,
				FILTER_BASIC_DIR_NONE)) {
			return 0;
		}
	}

	fb = e->filter[e->n - 1].arg;
	fb->func_data.as = malloc(sizeof(struct function_as));
	if (!fb->func_data.as) {
		return 0;
	}

	*fb->func_data.as = as;

	fb->is_func = 1;

	if (tok == ASN) {
		return id(in, e, FILTER_BASIC_RANGE);
	} else {
		return id(in, e, FILTER_BASIC_STRING);
	}
}

