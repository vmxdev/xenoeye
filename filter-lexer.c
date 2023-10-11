#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "filter.h"

#define CHECK_END(I)                    \
do {                                    \
	if (*(I->s) == '\0') {          \
		I->end = 1;             \
		return;                 \
	}                               \
} while (0)

#define CHECK_END_UNEXP(I, ERR)         \
do {                                    \
	if (*(I->s) == '\0') {          \
		I->end = 1;             \
		I->error = 1;           \
		strcpy(I->errmsg, ERR); \
		return;                 \
	}                               \
} while (0)

#define SINGLE_SYM_TOKEN(I, T)                  \
do {                                            \
	I->current_token.data.str[0] = *(I->s); \
	I->current_token.data.str[1] = '\0';    \
	I->current_token.str_len = 1;           \
	I->s++;                                 \
	I->col++;                               \
	I->current_token.id = T;                \
} while (0)

#define EXPECT(I, F)                    \
do {                                    \
	F(I);                           \
	if (I->end || I->error) return; \
} while (0)

static void
c_style_comment(struct filter_input *q)
{
	for (;;) {
		q->s++;
		CHECK_END_UNEXP(q,
			"unexpected end of input inside the comment");

		q->col++;
		if (*(q->s) == '*') {
			/* end of comment? */
			q->s++;
			CHECK_END_UNEXP(q,
				"unexpected end of input inside the comment");

			q->col++;
			if (*(q->s) == '/') {
				/* end of comment */
				break;
			}
		} else if (*(q->s) == '\n') {
			q->line++;
			q->col = 1;
		}
	}
}

static void
one_line_comment(struct filter_input *q)
{
	for (;;) {
		q->s++;
		CHECK_END(q);

		q->col++;
		if (*(q->s) == '\n') {
			/* end of comment */

			q->line++;
			q->col = 1;
			break;
		}
	}
}

static void
whitespace(struct filter_input *q)
{
	for (;;) {
		CHECK_END(q);
		if ((*(q->s) == ' ') || (*(q->s) == '\t')) {
			q->col++;
		} else if ((*(q->s) == '\n') || (*(q->s) == '\r')) {
			q->line++;
			q->col = 1;
		} else if (*(q->s) == '/') {
			q->s++;

			CHECK_END_UNEXP(q,
				"unexpected end of input after '/'");

			q->col++;
			if (*(q->s) == '*') {
				EXPECT(q, c_style_comment);
			} else if (*(q->s) == '/') {
				EXPECT(q, one_line_comment);
			} else {
				q->col--;
				q->s--;
				break;
			}
		} else {
			/* end of whitespace */
			break;
		}
		q->s++;
	}
}

static int
id_sym(int c)
{
	int stop_symbols[] = {' ', '\t', ',', '\r', '\n', '(', ')', 0};
	int *sptr = stop_symbols;

	if (c == '\0') {
		return 0;
	}

	while (*sptr) {
		if (c == *sptr) {
			return 0;
		}
		sptr++;
	}

	return 1;
}

static int
read_str_token(const char *sample, enum TOKEN_ID *id)
{
#define MATCH(S) strcasecmp(sample, S) == 0

	if (MATCH("src")) {
		*id = SRC;
	} else if (MATCH("dst")) {
		*id = DST;

#define FIELD(NAME, STR, TYPE, SRC, DST)              \
	} else if (MATCH(STR)) {                      \
		*id = NAME;
#include "filter.def"

	} else if (MATCH("or")) {
		*id = OR;
	} else if (MATCH("and")) {
		*id = AND;
	} else if (MATCH("not")) {
		*id = NOT;
	/* filter fields */
	} else if (MATCH("asc")) {
		*id = ASC;
	} else if (MATCH("desc")) {
		*id = DESC;
	/* functions */
	} else if (MATCH("div")) {
		*id = DIV;
	} else if (MATCH("div_r")) {
		*id = DIV_R;
	} else if (MATCH("div_l")) {
		*id = DIV_L;
	}  else if (MATCH("min")) {
		*id = MIN;
	}  else if (MATCH("mfreq")) {
		*id = MFREQ;
/* geoip */
#define DO(FIELD, SIZE)                               \
	}  else if (MATCH(#FIELD)) {                  \
		*id = FIELD;
FOR_LIST_OF_GEOIP_FIELDS
#undef DO
/* as */
	}  else if (MATCH("asn")) {
		*id = ASN;
	}  else if (MATCH("asd")) {
		*id = ASD;

#define FIELD(NAME, STR, FLD, SCALE)                  \
	} else if (MATCH(STR)) {                      \
		*id = NAME;
#include "filter-ag.def"

	} else {
		/* unknown string */
		return 0;
	}

	return 1;
#undef MATCH
}

void
read_token(struct filter_input *q)
{
	q->current_token.str_len = 0;

	EXPECT(q, whitespace);

	if (*(q->s) == '(') {
		SINGLE_SYM_TOKEN(q, LPAREN);
	} else if (*(q->s) == ')') {
		SINGLE_SYM_TOKEN(q, RPAREN);
	} else if (*(q->s) == ',') {
		SINGLE_SYM_TOKEN(q, COMMA);
	} else if (*(q->s) == '\'') {
		/* string */
		q->s++;
		q->col++;

		do {
			/* FIXME: check for \n? */
			q->current_token.data.str[q->current_token.str_len]
				= *(q->s);
			q->current_token.str_len++;

			q->s++;
			q->col++;
		} while (*(q->s) != '\'');

		q->s++;
		q->col++;

		q->current_token.data.str[q->current_token.str_len] = '\0';

		q->current_token.id = STRING;
	} else {
		/* read rest of token */
		do {
			q->current_token.data.str[q->current_token.str_len]
				= *(q->s);
			q->current_token.str_len++;

			q->s++;
			q->col++;
		} while (id_sym(*(q->s)));

		q->current_token.data.str[q->current_token.str_len] = '\0';

		if (!read_str_token(q->current_token.data.str,
			&q->current_token.id)) {

			/* check if it int or range */
			char *endptr;
			long int res;

			res = strtol(q->current_token.data.str, &endptr, 0);
			if (*endptr == '\0') {
				/* number */
				q->current_token.id = INT_RANGE;
				q->current_token.data.range.low
					= q->current_token.data.range.high
					= res;
			} else if (*endptr == '-') {
				long int res2;
				char *endptr2;

				res2 = strtol(endptr + 1, &endptr2, 0);
				if (*endptr2 == '\0') {
					q->current_token.id = INT_RANGE;
					q->current_token.data.range.low = res;
					q->current_token.data.range.high = res2;
				} else {
					q->current_token.id = ID;
				}
			} else {
				q->current_token.id = ID;
			}
		}
	}
}

