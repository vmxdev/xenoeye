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
	int stop_symbols[] = {' ', '\t', '\r', '\n', '(', ')', 0};
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

void
read_token(struct filter_input *q)
{
	q->current_token.str_len = 0;

	EXPECT(q, whitespace);

	if (*(q->s) == '(') {
		SINGLE_SYM_TOKEN(q, LPAREN);
	} else if (*(q->s) == ')') {
		SINGLE_SYM_TOKEN(q, RPAREN);
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

#define MATCH(S) strcasecmp(q->current_token.data.str, S) == 0

		if (MATCH("src")) {
			q->current_token.id = SRC;
		} else if (MATCH("dst")) {
			q->current_token.id = DST;
		} else if (MATCH("host")) {
			q->current_token.id = HOST;
		} else if (MATCH("net")) {
			q->current_token.id = NET;
		} else if (MATCH("port")) {
			q->current_token.id = PORT;
		} else if (MATCH("or")) {
			q->current_token.id = OR;
		} else if (MATCH("and")) {
			q->current_token.id = AND;
		} else if (MATCH("not")) {
			q->current_token.id = NOT;
		} else {
			q->current_token.id = ID;
		}

#undef MATCH
	}

	/*printf("token: '%s', id: %d\n", q->current_token.data.str, q->current_token.id);*/
}

