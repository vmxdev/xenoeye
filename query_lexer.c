#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "query.h"

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

#define EXPECT_SYM_IN_KW(I, C1, C2)                                         \
do {                                                                        \
	I->s++;                                                             \
	CHECK_END_UNEXP(I, "unexpected end of input inside keyword");       \
	if ((*(I->s) != C1) && ((*(I->s) != C2))) {                         \
		I->error = 1;                                               \
		sprintf(I->errmsg, "expected '%c', got '%c'", C1, *(I->s)); \
		return;                                                     \
	}                                                                   \
	I->col++;                                                           \
	I->current_token.data.str[I->current_token.str_len] = C1;           \
	I->current_token.str_len++;                                         \
} while (0)

#define EXPECT(I, F)                    \
do {                                    \
	F(I);                           \
	if (I->end || I->error) return; \
} while (0)

static void
c_style_comment(struct query_input *q)
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
one_line_comment(struct query_input *q)
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
whitespace(struct query_input *q)
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

void
read_token(struct query_input *q)
{
	q->current_token.str_len = 0;

	EXPECT(q, whitespace);

	if ((*(q->s) == 'h') || (*(q->s) == 'H')) {
		/* host */
		EXPECT_SYM_IN_KW(q, 'o', 'O');
		EXPECT_SYM_IN_KW(q, 's', 'S');
		EXPECT_SYM_IN_KW(q, 't', 'T');
		q->current_token.id = HOST;
	} else if ((*(q->s) == 's') || (*(q->s) == 'S')) {
		/* src */
		EXPECT_SYM_IN_KW(q, 'r', 'R');
		EXPECT_SYM_IN_KW(q, 'c', 'C');
		q->current_token.id = SRC;
	}
}

