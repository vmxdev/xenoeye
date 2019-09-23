#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "query.h"

static int
is_idsym(int c)
{
	if (isalnum(c)) return 1;
	if (c == '_') return 1;
	if (c == '$') return 1;

	return 0;
}

void
read_token(struct query_input *i)
{

#define CHECK_EOF()               \
	if (*(i->s) == '\0') {    \
		i->eof = 1;       \
		return;           \
	}

#define BREAK_IF_EOF()            \
	if (*(i->s) == '\0') {    \
		break;            \
	}

#define NEXT_SYMBOL()             \
do {                              \
	i->s++;                   \
	i->col++;                 \
} while (0)

again:
	/* skip white space */
	for (;;) {
		CHECK_EOF();
		if (*(i->s) == '\n') {
			i->line++;
			i->col = 1;
		}
		if (isspace(*(i->s))) {
			NEXT_SYMBOL();
			CHECK_EOF();
		} else {
			break;
		}
	}

	/* skip comment */
	if (*(i->s) == '/') {

#define IF_NEXT(SYM)           \
	NEXT_SYMBOL();         \
	if (*(i->s) == SYM)

		IF_NEXT('*') {
			for (;;) {
				IF_NEXT('\n') {
					i->line++;
					i->col = 1;
				}
				if (*(i->s) != '*') {
					continue;
				}
				IF_NEXT('/') {
					i->s++;
					goto again;
				}
				i->s--;
			}
		}
		i->s--;
	}


#define SCAN_UNTIL(COND)                                     \
	do {                                                 \
		i->current_token.data.str[l] = *(i->s);      \
		l++;                                         \
		if (l > sizeof(i->current_token.data.str)) { \
			mkerror(i, "Token is too big");      \
			return;                              \
		}                                            \
		i->s++;                                      \
		i->col++;                                    \
	} while (COND)


	/* keywords and id's */
	if (isalpha(*(i->s))) {
                size_t l = 0;

		SCAN_UNTIL(is_idsym(*(i->s)));

		i->current_token.data.str[l] = '\0';
#define SCAN_STRING(STR, TOKEN) else if                     \
	(strcasecmp(STR, i->current_token.data.str) == 0) { \
		i->current_token.id = TOKEN;                \
	}
		if (0) {}
		SCAN_STRING("in", IN)
		SCAN_STRING("or", OR)
		SCAN_STRING("and", AND)
		SCAN_STRING("saddr", SADDR)
		SCAN_STRING("daddr", DADDR)
		SCAN_STRING("sport", SPORT)
		SCAN_STRING("dport", DPORT)
		else {
			i->current_token.id = ID;
		}
#undef SCAN_STRING
		return;
	}

	/* number */
	if (isdigit(*(i->s))) {
		size_t l = 0;

		SCAN_UNTIL(isdigit(*(i->s)));

		if (is_idsym(*(i->s))) {
			mkerror(i, "Incorrect token");
			return;
		}

		i->current_token.data.str[l] = '\0';
		i->current_token.data.num = atoi(i->current_token.data.str);
		i->current_token.id = NUM;
		return;
	}

	/* string */
	if (*(i->s) == '\"') {
		size_t l = 0;

		i->current_token.id = STRING_INCOMPLETE;
		NEXT_SYMBOL();
		CHECK_EOF();
		for (;;) {
			if (*(i->s) == '\"') {
				break;
			}

			if (*(i->s) == '\\') {
				/* escaped symbols */
				NEXT_SYMBOL();
				BREAK_IF_EOF();
				switch (*(i->s)) {
					case 'n':
						i->current_token.data.str[l]
							= '\n';
						break;
					case '\"':
						i->current_token.data.str[l]
							= '\"';
						break;
					case '\'':
						i->current_token.data.str[l]
							= '\'';
						break;
				}
			} else {
				i->current_token.data.str[l] = *(i->s);
			}
			l++;
			if (l > sizeof(i->current_token.data.str)) {
				mkerror(i, "Token is too big");
				return;
			}
			NEXT_SYMBOL();
			BREAK_IF_EOF();
		}

		if (*(i->s) != '\"') {
			mkerror(i, "Incorrect string token");
			return;
		}

		i->current_token.data.str[l] = '\0';
		i->current_token.id = STRING;
		NEXT_SYMBOL();
		return;
	}

#define SINGLE_SYM_TOKEN(SYM, ID)                    \
	if (*(i->s) == SYM) {                        \
		i->current_token.data.str[0] = SYM;  \
		i->current_token.data.str[1] = '\0'; \
		i->current_token.id = ID;            \
		NEXT_SYMBOL();                       \
		return;                              \
	}

	SINGLE_SYM_TOKEN(',', COMMA);
	SINGLE_SYM_TOKEN('|', VBAR);
	SINGLE_SYM_TOKEN('+', PLUS);
	SINGLE_SYM_TOKEN('-', MINUS);

	SINGLE_SYM_TOKEN('=', ASSIGN);
	SINGLE_SYM_TOKEN('(', LPAREN);
	SINGLE_SYM_TOKEN(')', RPAREN);

#undef SINGLE_SYM_TOKEN
#undef SCAN_UNTIL
#undef CHECK_EOF
#undef NEXT_SYMBOL
#undef IF_NEXT
	{
		char msg[128];

		snprintf(msg, sizeof(msg), "Unrecognized token '%c'", i->s[0]);
		mkerror(i, msg);
		return;
	}
}


