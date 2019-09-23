#ifndef query_h_included
#define query_h_included

#include <stdint.h>

#define ERR_MSG_LEN     1024
#define TOKEN_MAX_SIZE  512

enum TOKEN_ID
{
	ID,
	NUM,
	STRING_INCOMPLETE,
	STRING,
	COMMA,
	VBAR,
	PLUS,
	MINUS,
	ASSIGN,
	LPAREN,
	RPAREN,
	IN,
	OR,
	AND,

	SADDR,
	DADDR,
	SPORT,
	DPORT
};

struct token
{
	enum TOKEN_ID id;
	union data {
		char str[TOKEN_MAX_SIZE];
		int num;
		uint32_t ip_addr;
	} data;
};

struct query_input
{
	char *s;
	int eof;
	int line, col;

	int error;
	char errmsg[ERR_MSG_LEN];

	struct token current_token;
};

void mkerror(struct query_input *i, char *msg);

#endif

