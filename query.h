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

	CIDR,

	SADDR,
	DADDR,
	SPORT,
	DPORT
};

struct CIDR
{
	uint8_t addr[4];
	uint8_t mask;
};

struct token
{
	enum TOKEN_ID id;
	union data {
		char str[TOKEN_MAX_SIZE];
		int num;
		struct CIDR cidr;
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

void read_token(struct query_input *i);
void mkerror(struct query_input *i, char *msg);

#endif

