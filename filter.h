#ifndef query_h_included
#define query_h_included

#include <stdint.h>

#define ERR_MSG_LEN     1024
#define TOKEN_MAX_SIZE  512

enum TOKEN_ID
{
	ID,
	LPAREN,
	RPAREN,
	OR,
	AND,
	NOT,

	SRC,
	DST,
	HOST,
	NET,
	PORT
};

struct CIDR
{
	uint8_t ipv4[4];
	uint8_t ipv6[16];
	uint8_t mask;
};

struct token
{
	enum TOKEN_ID id;
	int str_len;
	union data {
		char str[TOKEN_MAX_SIZE];
		int num;
		struct CIDR cidr;
	} data;
};

struct query_input
{
	char *s;
	int end;
	int line, col;

	int error;
	char errmsg[ERR_MSG_LEN];

	struct token current_token;
};

void parse_filter(struct query_input *i);
void mkerror(struct query_input *i, char *msg);

void read_token(struct query_input *i);

#endif

