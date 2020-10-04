#ifndef filter_h_included
#define filter_h_included

#include <stdint.h>

#define ERR_MSG_LEN     1024
#define TOKEN_MAX_SIZE  512

struct CIDR
{
	int version;
	uint8_t ipv4[4];
	uint8_t ipv6[16];
	unsigned int mask;
};

struct int_range
{
	int low;
	int high;
};


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

struct token
{
	enum TOKEN_ID id;
	int str_len;
	union token_data {
		char str[TOKEN_MAX_SIZE];
		int num;
		struct int_range prange;
		struct CIDR cidr;
	} data;
};

/* filter_simple */
union filter_simple_data
{
	struct int_range range;
	struct CIDR cidr;
};

enum FILTER_SIMPLE_TYPE
{
	FILTER_SIMPLE_NET,
	FILTER_SIMPLE_PORT
};

struct filter_simple
{
	enum FILTER_SIMPLE_TYPE type;
	size_t n;
	union filter_simple_data *data;
};

enum FILTER_OP
{
	FILTER_OP_SIMPLE,

	FILTER_OP_NOT,
	FILTER_OP_AND,
	FILTER_OP_OR
};

struct filter_op
{
	enum FILTER_OP op;
	struct filter_simple *arg;
};

struct filter_expr
{
	size_t n;
	struct filter_op *filter;
};

struct filter_input
{
	char *s;
	int end;
	int line, col;

	int error;
	char errmsg[ERR_MSG_LEN];

	struct token current_token;

};

struct filter_expr *parse_filter(struct filter_input *f);
void mkerror(struct filter_input *f, char *msg);

void read_token(struct filter_input *f);

#endif

