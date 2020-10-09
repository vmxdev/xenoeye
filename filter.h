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
	INT_RANGE,
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
		struct int_range range;
		struct CIDR cidr;
	} data;
};

/* filter_simple */
#define FILTER_SIMPLE_DIR_SRC  1
#define FILTER_SIMPLE_DIR_DST  2
#define FILTER_SIMPLE_DIR_BOTH (FILTER_SIMPLE_DIR_SRC | FILTER_SIMPLE_DIR_DST)

union filter_simple_data
{
	struct int_range range;
	struct CIDR cidr;
};

enum FILTER_SIMPLE_TYPE
{
	FILTER_SIMPLE_NET,
	FILTER_SIMPLE_RANGE
};

struct filter_simple
{
	enum FILTER_SIMPLE_TYPE type;
	int direction;
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

int filter_add_simple_filter(struct filter_expr *e,
	enum FILTER_SIMPLE_TYPE type, int dir);
int filter_add_to_simple_filter(struct filter_expr *e, struct token *tok);
int filter_add_op(struct filter_expr *e, enum FILTER_OP op);

void filter_dump(struct filter_expr *e, FILE *f);
void filter_free(struct filter_expr *e);

#endif

