#ifndef filter_h_included
#define filter_h_included

#include <stdint.h>

#define ERR_MSG_LEN     1024
#define TOKEN_MAX_SIZE  512

struct nf_flow_info;

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

#define FILTER_FIELD(NAME, STR, TYPE, IP4S, IP4D, IP6S, IP6D)  \
	NAME,
#include "filter.def"

	SRC,
	DST
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

/* filter_basic */
#define FILTER_BASIC_DIR_SRC  1
#define FILTER_BASIC_DIR_DST  2
#define FILTER_BASIC_DIR_BOTH (FILTER_BASIC_DIR_SRC | FILTER_BASIC_DIR_DST)

union filter_basic_data
{
	struct int_range range;
	struct CIDR cidr;
};

enum FILTER_BASIC_TYPE
{
	FILTER_BASIC_ADDR,
	FILTER_BASIC_RANGE
};

enum FILTER_BASIC_NAME
{
	FILTER_BASIC_NAME_NONE,
#define FILTER_FIELD(NAME, STR, TYPE, IP4S, IP4D, IP6S, IP6D)  \
	FILTER_BASIC_NAME_##NAME,
#include "filter.def"
	FILTER_BASIC_NAME_DUMMY
};

struct filter_basic
{
	enum FILTER_BASIC_TYPE type;
	enum FILTER_BASIC_NAME name;
	int direction;

	size_t n;
	union filter_basic_data *data;
};

enum FILTER_OP
{
	FILTER_OP_BASIC,

	FILTER_OP_NOT,
	FILTER_OP_AND,
	FILTER_OP_OR
};

struct filter_op
{
	enum FILTER_OP op;
	struct filter_basic *arg;
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

int filter_add_basic_filter(struct filter_expr *e,
	enum FILTER_BASIC_TYPE type, enum FILTER_BASIC_NAME name, int dir);
int filter_add_to_basic_filter(struct filter_expr *e, struct token *tok);
int filter_add_op(struct filter_expr *e, enum FILTER_OP op);

int filter_match(struct filter_expr *expr, struct nf_flow_info *flow);

void filter_dump(struct filter_expr *e, FILE *f);
void filter_free(struct filter_expr *e);

#endif

