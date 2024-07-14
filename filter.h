#ifndef filter_h_included
#define filter_h_included

#include <stdint.h>
#include <math.h>
#include "xenoeye.h"
#include "iplist.h"
#include "geoip.h"

#define ERR_MSG_LEN     1024

struct flow_info;


struct ip_addr_and_mask_4
{
	uint32_t addr;
	uint32_t mask;
};

struct ip_addr_and_mask_6
{
	xe_ip addr;
	xe_ip mask;
};

struct ip_addr_and_mask
{
	int version;
	int mask_len;
	union ip_addr_and_mask_addr {
		struct ip_addr_and_mask_4 v4;
		struct ip_addr_and_mask_6 v6;
	} ip;
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
	STRING,

	LPAREN,
	RPAREN,

	OR,
	AND,
	NOT,

#define FIELD(NAME, STR, TYPE, SRC, DST)  \
	NAME,
#include "filter.def"

	SRC,
	DST,

	/* aggregable fields */
#define FIELD(NAME, STR, FLD, SCALE)  \
	NAME,
#include "filter-ag.def"

	ASC,
	DESC,

	/* functions */
	DIV,
	DIV_R,
	DIV_L,
	MIN,
	MFREQ,
/* geoip */
#define DO(FIELD, SIZE) FIELD,
FOR_LIST_OF_GEOIP_FIELDS
#undef DO
	ASN,
	ASD,
	TFSTR,
	PORTSTR,
	PPSTR,
	COMMA
};

struct token
{
	enum TOKEN_ID id;
	int str_len;
	union token_data {
		char str[TOKEN_MAX_SIZE];
		struct int_range range;
		struct ip_addr_and_mask ip;
	} data;
};

/* filter_basic */
#define FILTER_BASIC_DIR_NONE 0
#define FILTER_BASIC_DIR_SRC  1
#define FILTER_BASIC_DIR_DST  2
#define FILTER_BASIC_DIR_BOTH (FILTER_BASIC_DIR_SRC | FILTER_BASIC_DIR_DST)

struct filter_basic_data
{
	int is_list;
	union filter_basic_data_union {
		struct int_range range;
		struct ip_addr_and_mask ip;
		struct iplist *addr_list;
		char *str;
	} data;
};

enum FILTER_BASIC_TYPE
{
	FILTER_BASIC_ADDR4,
	FILTER_BASIC_ADDR6,
	FILTER_BASIC_RANGE,
	FILTER_BASIC_STRING
};

enum FILTER_BASIC_NAME
{
	FILTER_BASIC_NAME_NONE,
#define FIELD(NAME, STR, TYPE, SRC, DST)  \
	FILTER_BASIC_NAME_##NAME,
#include "filter.def"

	FILTER_BASIC_NAME_DIV,
	FILTER_BASIC_NAME_DIV_R,
	FILTER_BASIC_NAME_DIV_L,
	FILTER_BASIC_NAME_MIN,
	FILTER_BASIC_NAME_MFREQ,
/* geoip */
#define DO(FIELD, SIZE) FILTER_BASIC_NAME_##FIELD,
FOR_LIST_OF_GEOIP_FIELDS
#undef DO
	FILTER_BASIC_NAME_ASN,
	FILTER_BASIC_NAME_ASD,
	FILTER_BASIC_NAME_TFSTR,
	FILTER_BASIC_NAME_PORTSTR,
	FILTER_BASIC_NAME_PPSTR
};

struct function_div
{
	/* offsets and sizes in struct flow_info */
	unsigned int dividend_off;
	unsigned int dividend_size;

	unsigned int divisor_off;
	unsigned int divisor_size;

	int is_log;
	int k;
};

struct function_min
{
	/* offsets and sizes in struct flow_info */
	unsigned int arg1_off;
	unsigned int arg1_size;

	unsigned int arg2_off;
	unsigned int arg2_size;
};

struct function_mfreq
{
	/* offsets and sizes in struct flow_info */
	unsigned int arg1_off;
	unsigned int arg1_size;

	unsigned int arg2_off;
	unsigned int arg2_size;

	_Atomic uint64_t *freqmap;
};

struct function_geoip
{
	/* offset and size in struct flow_info */
	unsigned int ip_off;
	unsigned int ip_size;
	int *has_ip;

	enum GEOIP_FIELD field;
};

struct function_as
{
	/* offset and size in struct flow_info */
	unsigned int ip_off;
	unsigned int ip_size;
	int *has_ip;

	int num;
};

struct function_tfstr
{
	/* offset in struct flow_info */
	unsigned int tf_off;
};

struct function_portstr
{
	/* offset in struct flow_info */
	unsigned int port_off;
	unsigned int port_size;
};

struct function_ppstr
{
	/* offsets and sizes in struct flow_info */
	unsigned int arg1_off;
	unsigned int arg1_size;

	unsigned int arg2_off;
	unsigned int arg2_size;

	_Atomic uint64_t *freqmap;
};

struct filter_basic
{
	enum FILTER_BASIC_TYPE type;
	enum FILTER_BASIC_NAME name;
	int direction;

	size_t n;
	struct filter_basic_data *data;

	int is_func;
	union filter_func_data {
		struct function_div *div;
		struct function_min *min;
		struct function_mfreq *mfreq;
		struct function_geoip *geoip;
		struct function_as *as;
		struct function_tfstr *tfstr;
		struct function_portstr *portstr;
		struct function_ppstr *ppstr;
	} func_data;
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

struct field
{
	char name[TOKEN_MAX_SIZE], sql_name[TOKEN_MAX_SIZE];

	int descending;
	enum FILTER_BASIC_TYPE type;
	enum TOKEN_ID id;
	size_t nf_offset;
	int size;

	/* aggregable fields */
	int aggr;
	int scale;

	/* functions */
	int is_func;
	union field_func_data {
		struct function_div div;
		struct function_min min;
		struct function_mfreq mfreq;
		struct function_geoip geoip;
		struct function_as as;
		struct function_tfstr tfstr;
		struct function_portstr portstr;
		struct function_ppstr ppstr;
	} func_data;
};

struct filter_expr *parse_filter(struct filter_input *f);
int parse_field(char *s, struct field *f, char *err);
void mkerror(struct filter_input *f, char *msg);

void read_token(struct filter_input *f);

int filter_add_basic_filter(struct filter_expr *e,
	enum FILTER_BASIC_TYPE type, enum FILTER_BASIC_NAME name, int dir);

int filter_add_to_basic_filter(struct filter_input *f,
	struct filter_expr *e, struct token *tok, enum FILTER_BASIC_TYPE type);

int filter_add_op(struct filter_expr *e, enum FILTER_OP op);

int filter_match(struct filter_expr *expr, struct flow_info *flow);

void filter_dump(struct filter_expr *e, FILE *f);
void filter_free(struct filter_expr *e);


int accept_(struct filter_input *i, enum TOKEN_ID token);
int id(struct filter_input *f, struct filter_expr *e,
	enum FILTER_BASIC_TYPE type);

int function_div_parse(struct filter_input *in, struct function_div *div,
	enum TOKEN_ID *tok);
int function_div(struct filter_input *in, struct filter_expr *e,
	enum TOKEN_ID *tok);

int function_min_parse(struct filter_input *in, struct function_min *min);
int function_min(struct filter_input *in, struct filter_expr *e);

int function_mfreq_parse(struct filter_input *in, struct function_mfreq *mfreq);
int function_mfreq(struct filter_input *in, struct filter_expr *e);

int function_geoip_parse(struct filter_input *in, struct function_geoip *geoip,
	enum TOKEN_ID *tok);
int function_geoip(struct filter_input *in, struct filter_expr *e);

int function_as_parse(struct filter_input *in, struct function_as *as,
	enum TOKEN_ID *tok);
int function_as(struct filter_input *in, struct filter_expr *e);

int function_tfstr_parse(struct filter_input *in, struct function_tfstr *tfstr);
int function_tfstr(struct filter_input *in, struct filter_expr *e);

int function_portstr_parse(struct filter_input *in,
	struct function_portstr *portstr);
int function_portstr(struct filter_input *in, struct filter_expr *e);

int function_ppstr_parse(struct filter_input *in, struct function_ppstr *ppstr);
int function_ppstr(struct filter_input *in, struct filter_expr *e);

static inline uint64_t
get_nf_val(uintptr_t ptr, unsigned int size)
{
	uint64_t val;

	switch (size) {
		case sizeof(uint64_t):
			val = be64toh(*(uint64_t *)ptr);
			break;
		case sizeof(uint32_t):
			val = be32toh(*(uint32_t *)ptr);
			break;
		case sizeof(uint16_t):
			val = be16toh(*(uint16_t *)ptr);
			break;
		case sizeof(uint8_t):
			val = *(uint8_t *)ptr;
			break;
		default:
			val = 0;
			break;
	}

	return val;
}

static inline int
xdiv(uint64_t dividend, uint64_t divisor, int is_log, int k)
{
	int quotient;

	if (divisor == 0) {
		return 0;
	}

	quotient = dividend / divisor;

	if (is_log) {
		int lg = log(quotient) / log(k);
		quotient = pow(k, lg);
	} else {
		if (k > 1) {
			quotient /= k;
			quotient *= k;
		}
	}

	return quotient;
}


#endif

