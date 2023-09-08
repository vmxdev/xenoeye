#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "filter.h"
#include "netflow.h"
#include "utils.h"

void
mkerror(struct filter_input *f, char *msg)
{
	f->error = 1;
	sprintf(f->errmsg, "Line %d, col %d: %s", f->line, f->col, msg);
}

int
filter_add_basic_filter(struct filter_expr *e, enum FILTER_BASIC_TYPE type,
	enum FILTER_BASIC_NAME name, int dir)
{
	struct filter_op *tmpfo;
	struct filter_basic *fb;

	fb = malloc(sizeof(struct filter_basic));
	if (!fb) {
		goto fail_filter_malloc;
	}
	fb->type = type;
	fb->name = name;
	fb->n = 0;
	fb->data = NULL;
	fb->direction = dir;

	fb->is_func = 0;


	tmpfo = realloc(e->filter, sizeof(struct filter_op) * (e->n + 1));
	if (!tmpfo) {
		goto fail_realloc;
	}
	e->filter = tmpfo;

	e->filter[e->n].op = FILTER_OP_BASIC;
	e->filter[e->n].arg = fb;
	e->n++;

	return 1;

fail_realloc:
	free(fb);
fail_filter_malloc:
	return 0;
}


static int
filter_id_to_addr(struct filter_input *f, char *host,
	struct ip_addr_and_mask *am)
{
	int rc;
	struct in6_addr hostaddr;
	char *mask_sym;
	char host_tmp[TOKEN_MAX_SIZE];

	strcpy(host_tmp, host);

	am->mask_len = -1;
	mask_sym = strchr(host_tmp, '/');
	if (mask_sym) {
		char *endptr;

		*mask_sym = '\0';
		mask_sym++;
		am->mask_len = strtol(mask_sym, &endptr, 10);
		if (*endptr != '\0') {
			mkerror(f, "Incorrect network mask");
			return 0;
		}
	}

	/* TODO: add getaddrinfo */
	if (am->version == 4) {
		rc = inet_pton(AF_INET, host_tmp, &hostaddr);
	} else {
		rc = inet_pton(AF_INET6, host_tmp, &hostaddr);
	}
	if (rc == 1) {
		int i;
		/* TODO: check mask_len */

		if (am->version == 4) {
			memcpy(&am->ip.v4.addr, &hostaddr, 4);
			if (am->mask_len < 0) {
				am->mask_len = 32;
			}
			am->ip.v4.mask = 0;

			for (i=0; i<am->mask_len; i++) {
				am->ip.v4.mask |= 1UL << i;
			}

			/* apply mask to address */
			am->ip.v4.addr &= am->ip.v4.mask;
		} else {
			memcpy(&am->ip.v6.addr, &hostaddr, 16);
			if (am->mask_len < 0) {
				am->mask_len = 16 * 8;
			}
			am->ip.v6.mask = 0;

			for (i=0; i<am->mask_len; i++) {
				am->ip.v6.mask |= 1UL << i;
			}

			am->ip.v6.addr &= am->ip.v6.mask;
		}

		return 1;
	}

	mkerror(f, "Can't parse IP address");
	return 0;
}

int
filter_add_to_basic_filter(struct filter_input *f,
	struct filter_expr *e, struct token *tok, enum FILTER_BASIC_TYPE type)
{
	struct filter_op *fo;
	struct filter_basic *fb;
	struct filter_basic_data *tmpfbd;

	if (e->n < 1) {
		return 0;
	}

	fo = &(e->filter[e->n - 1]);
	if (fo->op != FILTER_OP_BASIC) {
		return 0;
	}

	fb = fo->arg;
	tmpfbd = realloc(fb->data,
		sizeof(struct filter_basic_data) * (fb->n + 1));
	if (!tmpfbd) {
		return 0;
	}

	fb->data = tmpfbd;

	fb->data[fb->n].is_list = 0;

	if (tok->id == ID) {
		if (type == FILTER_BASIC_ADDR4) {
			struct iplist *tmpiplist;

			/* try to parse as iplist */
			tmpiplist = iplist_get_by_name(tok->data.str);
			if (tmpiplist) {
				fb->data[fb->n].data.addr_list = tmpiplist;
				fb->data[fb->n].is_list = 1;
			} else {
				fb->data[fb->n].data.ip.version = 4;
				if (!filter_id_to_addr(f, tok->data.str,
					&(fb->data[fb->n].data.ip))) {

					return 0;
				}
			}
		} else if (type == FILTER_BASIC_ADDR6) {
			struct iplist *tmpiplist;

			tmpiplist = iplist_get_by_name(tok->data.str);
			if (tmpiplist) {
				fb->data[fb->n].data.addr_list = tmpiplist;
				fb->data[fb->n].is_list = 1;
			} else {
				fb->data[fb->n].data.ip.version = 6;
				if (!filter_id_to_addr(f, tok->data.str,
					&(fb->data[fb->n].data.ip))) {

					return 0;
				}
			}
		}
	} else if (tok->id == INT_RANGE) {
		fb->data[fb->n].data.range.low = tok->data.range.low;
		fb->data[fb->n].data.range.high = tok->data.range.high;
	} else if (tok->id == STRING) {
		fb->data[fb->n].data.str = strdup(tok->data.str);
	} else {
		return 0;
	}
	fb->n++;

	return 1;
}

int
filter_add_op(struct filter_expr *e, enum FILTER_OP op)
{
	struct filter_op *tmpfo;

	tmpfo = realloc(e->filter, sizeof(struct filter_op) * (e->n + 1));
	if (!tmpfo) {
		goto fail_realloc;
	}
	e->filter = tmpfo;

	e->filter[e->n].op = op;
	e->filter[e->n].arg = NULL;
	e->n++;

	return 1;

fail_realloc:
	return 0;
}

static int
filter_basic_match_single_addr4(int direction, struct filter_basic_data *fbd,
	uint32_t *addr, uint32_t *addr2)
{
	if (direction == FILTER_BASIC_DIR_BOTH) {
		if (fbd->is_list) {
			/* check against IP list */
			if (addr) {
				if (iplist_match4(fbd->data.addr_list, *addr)) {
					return 1;
				}
			}

			if (addr2) {
				if (iplist_match4(fbd->data.addr_list, *addr2)) {
					return 1;
				}
			}
		} else {
			if (addr) {
				if ((*addr & fbd->data.ip.ip.v4.mask)
					== fbd->data.ip.ip.v4.addr) {
					return 1;
				}
			}

			if (addr2) {
				if ((*addr2 & fbd->data.ip.ip.v4.mask)
					== fbd->data.ip.ip.v4.addr) {

					return 1;
				}
			}
		}

		return 0;
	}

	if (fbd->is_list) {
		if (iplist_match4(fbd->data.addr_list, *addr)) {
			return 1;
		}
	} else {
		if ((*addr & fbd->data.ip.ip.v4.mask)
			== fbd->data.ip.ip.v4.addr) {

			return 1;
		}
	}

	return 0;
}

static int
filter_basic_match_addr4(struct filter_basic *fb, struct nf_flow_info *flow)
{
	size_t i;
	uint32_t *addr4 = NULL;
	uint32_t *addr4_second = NULL;

	switch (fb->name) {
#define FIELD(NAME, STR, TYPE, SRC, DST)                                     \
		case FILTER_BASIC_NAME_##NAME:                               \
			if (fb->direction == FILTER_BASIC_DIR_SRC) {         \
				if (!flow->has_##SRC) {                      \
					return 0;                            \
				}                                            \
				addr4 = (uint32_t *)flow->SRC;               \
			} else if (fb->direction == FILTER_BASIC_DIR_DST) {  \
				if (!flow->has_##DST) {                      \
					return 0;                            \
				}                                            \
				addr4 = (uint32_t *)flow->DST;               \
			} else if (fb->direction == FILTER_BASIC_DIR_BOTH) { \
				if (flow->has_##SRC) {                       \
					addr4 = (uint32_t *)flow->SRC;       \
				}                                            \
				if (flow->has_##DST) {                       \
					addr4_second = (uint32_t *)flow->DST;\
				}                                            \
			} else {                                             \
				return 0;                                    \
			}                                                    \
			break;
#include "filter.def"
		default:
			return 0;
	}

	if ((!addr4) && (!addr4_second)) {
		return 0;
	}

	for (i=0; i<fb->n; i++) {
		if (filter_basic_match_single_addr4(fb->direction,
			&(fb->data[i]), addr4, addr4_second)) {

			return 1;
		}
	}

	return 0;
}

static int
filter_basic_match_single_addr6(int direction, struct filter_basic_data *fbd,
	xe_ip *addr, xe_ip *addr2)
{
	if (direction == FILTER_BASIC_DIR_BOTH) {
		if (fbd->is_list) {
			/* check against IP list */
			if (addr) {
				if (iplist_match6(fbd->data.addr_list, addr)) {
					return 1;
				}
			}

			if (addr2) {
				if (iplist_match6(fbd->data.addr_list, addr2)) {
					return 1;
				}
			}

			return 0;
		} else {
			if (addr) {
				if ((*addr & fbd->data.ip.ip.v6.mask)
					== fbd->data.ip.ip.v6.addr) {
					return 1;
				}
			}

			if (addr2) {
				if ((*addr2 & fbd->data.ip.ip.v6.mask)
					== fbd->data.ip.ip.v6.addr) {

					return 1;
				}
			}
		}

		return 0;
	}

	if (fbd->is_list) {
		if (iplist_match6(fbd->data.addr_list, addr)) {
			return 1;
		}

		return 0;
	} else {
		if ((*addr & fbd->data.ip.ip.v6.mask)
			== fbd->data.ip.ip.v6.addr) {

			return 1;
		}
	}

	return 0;
}


static int
filter_basic_match_addr6(struct filter_basic *fb, struct nf_flow_info *flow)
{
	size_t i;
	xe_ip *addr6 = NULL;
	xe_ip *addr6_second = NULL;

	switch (fb->name) {
#define FIELD(NAME, STR, TYPE, SRC, DST)                                     \
		case FILTER_BASIC_NAME_##NAME:                               \
			if (fb->direction == FILTER_BASIC_DIR_SRC) {         \
				if (!flow->has_##SRC) {                      \
					return 0;                            \
				}                                            \
				addr6 = (xe_ip *)flow->SRC;                  \
			} else if (fb->direction == FILTER_BASIC_DIR_DST) {  \
				if (!flow->has_##DST) {                      \
					return 0;                            \
				}                                            \
				addr6 = (xe_ip *)flow->DST;                  \
			} else if (fb->direction == FILTER_BASIC_DIR_BOTH) { \
				if (flow->has_##SRC) {                       \
					addr6 = (xe_ip *)flow->SRC;          \
				}                                            \
				if (flow->has_##DST) {                       \
					addr6_second = (xe_ip *)flow->DST;   \
				}                                            \
			} else {                                             \
				return 0;                                    \
			}                                                    \
			break;
#include "filter.def"
		default:
			return 0;
	}

	if ((!addr6) && (!addr6_second)) {
		return 0;
	}

	for (i=0; i<fb->n; i++) {
		if (filter_basic_match_single_addr6(fb->direction,
			&(fb->data[i]), addr6, addr6_second)) {

			return 1;
		}
	}

	return 0;
}

static int
filter_basic_match_range(struct filter_basic *fb, struct nf_flow_info *flow)
{
	size_t i;
	int r1, r2;

	void *tmp;

	switch (fb->name) {
#define FIELD(NAME, STR, TYPE, SRC, DST)                                     \
		case FILTER_BASIC_NAME_##NAME:                               \
			if (fb->direction == FILTER_BASIC_DIR_SRC) {         \
				tmp = flow->SRC;                             \
				if (flow->SRC##_size == 1) {                 \
					r1 = *((uint8_t *)tmp);              \
				} else if (flow->SRC##_size == 2) {          \
					r1 = ntohs(*((uint16_t *)tmp));      \
				} else if (flow->SRC##_size == 4) {          \
					r1 = ntohl(*((uint32_t *)tmp));      \
				}                                            \
			} else if (fb->direction == FILTER_BASIC_DIR_DST) {  \
				tmp = flow->DST;                             \
				if (flow->DST##_size == 1) {                 \
					r1 = *((uint8_t *)tmp);              \
				} else if (flow->DST##_size == 2) {          \
					r1 = ntohs(*((uint16_t *)tmp));      \
				} else if (flow->DST##_size == 4) {          \
					r1 = ntohl(*((uint32_t *)tmp));      \
				}                                            \
			} else if (fb->direction == FILTER_BASIC_DIR_BOTH) { \
				tmp = flow->SRC;                             \
				if (flow->SRC##_size == 1) {                 \
					r1 = *((uint8_t *)tmp);              \
				} else if (flow->SRC##_size == 2) {          \
					r1 = ntohs(*((uint16_t *)tmp));      \
				} else if (flow->SRC##_size == 4) {          \
					r1 = ntohl(*((uint32_t *)tmp));      \
				}                                            \
				tmp = flow->DST;                             \
				if (flow->DST##_size == 1) {                 \
					r2 = *((uint8_t *)tmp);              \
				} else if (flow->DST##_size == 2) {          \
					r2 = ntohs(*((uint16_t *)tmp));      \
				} else if (flow->DST##_size == 4) {          \
					r2 = ntohl(*((uint32_t *)tmp));      \
				}                                            \
			} else {                                             \
				return 0;                                    \
			}                                                    \
			break;
#include "filter.def"
		default:
			return 0;
	}

	for (i=0; i<fb->n; i++) {
		if (fb->direction != FILTER_BASIC_DIR_BOTH) {
			if ((r1 >= fb->data[i].data.range.low)
				&& (r1 <= fb->data[i].data.range.high)) {
				return 1;
			}
		} else {
			if ((r1 >= fb->data[i].data.range.low)
				&& (r1 <= fb->data[i].data.range.high)) {
				return 1;
			}
			if ((r2 >= fb->data[i].data.range.low)
				&& (r2 <= fb->data[i].data.range.high)) {
				return 1;
			}
		}
	}

	return 0;
}

static int
filter_basic_match_string(struct filter_basic *fb, struct nf_flow_info *flow)
{
	size_t i;
	size_t len1, len2;

	char *tmp1, *tmp2;

	switch (fb->name) {
#define FIELD(NAME, STR, TYPE, SRC, DST)                                     \
		case FILTER_BASIC_NAME_##NAME:                               \
			if (fb->direction == FILTER_BASIC_DIR_SRC) {         \
				tmp1 = (char *)flow->SRC;                    \
				len1 = flow->SRC##_size;                     \
			} else if (fb->direction == FILTER_BASIC_DIR_DST) {  \
				tmp1 = (char *)flow->DST;                    \
				len1 = flow->DST##_size;                     \
			} else if (fb->direction == FILTER_BASIC_DIR_BOTH) { \
				tmp1 = (char *)flow->SRC;                    \
				tmp2 = (char *)flow->DST;                    \
				len1 = flow->SRC##_size;                     \
				len2 = flow->DST##_size;                     \
			} else {                                             \
				return 0;                                    \
			}                                                    \
			break;
#include "filter.def"
		default:
			return 0;
	}

	for (i=0; i<fb->n; i++) {
		if (fb->direction != FILTER_BASIC_DIR_BOTH) {
			if (strncmp(fb->data[i].data.str, tmp1, len1) == 0) {
				return 1;
			}

			if (strncmp(fb->data[i].data.str, tmp2, len2) == 0) {
				return 1;
			}
		} else {
			if (strncmp(fb->data[i].data.str, tmp1, len1) == 0) {
				return 1;
			}
		}
	}

	return 0;
}

/* functions */
static int
filter_function_div(struct filter_basic *fb, struct nf_flow_info *flow)
{
	size_t i;
	struct function_div *div = fb->func_data.div;
	uint64_t dividend, divisor;
	int quotient;

	dividend = get_nf_val((uintptr_t)flow + div->dividend_off,
		div->dividend_size);
	divisor = get_nf_val((uintptr_t)flow + div->divisor_off,
		div->divisor_size);

	if (divisor == 0) {
		LOG("Division by zero");
		return 0;
	}

	quotient = dividend / divisor;

	for (i=0; i<fb->n; i++) {
		if ((quotient >= fb->data[i].data.range.low)
			&& (quotient <= fb->data[i].data.range.high)) {

			return 1;
		}
	}

	return 0;
}

static int
filter_function_min(struct filter_basic *fb, struct nf_flow_info *flow)
{
	size_t i;
	struct function_min *min = fb->func_data.min;
	uint64_t arg1, arg2;
	int64_t res;

	arg1 = get_nf_val((uintptr_t)flow + min->arg1_off,
		min->arg1_size);
	arg2 = get_nf_val((uintptr_t)flow + min->arg2_off,
		min->arg2_size);

	res = (arg1 < arg2) ? arg1 : arg2;

	for (i=0; i<fb->n; i++) {
		if ((res >= fb->data[i].data.range.low)
			&& (res <= fb->data[i].data.range.high)) {

			return 1;
		}
	}

	return 0;
}

static int
filter_function_mfreq(struct filter_basic *fb, struct nf_flow_info *flow)
{
	size_t i;
	struct function_mfreq *mfreq = fb->func_data.mfreq;
	uint16_t arg1, arg2;
	uint64_t freq1, freq2;
	int64_t res;

	arg1 = get_nf_val((uintptr_t)flow + mfreq->arg1_off,
		mfreq->arg1_size);
	arg2 = get_nf_val((uintptr_t)flow + mfreq->arg2_off,
		mfreq->arg2_size);

	freq1 = mfreq->freqmap[arg1];
	freq2 = mfreq->freqmap[arg2];

	if (freq1 != freq2) {
		res = (freq1 > freq2) ? arg1 : arg2;
	} else {
		/* same frequencies */
		res = (arg1 < arg2) ? arg1 : arg2;
	}

	/* update freqmap */
	/* FIXME: atomic? */
	mfreq->freqmap[arg1]++;
	mfreq->freqmap[arg2]++;


	for (i=0; i<fb->n; i++) {
		if ((res >= fb->data[i].data.range.low)
			&& (res <= fb->data[i].data.range.high)) {

			return 1;
		}
	}

	return 0;
}


static int
filter_basic_match(struct filter_basic *fb, struct nf_flow_info *flow)
{
	int ret = 0;

	if (fb->is_func) {
		switch (fb->name) {
			case FILTER_BASIC_NAME_DIV:
				return filter_function_div(fb, flow);
			case FILTER_BASIC_NAME_MIN:
				return filter_function_min(fb, flow);
			case FILTER_BASIC_NAME_MFREQ:
				return filter_function_mfreq(fb, flow);
			default:
				break;
		}
	}

	if (fb->type == FILTER_BASIC_ADDR4) {
		ret = filter_basic_match_addr4(fb, flow);
	} else if (fb->type == FILTER_BASIC_ADDR6) {
		ret = filter_basic_match_addr6(fb, flow);
	} else if (fb->type == FILTER_BASIC_RANGE) {
		ret = filter_basic_match_range(fb, flow);
	} else if (fb->type == FILTER_BASIC_STRING) {
		ret = filter_basic_match_string(fb, flow);
	} else {
		/* unknown filter type */
	}

	return ret;
}

int
filter_match(struct filter_expr *expr, struct nf_flow_info *flow)
{
	size_t i;
	int ret;
	int *stack = alloca(expr->n * sizeof(int));
	size_t sp = 0;

	if (expr->n == 0) {
		/* empty filter, match all */
		return 1;
	}

	for (i=0; i<expr->n; i++) {
		struct filter_op *op = &expr->filter[i];
		switch (op->op) {
			case FILTER_OP_BASIC:
				stack[sp] = filter_basic_match(op->arg, flow);
				sp++;
				break;
			case FILTER_OP_NOT:
				if (sp < 1) {
					return 0;
				}
				stack[sp - 1] = !stack[sp - 1];
				break;
			case FILTER_OP_AND:
				if (sp < 2) {
					return 0;
				}
				stack[sp - 2] &= stack[sp - 1];
				sp--;
				break;
			case FILTER_OP_OR:
				if (sp < 2) {
					return 0;
				}
				stack[sp - 2] |= stack[sp - 1];
				sp--;
				break;
			default:
				return 0;
		}
	}

	if (sp != 1) {
		ret = 0;
	} else {
		ret = stack[0];
	}

	return ret;
}

void
filter_free(struct filter_expr *e)
{
	size_t i;
	struct filter_basic *fb;

	for (i=0; i<e->n; i++) {
		fb = e->filter[i].arg;
		if (fb) {
			free(fb->data);
			fb->data = NULL;
			if (fb->is_func) {
				switch (fb->name) {
					case FILTER_BASIC_NAME_DIV:
						free(fb->func_data.div);
						fb->func_data.div = NULL;
						break;
					case FILTER_BASIC_NAME_MIN:
						free(fb->func_data.min);
						fb->func_data.min = NULL;
						break;
					case FILTER_BASIC_NAME_MFREQ:
						free(fb->func_data.mfreq
							->freqmap);
						free(fb->func_data.mfreq);
						fb->func_data.mfreq = NULL;
						break;
					default:
						break;
				}
			}
			free(fb);
		}
		e->filter[i].arg = NULL;
	}

	free(e->filter);
	free(e);
}


static void
filter_dump_addr(FILE *f, int version, uint8_t *aptr, int mask)
{
	int i;

	fprintf(f, " ");

	if (version == 4) {
		for (i=0; i<4; i++) {
			fprintf(f, "%u", aptr[i]);
			if (i != 3) {
				fprintf(f, ".");
			}
		}
	} else {
		for (i=0; i<16; i++) {
			fprintf(f, "%u", aptr[i]);
			if (i != 15) {
				fprintf(f, ":");
			}
		}
	}

	fprintf(f, "/%d", mask);
}


static void
filter_dump_basic(struct filter_basic *fb, FILE *f)
{
	size_t i;

	if (fb->direction == FILTER_BASIC_DIR_NONE) {
		/* no direction */
	} else if (fb->direction == FILTER_BASIC_DIR_SRC) {
		fprintf(f, "SRC ");
	} else if (fb->direction == FILTER_BASIC_DIR_DST) {
		fprintf(f, "DST ");
	} else if (fb->direction == FILTER_BASIC_DIR_BOTH) {
		fprintf(f, "SRC OR DST ");
	} else {
		fprintf(f, "<Unknown direction %d> ", fb->direction);
	}

	switch (fb->name) {

#define FIELD(NAME, STR, TYPE, SRC, DST)                      \
		case FILTER_BASIC_NAME_##NAME:                \
			fprintf(f, #STR" ");                  \
			break;
#include "filter.def"

		case FILTER_BASIC_NAME_DIV:
			fprintf(f, "DIV ([offset %d]/[offset %d])",
				(int)fb->func_data.div->dividend_off,
				(int)fb->func_data.div->divisor_off);
			break;

		case FILTER_BASIC_NAME_MIN:
			fprintf(f, "MIN ([offset %d]/[offset %d])",
				(int)fb->func_data.min->arg1_off,
				(int)fb->func_data.min->arg2_off);
			break;

		case FILTER_BASIC_NAME_MFREQ:
			fprintf(f, "MFREQ ([offset %d]/[offset %d])",
				(int)fb->func_data.mfreq->arg1_off,
				(int)fb->func_data.mfreq->arg2_off);
			break;

		default:
			fprintf(f, "<Unknown name %d> ", fb->name);
			break;
	}

	if (fb->type == FILTER_BASIC_ADDR4) {
		for (i=0; i<fb->n; i++) {
			struct filter_basic_data *fbd = &fb->data[i];

			if (fbd->is_list) {
				fprintf(f, " LIST '%s'",
					iplist_name(fbd->data.addr_list));
			} else {
				filter_dump_addr(f, 4,
					(uint8_t *)&(fbd->data.ip.ip.v4.addr),
					fbd->data.ip.mask_len);
			}
		}
	} else if (fb->type == FILTER_BASIC_ADDR6) {
		for (i=0; i<fb->n; i++) {
			struct filter_basic_data *fbd = &fb->data[i];

			if (fbd->is_list) {
				fprintf(f, " LIST '%s'",
					iplist_name(fbd->data.addr_list));
			} else {
				filter_dump_addr(f, 6,
					(uint8_t *)&(fbd->data.ip.ip.v6.addr),
					fbd->data.ip.mask_len);
			}
		}
	} else if (fb->type == FILTER_BASIC_RANGE) {
		for (i=0; i<fb->n; i++) {
			fprintf(f, " %d-%d", fb->data[i].data.range.low,
				fb->data[i].data.range.high);
		}
	} else if (fb->type == FILTER_BASIC_STRING) {
		for (i=0; i<fb->n; i++) {
			fprintf(f, " %s", fb->data[i].data.str);
		}
	} else {
		fprintf(f, "<Unknown type %d>", fb->type);
	}

	fprintf(f, "\n");
}

void
filter_dump(struct filter_expr *e, FILE *f)
{
	size_t i;
	struct filter_basic *fb;

	for (i=0; i<e->n; i++) {
		switch (e->filter[i].op) {
			case FILTER_OP_BASIC:
				fb = e->filter[i].arg;
				filter_dump_basic(fb, f);
				break;

			case FILTER_OP_NOT:
				fprintf(f, "NOT\n");
				break;

			case FILTER_OP_AND:
				fprintf(f, "AND\n");
				break;

			case FILTER_OP_OR:
				fprintf(f, "OR\n");
				break;

			default:
				fprintf(f, "Unknown opcode\n");
				break;
		}
	}
}

