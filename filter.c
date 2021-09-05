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
filter_id_to_addr4(struct filter_input *f, char *host,
	struct ipv4_addr_and_mask *am)
{
	int rc;
	struct in6_addr hostaddr;
	char *mask_sym;
	int mask = -1; /* assuming no mask by default */
	char host_tmp[TOKEN_MAX_SIZE];

	strcpy(host_tmp, host);

	mask_sym = strchr(host_tmp, '/');
	if (mask_sym) {
		char *endptr;

		*mask_sym = '\0';
		mask_sym++;
		mask = strtol(mask_sym, &endptr, 10);
		if (*endptr != '\0') {
			mkerror(f, "Incorrect network mask");
			return 0;
		}
	}

	/* TODO: add getaddrinfo */
	rc = inet_pton(AF_INET, host_tmp, &hostaddr);
	if (rc == 1) {
		memcpy(&am->addr, &hostaddr, 4);
		if (mask < 0) {
			/* no mask, set all bits to 1 */
			am->mask = ~(am->mask & 0);
		} else {
			/* TODO: check mask size */
			int i;

			am->mask = 0;

			for (i=0; i<mask; i++) {
				am->mask |= 1UL << i;
			}
		}
		return 1;
	}

	mkerror(f, "Can't parse IP address");
	return 0;
}

static int
filter_id_to_addr6(struct filter_input *f, char *host,
	struct ipv6_addr_and_mask *am)
{
	int rc;
	struct in6_addr hostaddr;
	char *mask_sym;
	int mask = -1; /* assuming no mask by default */
	char host_tmp[TOKEN_MAX_SIZE];

	strcpy(host_tmp, host);

	mask_sym = strchr(host_tmp, '/');
	if (mask_sym) {
		char *endptr;

		*mask_sym = '\0';
		mask_sym++;
		mask = strtol(mask_sym, &endptr, 10);
		if (*endptr != '\0') {
			mkerror(f, "Incorrect network mask");
			return 0;
		}
	}

	rc = inet_pton(AF_INET6, host_tmp, &hostaddr);
	if (rc == 1) {
		memcpy(&am->addr, &hostaddr, 16);
		if (mask < 0) {
			/* no mask */
			am->mask = ~(am->mask & 0);
		} else {
			int i;

			am->mask = 0;

			for (i=0; i<mask; i++) {
				am->mask |= 1UL << i;
			}
		}
		return 1;
	}

	mkerror(f, "Can't parse address");
	return 0;
}

int
filter_add_to_basic_filter(struct filter_input *f,
	struct filter_expr *e, struct token *tok, enum FILTER_BASIC_TYPE type)
{
	struct filter_op *fo;
	struct filter_basic *fb;
	union filter_basic_data *tmpfbd;

	if (e->n < 1) {
		return 0;
	}

	fo = &(e->filter[e->n - 1]);
	if (fo->op != FILTER_OP_BASIC) {
		return 0;
	}

	fb = fo->arg;
	tmpfbd = realloc(fb->data,
		sizeof(union filter_basic_data) * (fb->n + 1));
	if (!tmpfbd) {
		return 0;
	}

	fb->data = tmpfbd;
	if (tok->id == ID) {
		if (type == FILTER_BASIC_ADDR4) {
			if (!filter_id_to_addr4(f, tok->data.str,
				&(fb->data[fb->n].ipv4))) {

				return 0;
			}
		} else if (type == FILTER_BASIC_ADDR4) {
			if (!filter_id_to_addr6(f, tok->data.str,
				&(fb->data[fb->n].ipv6))) {

				return 0;
			}
		}
	} else if (tok->id == INT_RANGE) {
		fb->data[fb->n].range.low = tok->data.range.low;
		fb->data[fb->n].range.high = tok->data.range.high;
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
filter_basic_match_addr4(struct filter_basic *fb, struct nf_flow_info *flow)
{
	size_t i;
	void *addr4;
	void *addr4_second = NULL;

	switch (fb->name) {
#define FIELD(NAME, STR, TYPE, SRC, DST)                                     \
		case FILTER_BASIC_NAME_##NAME:                               \
			if (fb->direction == FILTER_BASIC_DIR_SRC) {         \
				addr4 = flow->SRC;                           \
			} else if (fb->direction == FILTER_BASIC_DIR_DST) {  \
				addr4 = flow->DST;                           \
			} else if (fb->direction == FILTER_BASIC_DIR_BOTH) { \
				addr4 = flow->SRC;                           \
				addr4_second = flow->DST;                    \
			} else {                                             \
				return 0;                                    \
			}                                                    \
			break;
#include "filter.def"
		default:
			return 0;
	}

	/* TODO: add mask */
	for (i=0; i<fb->n; i++) {
		if (fb->direction == FILTER_BASIC_DIR_BOTH) {
			if (memcmp(addr4,
				&fb->data[i].ipv4.addr, 4) == 0) {
				return 1;
			}
			if (memcmp(addr4_second,
				&fb->data[i].ipv4.addr, 4) == 0) {
				return 1;
			}
		} else {
			if (memcmp(addr4,
				&fb->data[i].ipv4.addr, 4) == 0) {
				return 1;
			}
		}
	}

	return 0;
}

static int
filter_basic_match_addr6(struct filter_basic *fb, struct nf_flow_info *flow)
{
	size_t i;
	void *addr6;
	void *addr6_second = NULL;

	switch (fb->name) {
#define FIELD(NAME, STR, TYPE, SRC, DST)                                     \
		case FILTER_BASIC_NAME_##NAME:                               \
			if (fb->direction == FILTER_BASIC_DIR_SRC) {         \
				addr6 = flow->SRC;                           \
			} else if (fb->direction == FILTER_BASIC_DIR_DST) {  \
				addr6 = flow->DST;                           \
			} else if (fb->direction == FILTER_BASIC_DIR_BOTH) { \
				addr6 = flow->SRC;                           \
				addr6_second = flow->DST;                    \
			} else {                                             \
				return 0;                                    \
			}                                                    \
			break;
#include "filter.def"
		default:
			return 0;
	}

	/* TODO: add mask */
	for (i=0; i<fb->n; i++) {
		if (fb->direction == FILTER_BASIC_DIR_BOTH) {
			if (memcmp(addr6,
				&fb->data[i].ipv6.addr, 16) == 0) {
				return 1;
			}
			if (memcmp(addr6_second,
				&fb->data[i].ipv6.addr, 16) == 0) {
				return 1;
			}
		} else {
			if (memcmp(addr6,
				&fb->data[i].ipv6.addr, 16) == 0) {
				return 1;
			}
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
#define FIELD(NAME, STR, TYPE, SRC, DST)                \
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
			if ((r1 >= fb->data[i].range.low)
				&& (r1 <= fb->data[i].range.high)) {
				return 1;
			}
		} else {
			if ((r1 >= fb->data[i].range.low)
				&& (r1 <= fb->data[i].range.high)) {
				return 1;
			}
			if ((r2 >= fb->data[i].range.low)
				&& (r2 <= fb->data[i].range.high)) {
				return 1;
			}
		}
	}

	return 0;
}


static int
filter_basic_match(struct filter_basic *fb, struct nf_flow_info *flow)
{
	int ret = 0;

	if (fb->type == FILTER_BASIC_ADDR4) {
		ret = filter_basic_match_addr4(fb, flow);
	} else if (fb->type == FILTER_BASIC_ADDR6) {
		ret = filter_basic_match_addr6(fb, flow);
	} else if (fb->type == FILTER_BASIC_RANGE) {
		ret = filter_basic_match_range(fb, flow);
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
				stack[sp] = ~stack[sp];
				break;
			case FILTER_OP_AND:
				if (sp < 2) {
					return 0;
				}
				stack[sp - 1] &= stack[sp];
				sp--;
				break;
			case FILTER_OP_OR:
				if (sp < 2) {
					return 0;
				}
				stack[sp - 1] |= stack[sp];
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
			free(fb);
		}
		e->filter[i].arg = NULL;
	}

	free(e->filter);
	free(e);
}

static void
filter_dump_addr4(struct ipv4_addr_and_mask *ipv4, FILE *f)
{
	int i;
	uint8_t *aptr = (uint8_t *)&ipv4->addr;

	fprintf(f, " ");

	for (i=0; i<4; i++) {
		fprintf(f, "%u", aptr[i]);
		if (i != 3) {
			fprintf(f, ".");
		}
	}
}

static void
filter_dump_addr6(struct ipv6_addr_and_mask *ipv6, FILE *f)
{
	int i;
	uint8_t *aptr = (uint8_t *)&ipv6->addr;

	fprintf(f, " ");

	for (i=0; i<16; i++) {
		fprintf(f, "%u", aptr[i]);
		if (i != 15) {
			fprintf(f, ":");
		}
	}

}


static void
filter_dump_basic(struct filter_basic *fb, FILE *f)
{
	size_t i;

	if (fb->direction == FILTER_BASIC_DIR_SRC) {
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

		default:
			fprintf(f, "<Unknown name %d> ", fb->name);
			break;
	}

	if (fb->type == FILTER_BASIC_ADDR4) {
		for (i=0; i<fb->n; i++) {
			filter_dump_addr4(&(fb->data[i].ipv4), f);
		}
	} else if (fb->type == FILTER_BASIC_ADDR6) {
		for (i=0; i<fb->n; i++) {
			filter_dump_addr6(&(fb->data[i].ipv6), f);
		}
	} else if (fb->type == FILTER_BASIC_RANGE) {
		for (i=0; i<fb->n; i++) {
			fprintf(f, " %d-%d", fb->data[i].range.low,
				fb->data[i].range.high);
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

