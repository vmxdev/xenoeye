#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "filter.h"

void
mkerror(struct filter_input *f, char *msg)
{
	f->error = 1;
	sprintf(f->errmsg, "Line %d, col %d: %s", f->line, f->col, msg);
}

int
filter_add_simple_filter(struct filter_expr *e, enum FILTER_SIMPLE_TYPE type,
	int dir)
{
	struct filter_op *tmpfo;
	struct filter_simple *fs;

	fs = malloc(sizeof(struct filter_simple));
	if (!fs) {
		goto fail_filter_malloc;
	}
	fs->type = type;
	fs->n = 0;
	fs->data = NULL;
	fs->direction = dir;


	tmpfo = realloc(e->filter, sizeof(struct filter_op) * (e->n + 1));
	if (!tmpfo) {
		goto fail_realloc;
	}
	e->filter = tmpfo;

	e->filter[e->n].op = FILTER_OP_SIMPLE;
	e->filter[e->n].arg = fs;
	e->n++;

	return 1;

fail_realloc:
	free(fs);
fail_filter_malloc:
	return 0;
}

static int
filter_id_to_addr(char *host, struct CIDR *cidr)
{
	int rc;
	struct in6_addr hostaddr;

	/* TODO: add mask and getaddrinfo */
	rc = inet_pton(AF_INET, host, &hostaddr);
	if (rc == 1) {
		/* IPv4 */
		cidr->version = 4;
		memcpy(cidr->ipv4, &hostaddr, 4);
		return 1;
	}

	rc = inet_pton(AF_INET6, host, &hostaddr);
	if (rc == 1) {
		/* IPv6 */
		cidr->version = 6;
		memcpy(cidr->ipv6, &hostaddr, 16);
		return 1;
	}

	return 0;
}

int
filter_add_to_simple_filter(struct filter_expr *e, struct token *tok)
{
	struct filter_op *fo;
	struct filter_simple *fs;
	union filter_simple_data *tmpfsd;

	if (e->n < 1) {
		return 0;
	}

	fo = &(e->filter[e->n - 1]);
	if (fo->op != FILTER_OP_SIMPLE) {
		return 0;
	}

	fs = fo->arg;
	tmpfsd = realloc(fs->data,
		sizeof(union filter_simple_data) * (fs->n + 1));
	if (!tmpfsd) {
		return 0;
	}

	fs->data = tmpfsd;
	if (tok->id == ID) {
		if (!filter_id_to_addr(tok->data.str,
			&(fs->data[fs->n].cidr))) {

			return 0;
		}
	} else if (tok->id == INT_RANGE) {
		fs->data[fs->n].range.low = tok->data.range.low;
		fs->data[fs->n].range.high = tok->data.range.high;
	} else {
		return 0;
	}
	fs->n++;

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

void
filter_free(struct filter_expr *e)
{
	size_t i;
	struct filter_simple *fs;

	for (i=0; i<e->n; i++) {
		fs = e->filter[i].arg;
		if (fs) {
			free(fs->data);
			fs->data = NULL;
			free(fs);
		}
		e->filter[i].arg = NULL;
	}

	free(e->filter);
	free(e);
}

static void
filter_dump_addr(struct CIDR *cidr, FILE *f)
{
	int i;

	if (cidr->version == 4) {
		fprintf(f, " ");
		for (i=0; i<4; i++) {
			fprintf(f, "%d", cidr->ipv4[i]);
			if (i != 3) {
				fprintf(f, ".");
			}
		}
	} else if (cidr->version == 6) {
		fprintf(f, " ");
		for (i=0; i<16; i++) {
			fprintf(f, "%d", cidr->ipv6[i]);
			if (i != 15) {
				fprintf(f, ".");
			}
		}
	} else {
		fprintf(f, " <Unknown IP version>");
	}
}

static void
filter_dump_simple(struct filter_simple *fs, FILE *f)
{
	size_t i;

	if (fs->direction == FILTER_SIMPLE_DIR_SRC) {
		fprintf(f, "SRC ");
	} else if (fs->direction == FILTER_SIMPLE_DIR_DST) {
		fprintf(f, "DST ");
	} else if (fs->direction == FILTER_SIMPLE_DIR_BOTH) {
		fprintf(f, "SRC OR DST ");
	} else {
		fprintf(f, "<Unknown direction %d> ", fs->direction);
	}

	if (fs->type == FILTER_SIMPLE_NET) {
		fprintf(f, "NET");

		for (i=0; i<fs->n; i++) {
			filter_dump_addr(&(fs->data[i].cidr), f);
		}
	} else if (fs->type == FILTER_SIMPLE_RANGE) {
		fprintf(f, "RANGE");

		for (i=0; i<fs->n; i++) {
			fprintf(f, " %d-%d", fs->data[i].range.low,
				fs->data[i].range.high);
		}
	} else {
		fprintf(f, "<Unknown type %d>", fs->type);
	}

	fprintf(f, "\n");
}

void
filter_dump(struct filter_expr *e, FILE *f)
{
	size_t i;
	struct filter_simple *fs;

	for (i=0; i<e->n; i++) {
		switch (e->filter[i].op) {
			case FILTER_OP_SIMPLE:
				fs = e->filter[i].arg;
				filter_dump_simple(fs, f);
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

