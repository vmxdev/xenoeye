/*
 * xenoeye
 *
 * Copyright (c) 2022, Vladimir Misyurov, Michael Kogan
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>

#include "iplist.h"

struct bitwise_trie_node
{
	uint32_t next[2];
	int is_leaf;
};

struct iplist
{
	char name[PATH_MAX];
	struct bitwise_trie_node *nodes4;
	struct bitwise_trie_node *nodes6;
	size_t n4, n6;
};

static struct iplist *iplists = NULL;
size_t n_iplists = 0;

char *
iplist_name(struct iplist *l)
{
	return l->name;
}

static int
iplist_add4(struct iplist *l, uint32_t addr, int mask)
{
	int i;
	uint32_t node, next;
	uint8_t *addr_ptr = (uint8_t *)&addr;

	if (!l->nodes4) {
		/* empty database */
		l->nodes4 = calloc(1, sizeof(struct bitwise_trie_node));
		if (!l->nodes4) {
			return 0;
		}
		l->n4 = 1;
	}

	node = 0;

	for (i=0; i<mask; i++) {
		struct bitwise_trie_node *tmp;
		int bit, bit_n;
		uint8_t byte;

		byte = addr_ptr[i / 8];
		bit_n = 7 - (i % 8);
		bit = !!(byte & (1 << bit_n));

		next = l->nodes4[node].next[bit];
		if (next) {
			node = next;
			continue;
		}

		tmp = realloc(l->nodes4,
			(l->n4 + 1) * sizeof(struct bitwise_trie_node));

		if (!tmp) {
			free(l->nodes4);
			l->nodes4 = NULL;
			l->n4 = 0;
			return 0;
		}

		l->nodes4 = tmp;
		memset(&l->nodes4[l->n4], 0, sizeof(struct bitwise_trie_node));
		l->nodes4[node].next[bit] = l->n4;
		node = l->n4;
		l->n4++;
	}
	l->nodes4[node].is_leaf = 1;

	return 1;
}

static int
iplist_add6(struct iplist *l, xe_ip *addr, int mask)
{
	int i;
	uint32_t node, next;
	uint8_t *addr_ptr = (uint8_t *)addr;

	if (!l->nodes6) {
		/* empty database */
		l->nodes6 = calloc(1, sizeof(struct bitwise_trie_node));
		if (!l->nodes6) {
			return 0;
		}
		l->n6 = 1;
	}

	node = 0;

	for (i=0; i<mask; i++) {
		struct bitwise_trie_node *tmp;
		int bit, bit_n;
		uint8_t byte;

		byte = addr_ptr[i / 8];
		bit_n = 7 - (i % 8);
		bit = !!(byte & (1 << bit_n));

		next = l->nodes6[node].next[bit];
		if (next) {
			node = next;
			continue;
		}

		tmp = realloc(l->nodes6,
			(l->n6 + 1) * sizeof(struct bitwise_trie_node));

		if (!tmp) {
			free(l->nodes6);
			l->nodes6 = NULL;
			l->n6 = 0;
			return 0;
		}

		l->nodes6 = tmp;
		memset(&l->nodes6[l->n6], 0, sizeof(struct bitwise_trie_node));
		l->nodes6[node].next[bit] = l->n6;
		node = l->n6;
		l->n6++;
	}
	l->nodes6[node].is_leaf = 1;

	return 1;
}

int
iplist_match4(struct iplist *l, uint32_t addr)
{
	int i;
	uint32_t node = 0, next = 0;
	uint8_t *addr_ptr = (uint8_t *)&addr;

	if (!l->nodes4) {
		return 0;
	}

	for (i=0; i<32; i++) {
		int bit, bit_n;
		uint8_t byte;

		byte = addr_ptr[i / 8];
		bit_n = 7 - (i % 8);
		bit = !!(byte & (1 << bit_n));

		next = l->nodes4[node].next[bit];
		if (!next) {
			break;
		}
		node = next;
	}

	return l->nodes4[node].is_leaf ? 1 : 0;
}

int
iplist_match6(struct iplist *l, xe_ip *addr)
{
	int i;
	uint32_t node = 0, next = 0;
	uint8_t *addr_ptr = (uint8_t *)addr;

	if (!l->nodes6) {
		return 0;
	}

	for (i=0; i<16*8; i++) {
		int bit, bit_n;
		uint8_t byte;

		byte = addr_ptr[i / 8];
		bit_n = 7 - (i % 8);
		bit = !!(byte & (1 << bit_n));

		next = l->nodes6[node].next[bit];
		if (!next) {
			break;
		}
		node = next;
	}

	return l->nodes6[node].is_leaf ? 1 : 0;
}

static int
iplist_try_load(const char *filename, const char *listname)
{
	struct iplist *tmp;
	FILE *f;
	int line_no = 0;

	f = fopen(filename, "r");
	if (!f) {
		return 0;
	}

	tmp = realloc(iplists,
		(n_iplists + 1) * sizeof(struct iplist));
	if (!tmp) {
		goto realloc_fail;
	}

	strcpy(tmp[n_iplists].name, listname);
	tmp[n_iplists].nodes4 = NULL;
	tmp[n_iplists].n4 = 0;

	tmp[n_iplists].nodes6 = NULL;
	tmp[n_iplists].n6 = 0;

	for (;;) {
		char line[INET6_ADDRSTRLEN + 1];
		char *str_addr;
		uint32_t addr;
		xe_ip addr6;
		char *mask_sym;
		int mask = 32;

		fgets(line, sizeof(line) - 1, f);
		if (feof(f)) {
			break;
		}
		line_no++;

		line[strcspn(line, "\n#")] = 0;
		str_addr = string_trim(line);
		if (strlen(str_addr) == 0) {
			continue;
		}

		mask_sym = strchr(str_addr, '/');
		if (mask_sym) {
			char *endptr;

			*mask_sym = '\0';
			mask_sym++;
			mask = strtol(mask_sym, &endptr, 10);
			if (*endptr != '\0') {
				/* incorrect mask */
				continue;
			}
		}

		if (inet_pton(AF_INET, str_addr, &addr)) {
			iplist_add4(&tmp[n_iplists], addr, mask);
		} else if (inet_pton(AF_INET6, str_addr, &addr6)) {
			iplist_add6(&tmp[n_iplists], &addr6, mask);
		} else {
			/* can't parse */
			LOG("Can't parse address '%s', list '%s', line %d",
				str_addr, filename, line_no);
		}
	}

	iplists = tmp;
	n_iplists++;

	return 1;

realloc_fail:
	fclose(f);
	return 0;
}

int
iplists_load(const char *dirname)
{
	DIR *d;
	struct dirent *dir;

	d = opendir(dirname);
	if (!d) {
		return 0;
	}

	while ((dir = readdir(d)) != NULL) {
		char path[PATH_MAX];

		if (dir->d_name[0] == '.') {
			continue;
		}
		sprintf(path, "%s/%s", dirname, dir->d_name);
		iplist_try_load(path, dir->d_name);
	}
	closedir(d);

	return 1;
}

struct iplist *
iplist_get_by_name(const char *name)
{
	size_t i;
	struct iplist *ret = NULL;

	for (i=0; i<n_iplists; i++) {
		if (strcmp(name, iplists[i].name) == 0) {
			ret = &iplists[i];
			break;
		}
	}

	return ret;
}

