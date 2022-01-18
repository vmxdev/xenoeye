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
	struct bitwise_trie_node *nodes;
	size_t n;
};

static struct iplist *iplists = NULL;
size_t n_iplists = 0;

static int
iplist_add4(struct iplist *l, uint32_t addr, int mask)
{
	int i;
	uint32_t node, next;

	if (!l->nodes) {
		l->nodes = calloc(1, sizeof(struct bitwise_trie_node));
		if (!l->nodes) {
			return 0;
		}
		l->n = 1;
	}

	node = 0;
	addr = ntohl(addr);

	for (i=0; i<mask; i++) {
		struct bitwise_trie_node *tmp;
		int pos, bit;

		pos = 31 - i;
		bit = !!(addr & (1 << pos));

		next = l->nodes[node].next[bit];
		if (next) {
			node = next;
			continue;
		}

		tmp = realloc(l->nodes,
			(l->n + 1) * sizeof(struct bitwise_trie_node));

		if (!tmp) {
			free(l->nodes);
			l->nodes = NULL;
			l->n = 0;
			return 0;
		}

		l->nodes = tmp;
		memset(&l->nodes[l->n], 0, sizeof(struct bitwise_trie_node));
		l->nodes[node].next[bit] = l->n;
		node = l->n;
		l->n++;
	}
	l->nodes[node].is_leaf = 1;

	return 1;
}

int
iplist_match4(struct iplist *l, uint32_t addr)
{
	int i;
	uint32_t node = 0, next = 0;

	if (!l->nodes) {
		return 0;
	}

	addr = ntohl(addr);
	for (i=0; i<32; i++) {
		int pos, bit;

		pos = 31 - i;
		bit = !!(addr & (1 << pos));

		next = l->nodes[node].next[bit];
		if (!next) {
			break;
		}
		node = next;
	}

	return l->nodes[node].is_leaf ? 1 : 0;
}

static int
iplist_try_load(const char *filename, const char *listname)
{
	struct iplist *tmp;
	FILE *f;

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
	tmp[n_iplists].nodes = NULL;
	tmp[n_iplists].n = 0;

	while (!feof(f)) {
		char line[INET6_ADDRSTRLEN + 1];
		uint32_t addr;
		char *mask_sym;
		int mask = 32;

		fgets(line, sizeof(line) - 1, f);
		line[strcspn(line, "\n")] = 0;

		mask_sym = strchr(line, '/');
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

		if (inet_pton(AF_INET, line, &addr)) {
			iplist_add4(&tmp[n_iplists], addr, mask);
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

