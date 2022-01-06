#ifndef iplist_h_included
#define iplist_h_included

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

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


int iplists_load(const char *dirname);

struct iplist *iplist_get_by_name(const char *name);

int iplist_match4(struct iplist *l, uint32_t addr);

#endif

