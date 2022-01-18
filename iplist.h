#ifndef iplist_h_included
#define iplist_h_included

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

struct iplist;

int iplists_load(const char *dirname);

struct iplist *iplist_get_by_name(const char *name);

int iplist_match4(struct iplist *l, uint32_t addr);

#endif

