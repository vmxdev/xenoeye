/*
 * xenoeye
 *
 * Copyright (c) 2020, Vladimir Misyurov, Michael Kogan
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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdlib.h>


#include "utils.h"
#include "xenoeye.h"
#include "filter.h"
#include "aajson/aajson.h"

static int
monit_item_json_callback(struct aajson *a, aajson_val *value, void *user)
{
	struct monit_item *mi;
	char *key = a->path_stack[a->path_stack_pos].data.path_item;

	mi = (struct monit_item *)user;

	if (a->path_stack_pos == 1) {
		if (strcmp(key, "filter") == 0) {
			struct filter_input input;

			memset(&input, 0, sizeof(input));
			input.s = value->str;
			mi->expr = parse_filter(&input);
			if (input.error) {
				LOG("Parse error: %s", input.errmsg);
				return 0;
			}
		}
	}
	return 1;
}

static int
monit_item_info_parse(struct xe_data *data, const char *miname, const char *fn)
{
	FILE *f;
	struct stat st;
	size_t s;
	char *json;
	int ret = 0;
	struct monit_item mi, *mitmp;

	struct aajson a;

	/* read entire file in memory */
	f = fopen(fn, "r");
	if (!f) {
		LOG("Can't open info file '%s': %s", fn, strerror(errno));
		goto fail_open;
	}

	if (fstat(fileno(f), &st) < 0) {
		LOG("Can't make fstat() on info file '%s': %s",
			fn, strerror(errno));
		goto fail_fstat;
	}

	json = (char *)malloc(st.st_size + 1);
	if (!json) {
		LOG("malloc(%lu) failed", (unsigned long int)(st.st_size + 1));
		goto fail_malloc;
	}

	s = fread(json, st.st_size, 1, f);
	if (s != 1) {
		LOG("Can't read file '%s'", fn);
		goto fail_fread;
	}

	/* parse */
	aajson_init(&a, json);
	aajson_parse(&a, &monit_item_json_callback, &mi);
	if (a.error) {
		LOG("Can't parse json file '%s': %s", fn, a.errmsg);
		goto fail_parse;
	}

	mitmp = realloc(data->monit_items, (data->nmonit_items + 1)
		* sizeof(struct monit_item));
	if (!mitmp) {
		LOG("realloc() failed");
		goto fail_realloc;
	}

	/* copy name of monitoring item */
	strcpy(mi.name, miname);

	data->monit_items = mitmp;
	data->monit_items[data->nmonit_items] = mi;
	data->nmonit_items++;

	ret = 1;

fail_realloc:
fail_parse:
fail_fread:
	free(json);
fail_malloc:
fail_fstat:
	fclose(f);
fail_open:

	return ret;
}

int
monit_items_init(struct xe_data *data)
{
	DIR *d;
	struct dirent *dir;
	int ret = 1;
	char midir[PATH_MAX] = "monit_items";
	char mifile[PATH_MAX];

	free(data->monit_items);
	data->monit_items = NULL;
	data->nmonit_items = 0;

	d = opendir(midir);
	if (!d) {
		LOG("Can't open directory with monitoring items '%s': %s",
			midir, strerror(errno));
		goto fail_opendir;
	}

	while ((dir = readdir(d)) != NULL) {
		if (dir->d_name[0] == '.') {
			/* skip hidden files */
			continue;
		}

		if (dir->d_type != DT_DIR) {
			continue;
		}

		sprintf(mifile, "%s/%s/info.json", midir, dir->d_name);
		LOG("Adding monitoring item '%s'", dir->d_name);

		if (!monit_item_info_parse(data, dir->d_name, mifile)) {
			continue;
		}
	}

	closedir(d);

fail_opendir:
	return ret;
}

