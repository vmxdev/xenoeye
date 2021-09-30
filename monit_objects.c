/*
 * xenoeye
 *
 * Copyright (c) 2020-2021, Vladimir Misyurov, Michael Kogan
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

#include "aajson/aajson.h"

#include "utils.h"
#include "xenoeye.h"
#include "filter.h"
#include "flow_debug.h"


struct mo_fieldset
{
	/* all fields */
	size_t n;
	struct field *fields;

	/* key fields (without packets/octets) */
	size_t nkey;
	struct field *key;
};

struct mo_fwm
{
	char name[TOKEN_MAX_SIZE];
	struct mo_fieldset fieldset;
	int time;
};

#define STRCMP(A, I, S) strcmp(A->path_stack[I].data.path_item, S)

static int
fixed_window_mem_config(struct aajson *a, aajson_val *value,
	struct monit_object *mo)
{
	size_t i;
	struct mo_fwm *window;

	if (a->path_stack[2].type != AAJSON_PATH_ITEM_ARRAY) {
		LOG("'fwn' must be array");
		return 0;
	}

	i = a->path_stack[2].data.array_idx;
	if (i <= mo->nfwm) {
		struct mo_fwm *tmp;

		/* append new window */
		tmp = realloc(mo->fwms, (i + 1) * sizeof(struct mo_fwm));
		if (!tmp) {
			LOG("Insufficient memory");
			return 0;
		}
		memset(&tmp[i], 0, sizeof(struct mo_fwm));

		mo->fwms = tmp;
		mo->nfwm = i + 1;;
	}

	window = &mo->fwms[i];

	if (STRCMP(a, 3, "name") == 0) {
		strcpy(window->name, value->str);
	} else if (STRCMP(a, 3, "fields") == 0) {
		/* append field */
		struct field fld;
		char err[ERR_MSG_LEN];

		if (!parse_field(value->str, &fld, err)) {
			LOG("Can't parse field '%s': %s", value->str, err);
			return 0;
		}
	} else if (STRCMP(a, 3, "time") == 0) {
		window->time = atoi(value->str);
		if (window->time < 0) {
			LOG("Incorrect time '%s'", value->str);
			return 0;
		}
	}

	return 1;
}

static int
monit_object_json_callback(struct aajson *a, aajson_val *value, void *user)
{
	struct monit_object *mo;
	char *key = a->path_stack[a->path_stack_pos].data.path_item;

	mo = (struct monit_object *)user;

	if (a->path_stack_pos == 1) {
		if (strcmp(key, "filter") == 0) {
			struct filter_input input;

			memset(&input, 0, sizeof(input));
			input.s = value->str;
			mo->expr = parse_filter(&input);
			if (input.error) {
				LOG("Parse error: %s", input.errmsg);
				return 0;
			}
		}
	}

	if (STRCMP(a, 1, "debug") == 0) {
		return flow_debug_config(a, value, &mo->debug);
	}

	if (STRCMP(a, 1, "fwm") == 0) {
		/* fixed window in memory */
		return fixed_window_mem_config(a, value, mo);
	}

	return 1;
}

#undef STRCMP

static int
monit_object_info_parse(struct xe_data *data, const char *miname,
	const char *fn)
{
	FILE *f;
	struct stat st;
	size_t s;
	char *json;
	int ret = 0;
	struct monit_object mi, *mitmp;

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

	memset(&mi, 0, sizeof(struct monit_object));
	/* parse */
	aajson_init(&a, json);
	aajson_parse(&a, &monit_object_json_callback, &mi);
	if (a.error) {
		LOG("Can't parse config file '%s' (line: %lu, col: %lu): %s",
			fn, a.line, a.col, a.errmsg);
		goto fail_parse;
	}

	mitmp = realloc(data->monit_objects, (data->nmonit_objects + 1)
		* sizeof(struct monit_object));
	if (!mitmp) {
		LOG("realloc() failed");
		goto fail_realloc;
	}

	filter_dump(mi.expr, stdout);

	/* copy name of monitoring object */
	strcpy(mi.name, miname);

	data->monit_objects = mitmp;
	data->monit_objects[data->nmonit_objects] = mi;
	data->nmonit_objects++;

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
monit_objects_init(struct xe_data *data)
{
	DIR *d;
	struct dirent *dir;
	int ret = 1;
	char midir[PATH_MAX] = "monit_objects";
	char mifile[PATH_MAX];

	free(data->monit_objects);
	data->monit_objects = NULL;
	data->nmonit_objects = 0;

	d = opendir(midir);
	if (!d) {
		LOG("Can't open directory with monitoring objects '%s': %s",
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

		sprintf(mifile, "%s/%s/mo.conf", midir, dir->d_name);
		LOG("Adding monitoring object '%s'", dir->d_name);

		if (!monit_object_info_parse(data, dir->d_name, mifile)) {
			continue;
		}
	}

	closedir(d);

fail_opendir:
	return ret;
}

