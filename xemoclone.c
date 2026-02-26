/*
 *
 * Copyright (c) 2026, Vladimir Misyurov
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
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#include "utils.h"

#define MAX_LINE_LEN 4096
#define TEMPLATE_MARK "//!tmpl"

struct repl_kv
{
	char *key;
	char *val;
};

struct repl_data
{
	struct repl_kv *rkv;
	size_t n;
};

static void
print_usage(const char *progname)
{
	printf("Usage: %s -i SRC_DIR -o DST_DIR [-r \"A=B[;C=D[;...]]\"]\n",
		progname);
}

static void
str_replace(char *s, char *search_for, char *replace_with)
{
	char res[MAX_LINE_LEN];
	char *k;
	size_t prefix_size, replace_with_size;

	k = strstr(s, search_for);
	if (!k) {
		return;
	}
	prefix_size = k - s;
	replace_with_size = strlen(replace_with);

	memcpy(res, s, prefix_size);
	memcpy(res + prefix_size, replace_with, replace_with_size);
	strcpy(res + prefix_size + replace_with_size, 
		s + prefix_size + strlen(search_for));

	strcpy(s, res);
}

static void
line_process(char *line, struct repl_data *rd)
{
	size_t i;

	str_replace(line, TEMPLATE_MARK, "");

	for (i=0; i<rd->n; i++) {
		char skey[MAX_LINE_LEN];

		sprintf(skey, "${%s}", rd->rkv[i].key);
		str_replace(line, skey, rd->rkv[i].val);
	}
}


static void
conf_process(char *in, char *out, struct repl_data *rd)
{
	FILE *i, *o;

	i = fopen(in, "r");
	if (!i) {
		fprintf(stderr, "ERR: Can't open '%s': %s\n", in,
			strerror(errno));
	}

	o = fopen(out, "w");
	if (!o) {
		fprintf(stderr, "ERR: Can't open '%s': %s\n", out,
			strerror(errno));
		goto fail_open_o;
	}

	for (;;) {
		char line[MAX_LINE_LEN];

		if (!fgets(line, MAX_LINE_LEN, i)) {
			break;
		}
		if (feof(i)) {
			break;
		}

		if (strstr(line, TEMPLATE_MARK)) {
			fputs(line, o);
			line_process(line, rd);
			fputs(line, o);
			fgets(line, MAX_LINE_LEN, i);
		} else {
			fputs(line, o);
		}
	}

	fclose(o);

fail_open_o:
	fclose(i);
}


static int
process_recur(char *path, char *out, struct repl_data *rd)
{
	DIR *dir;
	struct dirent *dent;
	struct stat st;

	dir = opendir(path);
	if (!dir) {
		fprintf(stderr, "ERR: Can't open '%s': %s\n", path,
			strerror(errno));
		return 0;
	}

	if (lstat(path, &st) != 0) {
		fprintf(stderr, "WARN: lstat() failed on '%s': %s\n",
			path, strerror(errno));
		return 0;
	}
	if (mkdir(out, st.st_mode) != 0) {
		int err = errno;
		fprintf(stderr, "WARN: mkdir('%s') failed: %s\n",
			out, strerror(errno));
		if (err != EEXIST) {
			return 0;
		}
	}

	while ((dent = readdir(dir))) {
		char filename[PATH_MAX];
		char outfilename[PATH_MAX];

		if (dent->d_name[0] == '.') {
			continue;
		}

		sprintf(filename, "%s/%s", path, dent->d_name);
		sprintf(outfilename, "%s/%s", out, dent->d_name);

		if (lstat(filename, &st) != 0) {
			fprintf(stderr, "WARN: lstat() failed on '%s': %s\n",
				path, strerror(errno));
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			/* walk deeper */
			if (!process_recur(filename, outfilename, rd)) {
				return 0;
			}
		}

		if (S_ISREG(st.st_mode)) {
			/* process config file */
			conf_process(filename, outfilename, rd);
		}
	}

	closedir(dir);
	return 1;
}

static struct repl_data *
replacement_list_parse(char *repl)
{
	struct repl_data *rd = NULL;
	struct repl_kv *tmp_rkv;

	rd = malloc(sizeof(struct repl_data));
	if (!rd) {
		fprintf(stderr, "ERR: malloc() failed\n");
		return NULL;
	}

	rd->n = 0;
	rd->rkv = NULL;

	if (!repl) {
		fprintf(stderr, "WARN: Empty replacements list\n");
		return rd;
	}

	repl = string_trim(repl);

	while (strlen(repl) > 0) {
		char *eq, *delim;
		char *key, *val;

		eq = strchr(repl, '=');
		if (!eq) {
			fprintf(stderr, "WARN: Malformed replacements list: "
				"missing '='\n");
			break;
		}

		*eq = '\0';
		repl = string_trim(repl);
		key = strdup(repl);

		repl = eq + 1;
		if (strlen(repl) == 0) {
			fprintf(stderr, "WARN: Malformed replacements list: "
				"no value\n");
			free(key);
			break;
		}

		delim = strchr(repl, ';');
		if (delim) {
			*delim = '\0';
			repl = string_trim(repl);
			val = strdup(repl);
			repl = delim + 1;
		} else {
			repl = string_trim(repl);
			val = strdup(repl);
			repl += strlen(repl);
		}

		tmp_rkv = realloc(rd->rkv,
			sizeof(struct repl_kv) * (rd->n + 1));
		if (!tmp_rkv) {
			fprintf(stderr, "ERR: realloc() failed\n");
			return NULL;
		}

		rd->rkv = tmp_rkv;
		rd->rkv[rd->n].key = key;
		rd->rkv[rd->n].val = val;
		rd->n += 1;
	}

	return rd;
}


static void
replacement_list_free(struct repl_data *rd)
{
	size_t i;

	for (i=0; i<rd->n; i++) {
		free(rd->rkv[i].key);
		free(rd->rkv[i].val);
	}
	free(rd->rkv);
}

int
main(int argc, char *argv[])
{
	int opt;
	char *input = NULL, *output = NULL;
	char *repl = NULL;
	struct repl_data *rd;

	while ((opt = getopt(argc, argv, "hi:o:r:")) != -1) {
		switch (opt) {
			case 'i':
				input = optarg;
				break;

			case 'o':
				output = optarg;
				break;

			case 'r':
				repl = optarg;
				break;

			case 'h':
				print_usage(argv[0]);
				return EXIT_SUCCESS;

			default:
				fprintf(stderr, "Unrecognized option '%c'\n",
					opt);
				print_usage(argv[0]);
				return EXIT_FAILURE;
		}
	}

	if (!input) {
		fprintf(stderr, "Input dir required (-i ...)\n");
		return EXIT_FAILURE;
	}

	if (!output) {
		fprintf(stderr, "Output dir required (-o ...)\n");
		return EXIT_FAILURE;
	}

	rd = replacement_list_parse(repl);
	if (!rd) {
		return EXIT_FAILURE;
	}

	if (!process_recur(input, output, rd)) {
		replacement_list_free(rd);
		free(rd);
		return EXIT_FAILURE;
	}

	replacement_list_free(rd);
	free(rd);

	return EXIT_SUCCESS;
}

