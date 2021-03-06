/*
 * xenoeye
 *
 * Copyright (c) 2018-2020, Vladimir Misyurov, Michael Kogan
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
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <pthread.h>

#include "utils.h"
#include "netflow.h"
#include "netflow_templates.h"
#include "xenoeye.h"
#include "aajson/aajson.h"

#define DEFAULT_CONFIG_FILE "xeconfig.json"

static void
print_usage(const char *progname)
{
	fprintf(stderr, "Usage:\n %s [-c config.json]\n", progname);
	fprintf(stderr, " %s -h\n", progname);
	fprintf(stderr, "    -c config file (default '%s')\n",
		DEFAULT_CONFIG_FILE);
	fprintf(stderr, "    -h print this message\n");
}

static int
config_adjust_cap_size(struct xe_data *data, size_t idx)
{
	struct capture *tmp;

	if (data->ncap >= (idx + 1)) {
		return 1;
	}

	tmp = realloc(data->cap, (idx + 1) * sizeof(struct capture));
	if (!tmp) {
		LOG("realloc() failed");
		return 0;
	}

	data->cap = tmp;
	data->ncap = idx + 1;

	return 1;
}

static int
config_callback(struct aajson *a, aajson_val *value, void *user)
{
	struct xe_data *data = user;
	size_t idx;

#define STRCMP(I, S) strcmp(a->path_stack[I].data.path_item, S)

	if (a->path_stack_pos != 4) {
		return 1;
	}

	if (STRCMP(1, "capture") != 0) {
		return 1;
	}

	if (a->path_stack[2].type != AAJSON_PATH_ITEM_ARRAY) {
		return 1;
	}
	idx = a->path_stack[2].data.array_idx;

	if (STRCMP(3, "pcap") == 0) {
		if (!config_adjust_cap_size(data, idx)) {
			return 0;
		}

		data->cap[data->ncap - 1].type = XENOEYE_CAPTURE_TYPE_PCAP;

		if (STRCMP(4, "interface") == 0) {
			data->cap[data->ncap - 1].iface = strdup(value->str);
		}

		if (STRCMP(4, "filter") == 0) {
			data->cap[data->ncap - 1].filter = strdup(value->str);
		}
	}

	if (STRCMP(3, "socket") == 0) {
		if (!config_adjust_cap_size(data, idx)) {
			return 0;
		}

		data->cap[data->ncap - 1].type = XENOEYE_CAPTURE_TYPE_SOCKET;

		if (STRCMP(4, "listen-on") == 0) {
			data->cap[data->ncap - 1].addr = strdup(value->str);
		}

		if (STRCMP(4, "port") == 0) {
			struct servent *se;
			long int port;
			char *endptr;

			/* check if port is given by number */
			/* allow hex and octal forms */
			port = strtol(value->str, &endptr, 0);
			if (*endptr == '\0') {
				if ((port < 0) || (port > UINT16_MAX)) {
					LOG("Incorrect port number %s",
						value->str);
					return 0;
				}

				data->cap[data->ncap - 1].port = port;
				return 1;
			}

			/* search in services database */
			se = getservbyname(value->str, NULL);
			if (!se) {
				LOG("Can't convert '%s' to port number",
					value->str);
				return 0;
			}

			data->cap[data->ncap - 1].port = se->s_port;
		}
	}

#undef STRCMP

	return 1;
}

static int
config_parse(struct xe_data *data, const char *conffile)
{
	char *file = NULL;
	long int len;
	FILE *f;
	int ret = 0;
	struct aajson conf_json;

	f = fopen(conffile, "rb");
	if (!f) {
		LOG("Can't open config file '%s'", conffile);
		goto fail_open;
	}

	fseek(f, 0, SEEK_END);
	len = ftell(f);

	fseek(f, 0, SEEK_SET);
	file = malloc(len);
	if (!file) {
		LOG("Can't allocate %ld bytes", len);
		goto fail_alloc;
	}

	if (fread(file, 1, len, f) != (size_t)len) {
		LOG("Can't read config file '%s'", conffile);
		goto fail_read;
	}

	aajson_init(&conf_json, file);
	aajson_parse(&conf_json, &config_callback, data);

	if (conf_json.error) {
		LOG("Can't parse config file '%s': line %lu, col %lu: %s",
			conffile, conf_json.line, conf_json.col,
			conf_json.errmsg);
		goto fail_parse;
	}

	ret = 1;

fail_parse:
fail_read:
	free(file);
fail_alloc:
	fclose(f);
fail_open:
	return ret;
}

static void *
scapture_thread(void *arg)
{
	struct capture_thread_params params, *params_ptr;

	struct capture *cap;

	socklen_t clientlen;

	params_ptr = (struct capture_thread_params *)arg;
	params = *params_ptr;
	free(params_ptr);

	cap = &params.data->cap[params.idx];

	clientlen = sizeof(struct sockaddr);

	LOG("Starting collector thread on port %d", cap->port);

	for (;;) {
		ssize_t len;
		struct nf_packet_info nfpkt;

		len = recvfrom(cap->sockfd, nfpkt.rawpacket,
			MAX_NF_PACKET_SIZE, 0,
			&(nfpkt.src_addr), &clientlen);

		if (len < 0) {
			LOG("recvfrom() failed: %s", strerror(errno));

			continue;
		}

		if (nfpkt.src_addr.sa_family == AF_INET) {
			struct sockaddr_in *addr;

			addr = (struct sockaddr_in *)&nfpkt.src_addr;
			/* we're supporting only IPv4 */
			LOG("src_addr: %s", inet_ntoa(addr->sin_addr));

			nfpkt.src_addr_ipv4 =
				 *((uint32_t *)&(addr->sin_addr));
		} else {
			nfpkt.src_addr_ipv4 = 0;
		}

		if (netflow_process(params.data, &nfpkt, len)) {
			/* ok */
		}
	}

	close(cap->sockfd);

	return NULL;
}

static int
scapture_start(struct xe_data *data, size_t idx)
{
	int one = 1;
	struct capture_thread_params *params;
	struct sockaddr_in serveraddr;

	struct capture *cap = &data->cap[idx];

	int thread_err;

	params = malloc(sizeof(struct capture_thread_params));
	if (!params) {
		LOG("malloc() failed");
		goto fail_alloc;
	}

	params->data = data;
	params->idx = idx;

	cap->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (cap->sockfd < 0) {
		LOG("socket() failed: %s", strerror(errno));
		goto fail_socket;
	}

	if (setsockopt(cap->sockfd, SOL_SOCKET, SO_REUSEADDR,
		(const void *)&one, sizeof(int)) == -1) {

		LOG("setsockopt() failed: %s", strerror(errno));
		goto fail_setsockopt;
	}

	bzero((char *)&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;

	/* FIXME: take address from user */
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons(cap->port);

	if (bind(cap->sockfd, (struct sockaddr *)&serveraddr,
		sizeof(serveraddr)) < 0) {

		LOG("bind() failed: %s", strerror(errno));
		goto fail_bind;
	}

	thread_err = pthread_create(&cap->tid, NULL, &scapture_thread, params);

	if (thread_err) {
		LOG("Can't start thread: %s", strerror(thread_err));
		goto fail_thread;
	}

	return 1;

/* errors */
fail_thread:
fail_bind:
fail_setsockopt:
	close(cap->sockfd);
fail_socket:
	free(params);
fail_alloc:
	return 0;
}

int
main(int argc, char *argv[])
{
	char *conffile = NULL;
	struct xe_data data;
	int opt;
	size_t i;


	while ((opt = getopt(argc, argv, "c:h")) != -1) {
		switch (opt) {
			case 'c':
				conffile = optarg;
				break;

			case 'h':
			default:
				print_usage(argv[0]);
				return EXIT_SUCCESS;
		}
	}

	openlog(NULL, LOG_PERROR, LOG_USER);

	memset(&data, 0, sizeof(struct xe_data));
	if (!config_parse(&data, conffile ? conffile : DEFAULT_CONFIG_FILE)) {
		return EXIT_FAILURE;
	}

	if (!monit_items_init(&data)) {
		LOG("Can't init monitoring items, exiting");
		return EXIT_FAILURE;
	}

	if (!netflow_templates_init()) {
		LOG("Can't init templates storage, exiting");
		return EXIT_FAILURE;
	}

	for (i=0; i<data.ncap; i++) {
		if (data.cap[i].type == XENOEYE_CAPTURE_TYPE_PCAP) {
			if (!pcapture_start(&data, i)) {
				return EXIT_FAILURE;
			}
		} else if (data.cap[i].type == XENOEYE_CAPTURE_TYPE_SOCKET) {
			if (!scapture_start(&data, i)) {
				return EXIT_FAILURE;
			}
		}
	}

	/* FIXME: correct shutdown */
	for (i=0; i<data.ncap; i++) {
		pthread_join(data.cap[i].tid, NULL);
	}

	netflow_templates_shutdown();

	return EXIT_SUCCESS;
}

