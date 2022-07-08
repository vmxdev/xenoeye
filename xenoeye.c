/*
 * xenoeye
 *
 * Copyright (c) 2018-2021, Vladimir Misyurov, Michael Kogan
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
#include <signal.h>

#include "aajson/aajson.h"

#include "utils.h"
#include "netflow.h"
#include "netflow_templates.h"
#include "flow_debug.h"
#include "xenoeye.h"
#include "devices.h"

#define DEFAULT_CONFIG_FILE "/etc/xenoeye/xenoeye.conf"
#define DEFAULT_TEMPLATES_FILE "/var/lib/xenoeye/templates.tkv"
#define DEFAULT_EXPORT_DIR "/var/lib/xenoeye/exp/"
#define DEFAULT_IPLISTS_DIR "/var/lib/xenoeye/iplists/"
#define DEFAULT_NOTIF_DIR "/var/lib/xenoeye/notifications/"

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

#define STRCMP(A, I, S) strcmp(A->path_stack[I].data.path_item, S)

static int
config_templates(struct aajson *a, aajson_val *value, struct xe_data *data)
{
	if (STRCMP(a, 2, "db") == 0) {
		strcpy(data->templates_db, value->str);
	}

	if (STRCMP(a, 2, "allow-templates-in-future") == 0) {
		if (value->type == AAJSON_VALUE_TRUE) {
			data->allow_templates_in_future = 1;
		}
		if (value->type == AAJSON_VALUE_NUM) {
			data->allow_templates_in_future = atoi(value->str);
		}
	}

	return 1;
}


static int
config_callback(struct aajson *a, aajson_val *value, void *user)
{
	struct xe_data *data = user;
	size_t idx;

	if (STRCMP(a, 1, "devices") == 0) {
		strcpy(data->devices, value->str);
	}

	if (STRCMP(a, 1, "mo-dir") == 0) {
		strcpy(data->mo_dir, value->str);
	}

	if (STRCMP(a, 1, "export-dir") == 0) {
		strcpy(data->exp_dir, value->str);
	}

	if (STRCMP(a, 1, "iplists-dir") == 0) {
		strcpy(data->iplists_dir, value->str);
	}

	if (STRCMP(a, 1, "notifications-dir") == 0) {
		strcpy(data->notif_dir, value->str);
	}

	if (a->path_stack_pos < 2) {
		return 1;
	}

	if (STRCMP(a, 1, "templates") == 0) {
		return config_templates(a, value, data);
	}

	if (STRCMP(a, 1, "debug") == 0) {
		return flow_debug_config(a, value, &data->debug);
	}

	if (STRCMP(a, 1, "capture") != 0) {
		return 1;
	}

	if (a->path_stack_pos != 4) {
		return 1;
	}

	if (a->path_stack[2].type != AAJSON_PATH_ITEM_ARRAY) {
		return 1;
	}
	idx = a->path_stack[2].data.array_idx;

	if (STRCMP(a, 3, "pcap") == 0) {
		if (!config_adjust_cap_size(data, idx)) {
			return 0;
		}

		data->cap[data->ncap - 1].type = XENOEYE_CAPTURE_TYPE_PCAP;

		if (STRCMP(a, 4, "interface") == 0) {
			data->cap[data->ncap - 1].iface = strdup(value->str);
		}

		if (STRCMP(a, 4, "filter") == 0) {
			data->cap[data->ncap - 1].filter = strdup(value->str);
		}
	}

	if (STRCMP(a, 3, "socket") == 0) {
		if (!config_adjust_cap_size(data, idx)) {
			return 0;
		}

		data->cap[data->ncap - 1].type = XENOEYE_CAPTURE_TYPE_SOCKET;

		if (STRCMP(a, 4, "listen-on") == 0) {
			data->cap[data->ncap - 1].addr = strdup(value->str);
		}

		if (STRCMP(a, 4, "port") == 0) {
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

	return 1;
}
#undef STRCMP

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

	data->nthreads = data->ncap;

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

			nfpkt.src_addr_ipv4 =
				 *((uint32_t *)&(addr->sin_addr));
		} else {
			nfpkt.src_addr_ipv4 = 0;
		}

		if (netflow_process(params.data, params.idx, &nfpkt, len)) {
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

static struct xe_data *tmp_data;

static void
on_ctrl_c(int s)
{
	if (s != SIGINT) {
		return;
	}

	/* TODO: correct shutdown */
	exit(0);
}

int
main(int argc, char *argv[])
{
	char *conffile = NULL;
	struct xe_data data;
	int opt;
	size_t i;
	struct sigaction sig_int;


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
	atomic_init(&data.stop, 0);

	if (!config_parse(&data, conffile ? conffile : DEFAULT_CONFIG_FILE)) {
		return EXIT_FAILURE;
	}

	/* load devices with sampling rates */
	if (*data.devices) {
		if (!devices_load(data.devices)) {
			LOG("Devices list with sampling rates not loaded");
		}
	} else {
		LOG("Devices file is not set in config, sampling rate of "
			"all devices will be 1");
	}

	/* check exports directory */
	if (!*data.exp_dir) {
		strcpy(data.exp_dir, DEFAULT_EXPORT_DIR);
		LOG("Export dir is not set, using default '%s'",
			DEFAULT_EXPORT_DIR);
	}

	/* IP lists directory */
	if (!*data.iplists_dir) {
		strcpy(data.iplists_dir, DEFAULT_IPLISTS_DIR);
		LOG("IP lists dir is not set, using default '%s'",
			DEFAULT_IPLISTS_DIR);
	}
	if (!iplists_load(data.iplists_dir)) {
		LOG("Can't load IP lists from '%s': %s", data.iplists_dir,
			strerror(errno));
	}

	/* notofications directory */
	if (!*data.notif_dir) {
		strcpy(data.notif_dir, DEFAULT_NOTIF_DIR);
		LOG("notifications dir is not set, using default '%s'",
			DEFAULT_NOTIF_DIR);
	}

	/* templates database */
	if (!*data.templates_db) {
		strcpy(data.templates_db, DEFAULT_TEMPLATES_FILE);
		LOG("Templates DB file is not set, using default '%s'",
			DEFAULT_TEMPLATES_FILE);
	}

	LOG("Allow templates in future: %s",
		data.allow_templates_in_future ? "yes": "no");

	if (!monit_objects_init(&data)) {
		LOG("Can't init monitoring objects");
	}

	if (!netflow_templates_init(&data)) {
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


	tmp_data = &data;
	sig_int.sa_handler = &on_ctrl_c;
	sigemptyset(&sig_int.sa_mask);
	sig_int.sa_flags = 0;
	sigaction(SIGINT, &sig_int, NULL);

	/* FIXME: correct shutdown */
	for (i=0; i<data.ncap; i++) {
		pthread_join(data.cap[i].tid, NULL);
	}

	netflow_templates_shutdown();

	return EXIT_SUCCESS;
}

