/*
 * xenoeye
 *
 * Copyright (c) 2018-2023, Vladimir Misyurov, Michael Kogan
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
#include "netflow-templates.h"
#include "flow-debug.h"
#include "xenoeye.h"
#include "devices.h"
#include "geoip.h"

#define DEFAULT_CONFIG_FILE "/etc/xenoeye/xenoeye.conf"
#define DEFAULT_TEMPLATES_FILE "/var/lib/xenoeye/templates.tkv"
#define DEFAULT_EXPORT_DIR "/var/lib/xenoeye/exp/"
#define DEFAULT_IPLISTS_DIR "/var/lib/xenoeye/iplists/"
#define DEFAULT_NOTIF_DIR "/var/lib/xenoeye/notifications/"
#define DEFAULT_CLSF_DIR "/var/lib/xenoeye/clsf/"

static struct xe_data *globl;

static void
on_ctrl_c(int s)
{
	if (s != SIGINT) {
		return;
	}

	/* TODO: correct shutdown */
	exit(0);
}

static void
on_hup(int s)
{
	/* It is not safe to use the pthread_cond_signal() function
	 * in a signal handler
	 */
	(void)s;
	/* notify geoip thread */
	atomic_store_explicit(&globl->reload_geoip, 1, memory_order_relaxed);

	atomic_store_explicit(&globl->reload_config, 1, memory_order_relaxed);
}


static void
print_usage(const char *progname)
{
	fprintf(stderr, "Usage:\n %s [-c config.json]\n", progname);
	fprintf(stderr, " %s -h\n", progname);
	fprintf(stderr, "    -c config file (default '%s')\n",
		DEFAULT_CONFIG_FILE);
	fprintf(stderr, "    -h print this message\n");
}

static void *
config_reload_thread(void *arg)
{
	struct xe_data *globl = arg;

	for (;;) {
		if (atomic_load_explicit(&globl->stop, memory_order_relaxed)) {
			break;
		}
		if (atomic_load_explicit(&globl->reload_config,
			memory_order_relaxed)) {

			atomic_store_explicit(&globl->reload_config, 0,
				memory_order_relaxed);
			LOG("Reloading config");
			monit_objects_reload(globl);
			LOG("config reloaded");
		}
		usleep(10000);
	}

	return NULL;
}

#ifdef FLOWS_CNT
static void *
fc_thread(void *arg)
{
	struct xe_data *globl = arg;

	uint64_t flows = 0;
	int timeout = 10;

	for (;;) {
		sleep(timeout);
		LOG("fps: %lu", (globl->nflows - flows) / timeout);
		flows = globl->nflows;
	}

	return NULL;
}
#endif

#define STRCMP(A, I, S) strcmp(A->path_stack[I].data.path_item, S)

static size_t
config_adjust_cap_size(struct xe_data *data, size_t idx, enum FLOW_TYPE type)
{
	struct capture *tmp, *cap;
	size_t n;

	if (type == FLOW_TYPE_NETFLOW) {
		n = data->nnfcap;
		cap = data->nfcap;
	} else {
		n = data->nsfcap;
		cap = data->sfcap;
	}

	if (n >= (idx + 1)) {
		return 1;
	}

	tmp = realloc(cap, (idx + 1) * sizeof(struct capture));
	if (!tmp) {
		LOG("realloc() failed");
		return 0;
	}

	if (type == FLOW_TYPE_NETFLOW) {
		data->nfcap = tmp;
		data->nnfcap = idx + 1;
	} else {
		data->sfcap = tmp;
		data->nsfcap = idx + 1;
	}

	return 1;
}

static int
config_capture(struct aajson *a, aajson_val *value, struct xe_data *data,
	enum FLOW_TYPE type)
{
	size_t idx;

	if (a->path_stack_pos != 4) {
		return 1;
	}

	if (a->path_stack[2].type != AAJSON_PATH_ITEM_ARRAY) {
		return 1;
	}
	idx = a->path_stack[2].data.array_idx;

	if (STRCMP(a, 3, "pcap") == 0) {
		struct capture *cap;

		if (!config_adjust_cap_size(data, idx, type)) {
			return 0;
		}

		cap = type == FLOW_TYPE_NETFLOW ? 
			&data->nfcap[data->nnfcap - 1]
			:
			&data->sfcap[data->nsfcap - 1];

		cap->type = XENOEYE_CAPTURE_TYPE_PCAP;

		if (STRCMP(a, 4, "interface") == 0) {
			cap->iface = strdup(value->str);
		}

		if (STRCMP(a, 4, "filter") == 0) {
			cap->filter = strdup(value->str);
		}
	}

	if (STRCMP(a, 3, "socket") == 0) {
		struct capture *cap;

		if (!config_adjust_cap_size(data, idx, type)) {
			return 0;
		}

		cap = type == FLOW_TYPE_NETFLOW ? 
			&data->nfcap[data->nnfcap - 1]
			:
			&data->sfcap[data->nsfcap - 1];

		cap->type = XENOEYE_CAPTURE_TYPE_SOCKET;

		if (STRCMP(a, 4, "listen-on") == 0) {
			cap->addr = strdup(value->str);
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

				cap->port = port;
				return 1;
			}

			/* search in services database */
			se = getservbyname(value->str, NULL);
			if (!se) {
				LOG("Can't convert '%s' to port number",
					value->str);
				return 0;
			}

			cap->port = se->s_port;
		}
	}

	return 1;
}

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

	if (STRCMP(a, 1, "clsf-dir") == 0) {
		strcpy(data->clsf_dir, value->str);
	}

	/* geoip/as */
	if (STRCMP(a, 1, "geodb") == 0) {
		strcpy(data->geodb_dir, value->str);
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

	/* capture section */
	if (STRCMP(a, 1, "capture") == 0) {
		return config_capture(a, value, data, FLOW_TYPE_NETFLOW);
	}

	if (STRCMP(a, 1, "sflow-capture") == 0) {
		return config_capture(a, value, data, FLOW_TYPE_SFLOW);
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

	data->nthreads = data->nnfcap + data->nsfcap;

	ret = 1;

fail_parse:
fail_read:
	free(file);
fail_alloc:
	fclose(f);
fail_open:
	return ret;
}

int
main(int argc, char *argv[])
{
	char *conffile = NULL;
	struct xe_data data;
	int opt;
	size_t i;
	struct sigaction sig_int, sig_chld, sig_hup;
	int thread_err;
	size_t thread_idx;


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
	atomic_init(&data.mavg_db_bank_idx, 0);

	/* reload geoip/as db at start */
	atomic_init(&data.reload_geoip, 1);

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

	/* notifications directory */
	if (!*data.notif_dir) {
		strcpy(data.notif_dir, DEFAULT_NOTIF_DIR);
		LOG("notifications dir is not set, using default '%s'",
			DEFAULT_NOTIF_DIR);
	}

	/* classes directory */
	if (!*data.clsf_dir) {
		strcpy(data.clsf_dir, DEFAULT_CLSF_DIR);
		LOG("classification dir is not set, using default '%s'",
			DEFAULT_CLSF_DIR);
	}

	if (!*data.geodb_dir) {
		strcpy(data.geodb_dir, DEFAULT_GEODB_DIR);
		LOG("GeoIP/AS DB dir is not set, using default '%s'",
			DEFAULT_GEODB_DIR);
	}

	/* templates database */
	if (!*data.templates_db) {
		strcpy(data.templates_db, DEFAULT_TEMPLATES_FILE);
		LOG("Templates DB file is not set, using default '%s'",
			DEFAULT_TEMPLATES_FILE);
	}

	LOG("Allow templates in future: %s",
		data.allow_templates_in_future ? "yes": "no");

	globl = &data;

#ifdef FLOWS_CNT
	{
		thread_err = pthread_create(&data.fc_tid, NULL,
			&fc_thread, &data);

		if (thread_err) {
			LOG("Can't start thread: %s", strerror(thread_err));
			return EXIT_FAILURE;
		}
	}
#endif

	/* geoip/as */
	thread_err = pthread_create(&data.geoip_tid, NULL,
		&geoip_thread, &data);
	if (thread_err) {
		LOG("Can't start thread: %s", strerror(thread_err));
		return EXIT_FAILURE;
	}

	if (!monit_objects_init(&data)) {
		LOG("Can't init monitoring objects");
	}

	if (!netflow_templates_init(&data)) {
		LOG("Can't init templates storage, exiting");
		return EXIT_FAILURE;
	}

	/* config reload thread */
	thread_err = pthread_create(&data.config_tid, NULL,
		&config_reload_thread, &data);
	if (thread_err) {
		LOG("Can't start thread: %s", strerror(thread_err));
		return EXIT_FAILURE;
	}

	netflow_process_init();
	flow_debug_init();


	sig_int.sa_handler = &on_ctrl_c;
	sigemptyset(&sig_int.sa_mask);
	sig_int.sa_flags = 0;
	sigaction(SIGINT, &sig_int, NULL);

	/* HUP */
	sig_hup.sa_handler = &on_hup;
	sigemptyset(&sig_hup.sa_mask);
	sig_hup.sa_flags = 0;
	sigaction(SIGHUP, &sig_hup, NULL);

	/* childs */
	sig_chld.sa_handler = SIG_DFL;
	sigemptyset(&sig_chld.sa_mask);
	sig_chld.sa_flags = SA_NOCLDWAIT;
	sigaction(SIGCHLD, &sig_chld, NULL);

	/* netflow threads */
	thread_idx = 0;
	for (i=0; i<data.nnfcap; i++) {
		struct capture *cap = &data.nfcap[i];

		if (cap->type == XENOEYE_CAPTURE_TYPE_PCAP) {
			if (!pcapture_start(&data, cap, thread_idx,
				FLOW_TYPE_NETFLOW)) {

				return EXIT_FAILURE;
			}
		} else if (cap->type == XENOEYE_CAPTURE_TYPE_SOCKET) {
			if (!scapture_start(&data, cap, thread_idx,
				FLOW_TYPE_NETFLOW)) {

				return EXIT_FAILURE;
			}
		}

		thread_idx++;
	}

	/* sflow threads */
	for (i=0; i<data.nsfcap; i++) {
		struct capture *cap = &data.sfcap[i];

		if (cap->type == XENOEYE_CAPTURE_TYPE_PCAP) {
			if (!pcapture_start(&data, cap, thread_idx,
				FLOW_TYPE_SFLOW)) {

				return EXIT_FAILURE;
			}
		} else if (cap->type == XENOEYE_CAPTURE_TYPE_SOCKET) {
			if (!scapture_start(&data, cap, thread_idx,
				FLOW_TYPE_SFLOW)) {

				return EXIT_FAILURE;
			}
		}

		thread_idx++;
	}

	/* FIXME: correct shutdown */
	for (i=0; i<data.nnfcap; i++) {
		pthread_join(data.nfcap[i].tid, NULL);
	}
	for (i=0; i<data.nsfcap; i++) {
		pthread_join(data.sfcap[i].tid, NULL);
	}

	netflow_templates_shutdown();

	return EXIT_SUCCESS;
}

