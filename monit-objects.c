/*
 * xenoeye
 *
 * Copyright (c) 2020-2025, Vladimir Misyurov, Michael Kogan
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
#include <unistd.h>
#include <arpa/inet.h>

#include "utils.h"
#include "xenoeye.h"
#include "filter.h"
#include "flow-debug.h"
#include "netflow.h"

#include "tkvdb.h"

#include "monit-objects.h"
#include "monit-objects-common.h"
#include "flow-info.h"
#include "geoip.h"

#define STR_MAX_LEN 512

#define STRCMP(A, I, S) strcmp(A->path_stack[I].data.path_item, S)

static void monit_object_mavg_limits_free(struct monit_object *mo);

static int
monit_object_json_callback(struct aajson *a, aajson_val *value, void *user)
{
	struct monit_object *mo;
	char *key = a->path_stack[a->path_stack_pos].data.path_item;

	mo = (struct monit_object *)user;

	if (a->path_stack_pos == 1) {
		if (strcmp(key, "filter") == 0) {
			struct filter_input input;

			if (mo->is_reloading) {
				return 1;
			}

			memset(&input, 0, sizeof(input));
			input.s = value->str;
			mo->expr = parse_filter(&input);
			if (input.error) {
				LOG("Can't parse filter. Parse error: %s",
					input.errmsg);
				return 0;
			}
		}
	}

	if (STRCMP(a, 1, "debug") == 0) {
		if (mo->is_reloading) {
			return 1;
		}

		return flow_debug_config(a, value, &mo->debug);
	}

	if (STRCMP(a, 1, "fwm") == 0) {
		if (mo->is_reloading) {
			return 1;
		}

		/* fixed window in memory */
		return fwm_config(a, value, mo);
	}

	if (STRCMP(a, 1, "mavg") == 0) {
		/* moving averages */
		return mavg_config(a, value, mo);
	}

	if (STRCMP(a, 1, "classification") == 0) {
		if (mo->is_reloading) {
			return 1;
		}

		return classification_config(a, value, mo);
	}

	return 1;
}

#undef STRCMP

static int
monit_object_info_parse(struct monit_object *mo, const char *moname,
	const char *fn)
{
	FILE *f;
	struct stat st;
	size_t i, s;
	char *json;
	int ret = 0;

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

	/* get last modification time */
	mo->modif_time = st.st_mtim;

	/* parse */
	aajson_init(&a, json);
	aajson_parse(&a, &monit_object_json_callback, mo);
	if (a.error) {
		LOG("Can't parse config file '%s' (line: %lu, col: %lu): %s",
			fn, a.line, a.col, a.errmsg);
		goto fail_parse;
	}

	/* copy path to file */
	strcpy(mo->mo_path, fn);

	/* copy name of monitoring object */
	strcpy(mo->name, moname);
	for (i=0; i<strlen(mo->name); i++) {
		if (mo->name[i] == '/') {
			mo->name[i] = '_';
		}
	}

	ret = 1;

fail_parse:
fail_fread:
	free(json);
fail_malloc:
fail_fstat:
	fclose(f);
fail_open:

	return ret;
}

static int
monit_object_add(struct monit_object **mos, size_t *n_mo,
	const char *moname, const char *fn)
{
	struct monit_object mo, *motmp;

	memset(&mo, 0, sizeof(struct monit_object));

	if (!monit_object_info_parse(&mo, moname, fn)) {
		return 0;
	}

	/* append to list of monitoring objects */
	motmp = realloc(*mos, (*n_mo + 1) * sizeof(struct monit_object));
	if (!motmp) {
		LOG("realloc() failed");
		return 0;
	}

	/*filter_dump(mo.expr, stdout);*/

	*mos = motmp;
	(*mos)[*n_mo] = mo;
	(*n_mo)++;

	return 1;
}


static inline int
cmp_modtime(const struct timespec *ts1, const struct timespec *ts2)
{
	uint64_t tm1 = ts1->tv_sec * 1e9 + ts1->tv_nsec;
	uint64_t tm2 = ts2->tv_sec * 1e9 + ts2->tv_nsec;

	return (tm1 == tm2);
}

static struct monit_object *
monit_object_need_reload(struct monit_object *mos, size_t n_mo, const char *fn)
{
	size_t i;

	for (i=0; i<n_mo; i++) {
		struct monit_object *mo = &mos[i];

		if (strcmp(mo->mo_path, fn) == 0) {
			/* found */
			struct stat st;

			if (stat(fn, &st) < 0) {
				LOG("Can't stat() file '%s': %s",
					fn, strerror(errno));
				continue;
			}

			if (!cmp_modtime(&st.st_mtim, &mo->modif_time)) {
				LOG("File %s was modified, reloading", fn);
				return mo;
			}
		}

		if (mo->n_mo) {
			return monit_object_need_reload(mo->mos, mo->n_mo, fn);
		}
	}

	return NULL;
}

static void
monit_objects_load_rec(struct xe_data *globl,
	const char *dirsuffix, struct monit_object **mos, size_t *n_mo,
	int is_reload)
{
	DIR *d;
	struct dirent *dir;
	char dirname[PATH_MAX + 512];

	sprintf(dirname, "%s/%s/", globl->mo_dir, dirsuffix);
	if (strlen(dirname) >= PATH_MAX) {
		LOG("Directory name too big: %s/%s", globl->mo_dir, dirsuffix);
		return;
	}

	d = opendir(dirname);
	if (!d) {
		LOG("Can't open directory with monitoring objects '%s': %s",
			dirname, strerror(errno));
		return;
	}

	while ((dir = readdir(d)) != NULL) {
		size_t i;
		struct monit_object *mo;
		char mofile[PATH_MAX * 2];
		char inner_dir[PATH_MAX];
		char moname[PATH_MAX];

		struct timespec tmsp;
		uint64_t time_ns;

		if (clock_gettime(CLOCK_REALTIME_COARSE, &tmsp) < 0) {
			LOG("clock_gettime() failed: %s", strerror(errno));
			continue;
		}
		time_ns = tmsp.tv_sec * 1e9 + tmsp.tv_nsec;

		if (dir->d_name[0] == '.') {
			/* skip hidden files */
			continue;
		}

		if (dir->d_type != DT_DIR) {
			continue;
		}

		sprintf(mofile, "%s/%s/mo.conf", dirname, dir->d_name);
		if (strlen(mofile) >= PATH_MAX) {
			LOG("Filename too big: %s/%s", dirname, dir->d_name);
			continue;
		}

		if (strlen(dirsuffix) == 0) {
			sprintf(moname, "%s", dir->d_name);
		} else {
			sprintf(moname, "%s/%s", dirsuffix, dir->d_name);
		}

		if (is_reload) {
			mo = monit_object_need_reload(globl->monit_objects,
				globl->nmonit_objects, mofile);
			if (!mo) {
				continue;
			}

			mo->is_reloading = 1;
			LOG("Reloading monitoring object '%s'", moname);
			monit_object_mavg_limits_free(mo);
			if (!monit_object_info_parse(mo, moname, mofile)) {
				continue;
			}
			mavg_limits_update(globl, mo);
		} else {
			LOG("Adding monitoring object '%s'", moname);
			if (!monit_object_add(mos, n_mo, moname, mofile)) {
				LOG("Monitoring object '%s' not added", moname);
				continue;
			}
			mo = &((*mos)[*n_mo - 1]);
		}

		for (i=0; i<mo->nfwm; i++) {
			size_t j;
			struct mo_fwm *fwm = &mo->fwms[i];

			if (!is_reload) {
				if (!fwm_fields_init(globl->nthreads, fwm)) {
					return;
				}
			}
			if (fwm->time == 0) {
				LOG("warning: timeout for '%s:%s' is not set"
					", using default %d",
					mo->name, fwm->name,
					FWM_DEFAULT_TIMEOUT);
				fwm->time = FWM_DEFAULT_TIMEOUT;
			}

			/* check whether we have fields that force packet
			 * payload parsing */
			for (j=0; j<fwm->fieldset.n_naggr; j++) {
				if (fwm->fieldset.naggr[j].id == DNS_NAME) {
					mo->payload_parse_dns = 1;
					fwm->has_dns_field = 1;
					break;
				}
				if (fwm->fieldset.naggr[j].id == DNS_IPS) {
					mo->payload_parse_dns = 1;
					fwm->has_dns_field = 1;
					break;
				}
				if (fwm->fieldset.naggr[j].id == SNI) {
					mo->payload_parse_sni = 1;
					fwm->has_sni_field = 1;
					break;
				}
			}
		}

		/* moving averages */
		for (i=0; i<mo->nmavg; i++) {
			struct mo_mavg *mavg = &mo->mavgs[i];
			char tmp_pfx[PATH_MAX * 3];

			mavg->start_ns = time_ns;

			if (!is_reload) {
				/* make prefix for notification files */
				sprintf(tmp_pfx, "%s/%s-%s",
					globl->notif_dir, mo->name, mavg->name);

				if (strlen(tmp_pfx) >= PATH_MAX) {
					LOG("Filename too big: %s/%s", mo->dir,
						mavg->name);
					return;
				}

				strcpy(mavg->notif_pfx, tmp_pfx);

				if (!mavg_fields_init(globl->nthreads, mavg)) {
					return;
				}
			}
			if (!mavg_limits_init(mavg, is_reload)) {
				return;
			}
			if (!is_reload && (mavg->size_secs == 0)) {
				LOG("warning: time for '%s:%s' is not set"
					", using default %d",
					mo->name, mavg->name,
					MAVG_DEFAULT_SIZE);
				mavg->size_secs = MAVG_DEFAULT_SIZE;
			}
		}

		/* classification */
		for (i=0; i<mo->nclassifications; i++) {
			if (!is_reload) {
				if (!classification_fields_init(globl->nthreads,
					&mo->classifications[i])) {

					return;
				}
			}

			if (mo->classifications[i].time == 0) {

				LOG("warning: time for '%s' class%d is "
					"not set, using default %d",
					mo->name,
					mo->classifications[i].id,
					CLSF_DEFAULT_TIMEOUT);
				mo->classifications[i].time
					= CLSF_DEFAULT_TIMEOUT;
			}
		}

		/* store path to monitoring object directory */
		sprintf(mofile, "%s/%s/", dirname, dir->d_name);
		strcpy(mo->dir, mofile);

		if (!is_reload) {
			LOG("Monitoring object '%s' added", moname);
		} else {

			for (i=0; i<mo->nmavg; i++) {
				struct mo_mavg *mavg = &mo->mavgs[i];

				atomic_fetch_add_explicit(&mavg->lim_curr_idx,
					1, memory_order_relaxed);
			}
			LOG("Monitoring object '%s' reloaded", moname);
		}

		/* try to walk deeper */
		if (strlen(dirsuffix) == 0) {
			sprintf(inner_dir, "%s", dir->d_name);
		} else {
			sprintf(inner_dir, "%s/%s", dirsuffix, dir->d_name);
		}
		monit_objects_load_rec(globl, inner_dir, &mo->mos, &mo->n_mo,
			is_reload);
	}

	closedir(d);
}

int
monit_objects_reload(struct xe_data *globl)
{
	monit_objects_load_rec(globl, "",
		&globl->monit_objects,
		&globl->nmonit_objects, 1);

	return 1;
}

int
monit_objects_init(struct xe_data *globl)
{
	int ret = 0;
	int thread_err;

	free(globl->monit_objects);
	globl->monit_objects = NULL;
	globl->nmonit_objects = 0;

	monit_objects_load_rec(globl, "",
		&globl->monit_objects,
		&globl->nmonit_objects, 0);


	/* all monitoring objects are parsed, so we can link extended stats */
	monit_objects_mavg_link_ext_stat(globl);

	/* create thread for background processing fixed windows in memory */
	thread_err = pthread_create(&globl->fwm_tid, NULL,
		&fwm_bg_thread, globl);

	if (thread_err) {
		LOG("Can't start thread: %s", strerror(thread_err));
		goto fail_fwmthread;
	}

	/* moving averages */
	/* thread with actions on overflow */
	thread_err = pthread_create(&globl->mavg_act_tid, NULL,
		&mavg_act_thread, globl);

	if (thread_err) {
		LOG("Can't start thread: %s", strerror(thread_err));
		goto fail_mavgthread;
	}

	/* underflow check thread */
	thread_err = pthread_create(&globl->mavg_under_tid, NULL,
		&mavg_check_underlimit_thread, globl);

	if (thread_err) {
		LOG("Can't start thread: %s", strerror(thread_err));
		goto fail_mavgthread;
	}

	/* dump thread */
	thread_err = pthread_create(&globl->mavg_dump_tid, NULL,
		&mavg_dump_thread, globl);

	if (thread_err) {
		LOG("Can't start thread: %s", strerror(thread_err));
		goto fail_mavgthread;
	}

	/* classifier thread */
	thread_err = pthread_create(&globl->clsf_tid, NULL,
		&classification_bg_thread, globl);

	if (thread_err) {
		LOG("Can't start thread: %s", strerror(thread_err));
		goto fail_clsfthread;
	}

	ret = 1;

fail_clsfthread:
fail_mavgthread:
fail_fwmthread:
	/* FIXME: free monitoring objects */
	return ret;
}


void
monit_object_field_print_str(struct field *fld, char *str, uint8_t *data,
	int print_spaces)
{
	uint16_t d16;
	uint32_t d32;
	uint64_t d64;
	char s[INET6_ADDRSTRLEN + 1];

	char esc[STR_MAX_LEN];
	char *escptr;
	size_t i;

	switch (fld->type) {
		case FILTER_BASIC_ADDR4:
			inet_ntop(AF_INET, data, s, INET_ADDRSTRLEN);
			if (print_spaces) {
				sprintf(str, " '%s' ", s);
			} else {
				sprintf(str, "%s", s);
			}
			break;

		case FILTER_BASIC_ADDR6:
			inet_ntop(AF_INET6, data, s, INET6_ADDRSTRLEN);
			if (print_spaces) {
				sprintf(str, " '%s' ", s);
			} else {
				sprintf(str, "%s", s);
			}
			break;

		case FILTER_BASIC_RANGE:
			switch (fld->size) {
				case sizeof(uint8_t):
					if (print_spaces) {
						sprintf(str, " %u ", data[0]);
					} else {
						sprintf(str, "%u", data[0]);
					}
					break;
				case sizeof(uint16_t):
					d16 = *((uint16_t *)data);
					if (print_spaces) {
						sprintf(str, " %u ",
							ntohs(d16));
					} else {
						sprintf(str, "%u", ntohs(d16));
					}
					break;
				case sizeof(uint32_t):
					d32 = *((uint32_t *)data);
					if (print_spaces) {
						sprintf(str, " %u ",
							ntohl(d32));
					} else {
						sprintf(str, "%u", ntohl(d32));
					}
					break;
				case sizeof(uint64_t):
					d64 = *((uint64_t *)data);
					if (print_spaces) {
						sprintf(str, " %lu ",
							be64toh(d64));
					} else {
						sprintf(str, "%lu",
							be64toh(d64));
					}
					break;
				default:
					break;
			}
			break;

		case FILTER_BASIC_STRING:
			escptr = esc;
			for (i=0; data[i] != 0; i++) {
				if (data[i] == '\'') {
					*escptr = '\'';
					*(escptr + 1) = '\'';
					escptr++;
				} else {
					*escptr = data[i];
				}
				escptr++;
			}
			*escptr = '\0';

			if (print_spaces) {
				sprintf(str, " '%s' ", esc);
			} else {
				sprintf(str, "%s", esc);
			}
			break;

		default:
			break;
	}
}


void
monit_object_field_print(struct field *fld, FILE *f, uint8_t *data,
	int print_spaces)
{
	char str[STR_MAX_LEN];

	monit_object_field_print_str(fld, str, data, print_spaces);
	fputs(str, f);
}


static void
monit_object_func_div(struct field *fld, struct flow_info *flow,
	uint8_t *key)
{
	uint64_t quotient, dividend, divisor;
	struct function_div *div = &fld->func_data.div;

	dividend = get_nf_val((uintptr_t)flow + div->dividend_off,
		div->dividend_size);
	divisor = get_nf_val((uintptr_t)flow + div->divisor_off,
		div->divisor_size);

	if (divisor) {
		int q = xdiv(dividend, divisor, div->is_log, div->k);
		quotient = htobe64(q);
	} else {
		/* division by zero */
		/* FIXME: warn user? log or write some value for notification? */
		quotient = htobe64(0);
	}

	memcpy(key, &quotient, sizeof(quotient));
}

static void
monit_object_func_min(struct field *fld, struct flow_info *flow,
	uint8_t *key)
{
	uint64_t arg1, arg2, res;

	arg1 = get_nf_val((uintptr_t)flow + fld->func_data.min.arg1_off,
		fld->func_data.min.arg1_size);
	arg2 = get_nf_val((uintptr_t)flow + fld->func_data.min.arg2_off,
		fld->func_data.min.arg2_size);

	res = htobe64((arg1 < arg2) ? arg1 : arg2);

	memcpy(key, &res, sizeof(res));
}

static void
monit_object_func_mfreq(struct field *fld, struct flow_info *flow,
	uint8_t *key)
{
	uint16_t arg1, arg2;
	uint64_t freq1, freq2;
	uint64_t res;

	arg1 = get_nf_val((uintptr_t)flow + fld->func_data.mfreq.arg1_off,
		fld->func_data.mfreq.arg1_size);
	arg2 = get_nf_val((uintptr_t)flow + fld->func_data.mfreq.arg2_off,
		fld->func_data.mfreq.arg2_size);

	freq1 = fld->func_data.mfreq.freqmap[arg1];
	freq2 = fld->func_data.mfreq.freqmap[arg2];

	if (freq1 != freq2) {
		res = htobe64((freq1 > freq2) ? arg1 : arg2);
	} else {
		res = htobe64((arg1 < arg2) ? arg1 : arg2);
	}

	/* update freqmap */
	atomic_fetch_add_explicit(&fld->func_data.mfreq.freqmap[arg1], 1,
		memory_order_relaxed);
	atomic_fetch_add_explicit(&fld->func_data.mfreq.freqmap[arg2], 1,
		memory_order_relaxed);

	memcpy(key, &res, sizeof(res));
}

static void
monit_object_func_geoip(struct field *fld, struct flow_info *flow,
	uint8_t *key)
{
	struct function_geoip *geoip = &fld->func_data.geoip;
	struct geoip_info *g;
	int size;

	size = geoip_get_field_size(geoip->field);

	memset(key, 0, size);

	if (geoip->ip_size == sizeof(uint32_t)) {
		uint32_t addr = *((uint32_t *)
			((uintptr_t)flow + geoip->ip_off));

		if (!geoip_lookup4(addr, &g)) {
			key[0] = '?';
			return;
		}
		memcpy(key, geoip_get_field(g, geoip->field), size - 1);
	} else if (geoip->ip_size == sizeof(xe_ip)) {
		xe_ip *addr = (xe_ip *)((uintptr_t)flow + geoip->ip_off);

		if (!geoip_lookup6(addr, &g)) {
			key[0] = '?';
			return;
		}
		memcpy(key, geoip_get_field(g, geoip->field), size - 1);
	}
}

static void
monit_object_func_as(struct field *fld, struct flow_info *flow,
	uint8_t *key)
{
	struct function_as *as = &fld->func_data.as;
	struct as_info *a;
	int size;
	int not_found = 0;

	if (as->num) {
		size = sizeof(((struct as_info *)0)->asn);
	} else {
		size = sizeof(((struct as_info *)0)->asd);
	}

	memset(key, 0, size);

	if (as->ip_size == sizeof(uint32_t)) {
		uint32_t addr = *((uint32_t *)
			((uintptr_t)flow + as->ip_off));

		if (!as_lookup4(addr, &a)) {
			not_found = 1;
		}
	} else if (as->ip_size == sizeof(xe_ip)) {
		xe_ip *addr = (xe_ip *)((uintptr_t)flow + as->ip_off);

		if (!as_lookup6(addr, &a)) {
			not_found = 1;
		}
	}

	if (as->num) {
		if (!not_found) {
			memcpy(key, &a->asn, size);
		}
	} else {
		if (not_found) {
			key[0] = '?';
		} else {
			memcpy(key, &a->asd, size);
		}
	}
}

static void
monit_object_func_tfstr(struct field *fld, struct flow_info *flow,
	uint8_t *key)
{
	char *s;
	uint8_t flags;

	memset(key, 0, TCP_FLAGS_STR_MAX_SIZE);

	flags = get_nf_val((uintptr_t)flow + fld->func_data.tfstr.tf_off, 1);
	s = tcp_flags_to_str(flags);

	strcpy((char *)key, s);
}

static void
monit_object_func_portstr(struct field *fld, struct flow_info *flow,
	uint8_t *key)
{
	uint16_t port;

	memset(key, 0, TCP_UDP_PORT_STR_MAX_SIZE);
	port = get_nf_val((uintptr_t)flow + fld->func_data.portstr.port_off,
		fld->func_data.portstr.port_size);

	port_to_str((char *)key, port);
}

static void
monit_object_func_ppstr(struct field *fld, struct flow_info *flow,
	uint8_t *key)
{
	uint16_t port1, port2;

	memset(key, 0, TCP_UDP_PP_STR_MAX_SIZE);

	port1 = get_nf_val((uintptr_t)flow + fld->func_data.ppstr.arg1_off,
		fld->func_data.ppstr.arg1_size);
	port2 = get_nf_val((uintptr_t)flow + fld->func_data.ppstr.arg2_off,
		fld->func_data.ppstr.arg2_size);

	ports_pair_to_str((char *)key, port1, port2);
}

void
monit_object_key_add_fld(struct field *fld, uint8_t *key,
	struct flow_info *flow)
{
	if (fld->is_func) {
		switch (fld->id) {
			case DIV:
			case DIV_L:
			case DIV_R:
				monit_object_func_div(fld, flow, key);
				break;
			case MIN:
				monit_object_func_min(fld, flow, key);
				break;
			case MFREQ:
				monit_object_func_mfreq(fld, flow, key);
				break;
/* geoip */
#define DO(FIELD, SIZE) case FIELD:
FOR_LIST_OF_GEOIP_FIELDS
#undef DO
				monit_object_func_geoip(fld, flow, key);
				break;
			case ASN:
			case ASD:
				monit_object_func_as(fld, flow, key);
				break;
			case TFSTR:
				monit_object_func_tfstr(fld, flow, key);
				break;
			case PORTSTR:
				monit_object_func_portstr(fld, flow, key);
				break;
			case PPSTR:
				monit_object_func_ppstr(fld, flow, key);
				break;
			default:
				break;
		}
	} else {
		uintptr_t flow_fld = (uintptr_t)flow + fld->nf_offset;
		memcpy(key, (void *)flow_fld, fld->size);
	}
}

int
monit_object_process_nf(struct xe_data *globl, struct monit_object *mo,
	size_t thread_id, uint64_t time_ns, struct flow_info *flow)
{
	size_t i, j, f;

	classification_process_nf(mo, thread_id, flow);

	/* fixed windows */
	for (i=0; i<mo->nfwm; i++) {
		tkvdb_tr *tr;
		TKVDB_RES rc;
		tkvdb_datum dtkey, dtval;

		struct mo_fwm *fwm;
		struct fwm_thread_data *fdata;
		uint8_t *key;

		fwm = &mo->fwms[i];

		/* check state */
		if (fwm->is_extended) {
			int active;

			active = atomic_load_explicit(&fwm->is_active,
				memory_order_relaxed);
			if (!active) {
				continue;
			}
		}

		/* check the sFlow fields with DNS/SNI */
		if (fwm->has_dns_field
			&& !(flow->has_dns_name || flow->has_dns_ips)) {
			/* skip flow without DNS info for window that
			 * require it */
			continue;
		}

		if (fwm->has_sni_field && !flow->has_sni) {
			/* same for SNI */
			continue;
		}


		fdata = &fwm->thread_data[thread_id];
		key = fdata->key;

		/* fwm */
		/* make key */
		for (f=0; f<fwm->fieldset.n_naggr; f++) {
			struct field *fld = &fwm->fieldset.naggr[f];

			monit_object_key_add_fld(fld, key, flow);
			key += fld->size;
		}

		/* get current database bank */
		tr = atomic_load_explicit(&fdata->tr, memory_order_relaxed);

		dtkey.data = fdata->key;
		dtkey.size = fdata->keysize;

		/* search for key */
		rc = tr->get(tr, &dtkey, &dtval);
		if (rc == TKVDB_OK) {
			/* update existing values */
			uint64_t *vals = dtval.data;
			for (j=0; j<fwm->fieldset.n_aggr; j++) {
				struct field *fld = &fwm->fieldset.aggr[j];
				uint64_t val = monit_object_nf_val(flow, fld);

				vals[j] += val * fld->scale
					* flow->sampling_rate;
			}
		} else if ((rc == TKVDB_EMPTY) || (rc == TKVDB_NOT_FOUND)) {
			/* try to add new key-value pair */

			/* init new aggregable values */
			for (j=0; j<fwm->fieldset.n_aggr; j++) {
				struct field *fld = &fwm->fieldset.aggr[j];
				uint64_t val = monit_object_nf_val(flow, fld);

				fdata->val[j] = val * fld->scale
					* flow->sampling_rate;
			}

			dtval.data = fdata->val;
			dtval.size = fdata->valsize;

			rc = tr->put(tr, &dtkey, &dtval);
			if (rc == TKVDB_OK) {
			} else if (rc == TKVDB_ENOMEM) {
				/* not enough memory */
			} else {
				LOG("Can't append key, error code %d", rc);
			}
		} else {
			LOG("Can't find key, error code %d", rc);
		}
	}

	/* moving average */
	if (!monit_object_mavg_process_nf(globl, mo, thread_id, time_ns,
		flow)) {

		return 0;
	}

	return 1;
}

static void
monit_object_mavg_limits_free(struct monit_object *mo)
{
	size_t i;
	for (i=0; i<mo->nmavg; i++) {
		struct mo_mavg *mavg = &mo->mavgs[i];
		mavg_limits_free(mavg);
	}
}

