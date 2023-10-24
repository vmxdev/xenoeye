#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <byteswap.h>
#include <sys/mman.h>

#include "xenoeye.h"
#include "geoip.h"
#include "ip-btrie.h"

/* geo */
static struct btrie_node_geo * _Atomic _geodb4 = NULL;
static size_t _geo4size = 0;
static struct btrie_node_geo * _Atomic _geodb6 = NULL;
static size_t _geo6size = 0;

/* as */
static struct btrie_node_as * _Atomic _asdb4 = NULL;
static size_t _as4size = 0;
static struct btrie_node_as * _Atomic _asdb6 = NULL;
static size_t _as6size = 0;


/* geo */
int
geoip_lookup4(uint32_t addr, struct geoip_info **g)
{
	uint8_t *addr_ptr = (uint8_t *)&addr;
	struct btrie_node_geo *geo4 = atomic_load_explicit(&_geodb4,
		memory_order_relaxed);

	IP_BTRIE_LOOKUP(geo4, 4 * 8);

	*g = &geo4[node].g;

	return 1;
}

int
geoip_lookup6(xe_ip *addr, struct geoip_info **g)
{
	uint8_t *addr_ptr = (uint8_t *)addr;
	struct btrie_node_geo *geo6 = atomic_load_explicit(&_geodb6,
		memory_order_relaxed);

	IP_BTRIE_LOOKUP(geo6, 16 * 8);

	*g = &geo6[node].g;

	return 1;
}

/* as */
int
as_lookup4(uint32_t addr, struct as_info **a)
{
	uint8_t *addr_ptr = (uint8_t *)&addr;
	struct btrie_node_as *as4 = atomic_load_explicit(&_asdb4,
		memory_order_relaxed);

	IP_BTRIE_LOOKUP(as4, 4 * 8);

	*a = &as4[node].a;

	return 1;
}

int
as_lookup6(xe_ip *addr, struct as_info **a)
{
	uint8_t *addr_ptr = (uint8_t *)addr;
	struct btrie_node_as *as6 = atomic_load_explicit(&_asdb6,
		memory_order_relaxed);

	IP_BTRIE_LOOKUP(as6, 16 * 8);

	*a = &as6[node].a;

	return 1;
}


static void *
mmap_db(struct xe_data *data, const char *dbname, size_t *size)
{
	void *addr = NULL;
	struct stat st;
	int fd;

	char path[PATH_MAX + 8];

	*size = 0;
	sprintf(path, "%s/%s.db", data->geodb_dir, dbname);

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		LOG("Can't open file '%s': %s", path, strerror(errno));
		return NULL;
	}

	if (fstat(fd, &st) != 0) {
		LOG("fstat() failed on file '%s': %s", path, strerror(errno));
		goto fail_fstat;
	}

	*size = st.st_size;
	addr = mmap(NULL, *size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == (void *) -1) {
		LOG("mmap() failed on file '%s': %s", path, strerror(errno));
		addr = NULL;
		goto fail_mmap;
	}

fail_fstat:
fail_mmap:
	close(fd);

	return addr;
}

static void
geoip_reload(struct xe_data *data)
{
	struct btrie_node_geo *geo4, *geo6;
	struct btrie_node_geo *geo4old, *geo6old;
	struct btrie_node_as *as4, *as6;
	struct btrie_node_as *as4old, *as6old;
	size_t geo4size, geo6size;
	size_t as4size, as6size;

	/* save old pointers */
	geo4old = atomic_load_explicit(&_geodb4, memory_order_relaxed);
	geo6old = atomic_load_explicit(&_geodb6, memory_order_relaxed);
	as4old = atomic_load_explicit(&_asdb4, memory_order_relaxed);
	as6old = atomic_load_explicit(&_asdb6, memory_order_relaxed);

	/* create new mappings */
	geo4 = mmap_db(data, "geo4", &geo4size);
	geo6 = mmap_db(data, "geo6", &geo6size);
	as4 = mmap_db(data, "as4", &as4size);
	as6 = mmap_db(data, "as6", &as6size);

	/* replace atomically */
	atomic_store_explicit(&_geodb4, geo4, memory_order_relaxed);
	atomic_store_explicit(&_geodb6, geo6, memory_order_relaxed);
	atomic_store_explicit(&_asdb4, as4, memory_order_relaxed);
	atomic_store_explicit(&_asdb6, as6, memory_order_relaxed);

	/* wait for stalled requests */
	usleep(100);

	/* remove old mappings */
#define UNMAP(X, S)                                                            \
do {                                                                           \
	if (X) {                                                               \
		if (munmap(X, S) != 0) {                                       \
			LOG("munmap() failed: %s", strerror(errno));           \
		}                                                              \
	}                                                                      \
} while (0)

	UNMAP(geo4old, _geo4size);
	UNMAP(geo6old, _geo6size);
	UNMAP(as4old, _as4size);
	UNMAP(as6old, _as6size);
#undef UNMAP

	/* update db sizes */
	_geo4size = geo4size;
	_geo6size = geo6size;
	_as4size = as4size;
	_as6size = as6size;
}

void *
geoip_thread(void *arg)
{
	struct xe_data *data = (struct xe_data *)arg;

	LOG("geoip: starting helper thread");
	for (;;) {
		if (atomic_load_explicit(&data->stop, memory_order_relaxed)) {
			/* stop */
			break;
		}

		if (atomic_load_explicit(&data->reload_geoip,
			memory_order_relaxed)) {

			atomic_store_explicit(&data->reload_geoip, 0,
				memory_order_relaxed);
			LOG("Reloading geo/as databases");
			geoip_reload(data);
			LOG("geo/as databases reloaded");
		}

		usleep(10000);
	}

	return NULL;
}

