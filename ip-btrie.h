#ifndef ip_btrie_h_included
#define ip_btrie_h_included

#define IP_BTRIE_ADD(DB, SIZE, NODE)                                        \
	int i;                                                              \
	uint32_t node, next;                                                \
                                                                            \
	if (!DB) {                                                          \
		/* empty database */                                        \
		DB = calloc(1, sizeof(struct NODE));                        \
		if (!DB) {                                                  \
			LOG("Not enough memory");                           \
			return 0;                                           \
		}                                                           \
		SIZE = 1;                                                   \
	}                                                                   \
                                                                            \
	node = 0;                                                           \
                                                                            \
	for (i=0; i<mask; i++) {                                            \
		struct NODE *tmp;                                           \
		int bit, bit_n;                                             \
		uint8_t byte;                                               \
                                                                            \
		byte = addr_ptr[i / 8];                                     \
		bit_n = 7 - (i % 8);                                        \
		bit = !!(byte & (1 << bit_n));                              \
                                                                            \
		next = DB[node].next[bit];                                  \
		if (next) {                                                 \
			node = next;                                        \
			continue;                                           \
		}                                                           \
                                                                            \
		tmp = realloc(DB, (SIZE + 1) * sizeof(struct NODE));        \
                                                                            \
		if (!tmp) {                                                 \
			LOG("Not enough memory");                           \
			free(DB);                                           \
			DB = NULL;                                          \
			SIZE = 0;                                           \
			return 0;                                           \
		}                                                           \
                                                                            \
		DB = tmp;                                                   \
		memset(&DB[SIZE], 0, sizeof(struct NODE));                  \
		DB[node].next[bit] = SIZE;                                  \
		node = SIZE;                                                \
		(SIZE)++;                                                   \
	}                                                                   \
	DB[node].is_leaf = 1;



#define IP_BTRIE_ADD_MMAP(DB, SIZE, NODE)                                   \
	int i;                                                              \
	uint32_t node, next;                                                \
                                                                            \
	if (SIZE == 0) {                                                    \
		/* empty database */                                        \
		memset(DB, 0, sizeof(struct NODE));                         \
		SIZE = 1;                                                   \
	}                                                                   \
                                                                            \
	node = 0;                                                           \
                                                                            \
	for (i=0; i<mask; i++) {                                            \
		int bit, bit_n;                                             \
		uint8_t byte;                                               \
                                                                            \
		byte = addr_ptr[i / 8];                                     \
		bit_n = 7 - (i % 8);                                        \
		bit = !!(byte & (1 << bit_n));                              \
                                                                            \
		next = DB[node].next[bit];                                  \
		if (next) {                                                 \
			node = next;                                        \
			continue;                                           \
		}                                                           \
                                                                            \
		memset(&DB[SIZE], 0, sizeof(struct NODE));                  \
		DB[node].next[bit] = SIZE;                                  \
		node = SIZE;                                                \
		(SIZE)++;                                                   \
	}                                                                   \
	DB[node].is_leaf = 1;



#define IP_BTRIE_LOOKUP(DB, SIZE)                                           \
	int i;                                                              \
	uint32_t node = 0, next = 0;                                        \
                                                                            \
	if (!DB) {                                                          \
		return 0;                                                   \
	}                                                                   \
                                                                            \
	for (i=0; i<SIZE; i++) {                                            \
		int bit, bit_n;                                             \
		uint8_t byte;                                               \
                                                                            \
		byte = addr_ptr[i / 8];                                     \
		bit_n = 7 - (i % 8);                                        \
		bit = !!(byte & (1 << bit_n));                              \
                                                                            \
		next = DB[node].next[bit];                                  \
		if (!next) {                                                \
			break;                                              \
		}                                                           \
		node = next;                                                \
	}                                                                   \
                                                                            \
	if (!DB[node].is_leaf) {                                            \
		return 0;                                                   \
	}


#endif

