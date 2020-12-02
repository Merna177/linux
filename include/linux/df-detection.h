/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LINUX_DOUBLE_FETCH_DETECTION_H__
#define __LINUX_DOUBLE_FETCH_DETECTION_H__

#include <linux/types.h>
#include <linux/stackdepot.h>

#ifdef CONFIG_DFETCH_DETECTION

#define DFETCH_INIT_SIZE 16
#define DFETCH_MAX_RECORDS 1024
#define MAX_LEN 1 << 20
#define STACK_DEPTH 64
#define DFETCH_ENABLE           _IO('c', 254)
#define DFETCH_DISABLE          _IO('c', 255)
#define BYTE_MAX 256

/* For each address range used by copy functions. */
struct dfetch_address_range {
        const void *start_address;
        unsigned long len;
        unsigned long caller;
        depot_stack_handle_t stack;
};

struct dfetch_pair {
        int first;
        int second;
};

struct double_fetch {
        struct dfetch_address_range *dfetch_addresses;
	int num_read;
	int ranges_size;
	struct dfetch_pair *dfetch_pairs;
	int dfetch_index;
	int dfetch_size;
	bool dfetch_enable;
};

void dfetch_add_address(const void *addr, size_t len, unsigned long caller, void * kernel_addr);
void dfetch_start_system_call(void);
void dfetch_end_system_call(void);

#else /* CONFIG_DFETCH_DETECTION */

void dfetch_start_system_call(void){}
void dfetch_end_system_call(void){}
void dfetch_add_address(const void *addr, size_t len, unsigned long caller, void * kernel_addr){}

#endif  /* CONFIG_DFETCH_DETECTION */

#endif /* __LINUX_DOUBLE_FETCH_DETECTION_H__ */
