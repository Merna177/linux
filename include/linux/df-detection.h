/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LINUX_DOUBLE_FETCH_DETECTION_H__
#define __LINUX_DOUBLE_FETCH_DETECTION_H__

#include <linux/types.h>
#include <linux/stackdepot.h>

#ifdef CONFIG_DF_DETECTION

#define DF_INIT_SIZE 16
#define DF_MAX_RECORDS 1024
#define MAX_LEN 1 << 20
#define STACK_DEPTH 64
#define DFETCH_ENABLE           _IO('c', 254)
#define DFETCH_DISABLE          _IO('c', 255)
#define BYTE_MAX 256

/*For each address range used by copy functions*/
struct df_address_range{
        const void *start_address;
        unsigned long len;
        unsigned long caller;
        depot_stack_handle_t stack;
};

struct df_pair{
        int first;
        int second;
};

void add_address(const void *addr, size_t len, unsigned long caller, void * kernel_addr);
void start_system_call(void);
void end_system_call(void);
depot_stack_handle_t df_save_stack(gfp_t flags);
void report(void);
void detect_intersection(void * kernel_addr);
int is_intersect(struct df_address_range a, struct df_address_range b, void * kernel_addr);

#endif  /*CONFIG_DF_DETECTION*/

#endif /*__LINUX_DOUBLE_FETCH_DETECTION_H__*/
