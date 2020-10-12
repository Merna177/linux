#ifndef __LINUX_DOUBLE_FETCH_DETECTION_H__
#define __LINUX_DOUBLE_FETCH_DETECTION_H__
#ifdef CONFIG_DF_DETECTION
#include <linux/types.h>
#include <linux/stackdepot.h>
#define DF_INIT_SIZE 16
#define DF_MAX_RECORDS 1024
#define MAX_LEN 1 << 20
#define STACK_DEPTH 64
#define DF_ENABLE			_IO('c', 254)
#define DF_DISABLE			_IO('c', 255)
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
void add_address(const void* addr,size_t len,unsigned long caller);
void start_system_call(long syscall);
void end_system_call(void);
depot_stack_handle_t df_save_stack(gfp_t flags);
void report(void);
int filter_stack(const unsigned long stack_entries[], int num_entries);
bool check_valid_detection(void);
void detect_intersection(void);
int is_intersect(struct df_address_range a, struct df_address_range b);
#endif
#endif
