#ifndef __LINUX_DOUBLE_FETCH_DETECTION_H__
#define __LINUX_DOUBLE_FETCH_DETECTION_H__
#ifdef CONFIG_DF_DETECTION
#include <linux/types.h>
#define DF_INIT_SIZE 16
#define DF_MAX_RECORDS 1024

struct df_address_range{
        const void *start_address;
        unsigned long len;
        unsigned long caller;
};
struct df_pair{
        struct df_address_range *first;
        struct df_address_range *second;
        //it will be 1 if first happens before second and 2 if second happens before first
        int sequence;
};
void add_address(const void* addr,size_t len,unsigned long caller);
void start_system_call(long syscall);
void end_system_call(void);
void report(void);
int reallocate_extra_memory(int sz, int max_size);
void detect_intersection(void);
int is_intersect(struct df_address_range a, struct df_address_range b);
#endif
#endif
