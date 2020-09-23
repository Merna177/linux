#ifndef __LINUX_DOUBLE_FETCH_DETECTION_H__
#define __LINUX_DOUBLE_FETCH_DETECTION_H__
#ifdef CONFIG_DF_DETECTION
#define allocation_size 16
struct df_address_range{
    const void *start_address;
    unsigned long len;
};


void add_address(const void* addr,unsigned long len);
void start_system_call(void);
void end_system_call(void);
void print(void);
int reallocate_extra_memory(void);

#endif
#endif