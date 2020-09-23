#ifndef __LINUX_DOUBLE_FETCH_DETECTION_H__
#define __LINUX_DOUBLE_FETCH_DETECTION_H__
#ifdef CONFIG_DF_DETECTION
#define DF_INIT_SIZE 16
#define DF_MAX_RECORDS 1024

struct df_address_range{
        const void *start_address;
        unsigned long len;
};


void add_address(const void* addr,unsigned long len);
void start_system_call(void);
void end_system_call(void);
int reallocate_extra_memory(void);

#endif
#endif
