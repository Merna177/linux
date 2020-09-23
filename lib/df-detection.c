#include "linux/df-detection.h"
#include <linux/context_tracking.h>
#include <linux/entry-common.h>
#include <linux/livepatch.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/kernel.h>

void add_address(const void* addr, unsigned long len)
{
        if (current->addresses == NULL || (current->num_read >= current->sz && reallocate_extra_memory() == -1))
                return;
        current->addresses[current->num_read].start_address = addr;
        current->addresses[current->num_read].len =len;
        current->num_read++;
}

void start_system_call()
{
        current->addresses = (struct df_address_range*)kmalloc_array(DF_INIT_SIZE,sizeof(struct df_address_range),GFP_KERNEL);
        current->sz = current->addresses ? DF_INIT_SIZE : 0;
        current->num_read = 0;
}
void end_system_call()
{    
        if (current->addresses != NULL){
                current->num_read = 0;
                current->sz = 0;
                kfree(current->addresses);
                current->addresses = NULL;
        }
}

//it returns -1 when it fails to re allocate memory
int reallocate_extra_memory()
{
        if (WARN_ON(current->sz > DF_MAX_RECORDS) || current->addresses == NULL){
                return -1;
        }
        current->addresses= (struct df_address_range*)krealloc(current->addresses,
                             current->sz*2*sizeof(struct df_address_range),GFP_KERNEL);
        if (current->addresses == NULL){
                return -1;
        }
        current->sz *= 2; 
        return 0;   
}
