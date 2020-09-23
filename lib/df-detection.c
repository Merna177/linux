#include "linux/df-detection.h"
#include <linux/context_tracking.h>
#include <linux/entry-common.h>
#include <linux/livepatch.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/slab.h>
void add_address(const void* addr, unsigned long len){
           if(!current->addresses || (current->num_read==current->sz && reallocate_extra_memory()==-1))
             return;
           current->addresses[current->num_read].start_address = addr;
           current->addresses[current->num_read].len =len;
           current->num_read++;
}

void start_system_call(){
    current->addresses= (struct df_address_range*)kmalloc_array(allocation_size,sizeof(struct df_address_range),GFP_KERNEL);
    current->num_read = current->addresses ? 0 : -1;
    current->sz = current->addresses ? allocation_size : 0;
}
void end_system_call(){
    print();
    if(current->addresses){
    current->num_read=-1;
    current->sz = 0;
    kfree(current->addresses);
    }
}
void print(){
       if(current->num_read>0 && current->addresses){
       pr_err("FINALLY         address  %p  and length %lu \n  ",current->addresses->start_address,current->addresses->len);
       }
      
}
//it returns -1 when it fails to re allocate memory
int reallocate_extra_memory(){
     if(current->sz>(INT_MAX)/2)
     {
       pr_err("It will exceed INT_MAX");
       return -1;
     }
     current->sz = krealloc(current->addresses,current->sz*sizeof(struct df_address_range),GFP_KERNEL) ? current->sz*2 : current->sz;
     return 0;
}
