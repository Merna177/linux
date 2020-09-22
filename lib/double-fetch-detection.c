#include "linux/double-fetch-detection.h"
#include <linux/context_tracking.h>
#include <linux/entry-common.h>
#include <linux/livepatch.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/slab.h>
void addAddress(void* addr, unsigned long leng){
           if(current->noRead==100 || current->noRead==-1)
             return;
           ((current->addresses)+current->noRead)->startaddress = addr;
            ((current->addresses)+current->noRead)->len =leng;
           current->noRead++;
}

void startSystemCall(){
    current->addresses= (struct address*)kmalloc_array(100,sizeof(struct address),GFP_KERNEL);
    if(!current->addresses)
        current->noRead=-1;
    else
        current->noRead=0;

}
void endSysCall(){
    print();
    current->noRead=-1;
    kfree(current->addresses);
}
void print(){
       if(current->noRead>0 && current->addresses){
       pr_err("FINALLY         address  %p  and length %lu \n  ",current->addresses->startaddress,current->addresses->len);
       }
      
}
