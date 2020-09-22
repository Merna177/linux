#ifndef __LINUX_DOUBLE_FETCH_DETECTION_H__
#define __LINUX_DOUBLE_FETCH_DETECTION_H__
#ifdef CONFIG_DF_DETECTION

struct address{
    void *startaddress;
    unsigned long len;
};


void addAddress(void* addr,unsigned long len);
void startSystemCall(void);
void endSysCall(void);
void print(void);

#endif
#endif