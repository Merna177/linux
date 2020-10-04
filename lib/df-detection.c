#include "linux/df-detection.h"
#include <linux/context_tracking.h>
#include <linux/entry-common.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>

void add_address(const void *addr, unsigned long len,unsigned int caller)
{
	if (current->addresses == NULL || current->pairs == NULL)
		return;
	if (current->num_read >= current->sz &&
	    reallocate_extra_memory(current->sz, DF_MAX_RECORDS)) {
		struct df_address_range *temp =
		    (struct df_address_range *)krealloc(
			current->addresses,
			current->sz * 2 * sizeof(struct df_address_range),
			GFP_KERNEL);
		current->addresses = temp ? temp : current->addresses;
		current->sz =
		    current->addresses ? current->sz * 2 : current->sz;
	}
	if (current->num_read < current->sz) {
		current->addresses[current->num_read].start_address = addr;
		current->addresses[current->num_read].len = len;
		current->addresses[current->num_read].caller = caller;
		detect_intersection();
		current->num_read++;
	}
}

void start_system_call(long syscall)
{
	current->syscall_num = syscall;
	pr_err("syscall %ld",syscall);
	current->addresses = (struct df_address_range *)kmalloc_array(
	    DF_INIT_SIZE, sizeof(struct df_address_range), GFP_KERNEL);
	current->sz = current->addresses ? DF_INIT_SIZE : 0;
	current->num_read = 0;
	current->pairs = (struct df_pair *)kmalloc_array(
	    DF_INIT_SIZE, sizeof(struct df_pair), GFP_KERNEL);
	current->df_size = current->pairs ? DF_INIT_SIZE : 0;
	current->df_index = 0;
}
void end_system_call(void)
{
	if (current->pairs != NULL) {
		if (current->df_index) {
			print_pairs();
			dump_stack();
			pr_err("BUG: Intersection Detected \n ");
		}
		kfree(current->pairs);
		current->pairs = NULL;
		current->df_index = 0;
		current->df_size = 0;
	}
	if (current->addresses != NULL) {
		current->num_read = 0;
		current->sz = 0;
		kfree(current->addresses);
		current->addresses = NULL;
	}
}
void print_pairs(void)
{
	int i;
	for (i = 0; i < current->df_index; i++) {
		pr_err("First %px len %lu \nSecond %px len %lu\n",
		       current->pairs[i].first->start_address,
		       current->pairs[i].first->len,
		       current->pairs[i].second->start_address,
		       current->pairs[i].second->len);
	}
}
// it returns 0 when it fails to re allocate memory
int reallocate_extra_memory(int sz, int mx_size)
{
	return WARN_ON(sz > mx_size) ? 0 : 1;
}
int is_intersect(struct df_address_range a, struct df_address_range b)
{
	if ((a.start_address <= b.start_address &&
	     ((void *)(char *)a.start_address + a.len) > b.start_address) ||
	    (b.start_address <= a.start_address &&
	     ((void *)(char *)b.start_address + b.len) > a.start_address)) {
		return 1;
	}
	return 0;
}
void detect_intersection(void)
{
	int i;
	for (i = 0; i < current->num_read; i++) {
		if (!is_intersect(current->addresses[i],
				  current->addresses[current->num_read]))
			continue;
		if (current->df_index >= current->df_size &&
		    reallocate_extra_memory(current->df_size,
					    DF_MAX_RECORDS * DF_MAX_RECORDS)) {
			struct df_pair *temp = (struct df_pair *)krealloc(
			    current->pairs,
			    current->df_size * 2 * sizeof(struct df_pair),
			    GFP_KERNEL);
			current->pairs = temp ? temp : current->pairs;
			current->df_size =
			    temp ? current->df_size * 2 : current->df_size;
		}
		if (current->df_index < current->df_size) {
			current->pairs[current->df_index].first =
			    &current->addresses[i];
			current->pairs[current->df_index].second =
			    &current->addresses[current->num_read];
			current->df_index++;
		}
	}
}
