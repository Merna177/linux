#include "linux/df-detection.h"
#include <asm/syscall.h>
#include <linux/context_tracking.h>
#include <linux/entry-common.h>
#include <linux/kernel.h>
#include <linux/livepatch.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>
#include <linux/sys.h>
#include <linux/types.h>
void add_address(const void *addr, size_t len, unsigned long caller)
{
	if (current->addresses == NULL || current->pairs == NULL ||
	    addr > TASK_SIZE)
		return;
	if (current->num_read >= current->sz &&
	    !WARN_ON(current->sz > DF_MAX_RECORDS)) {
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
		current->addresses[current->num_read].stack =
		    df_save_stack(GFP_NOWAIT);
		detect_intersection();
		current->num_read++;
	}
}

void start_system_call(long syscall)
{
	current->syscall_num = syscall;
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
		if (current->df_index)
			report();
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

void report(void)
{
	if (!check_valid_detection())
		return;
	int i;
	pr_err("BUG: Intersection Detected at syscall: %pSR\n ",
	       sys_call_table[current->syscall_num]);
	pr_err("==================================================================\n");
	pr_err("syscall number %ld  System Call: %pSR\n", current->syscall_num,
	       sys_call_table[current->syscall_num]);
	for (i = 0; i < current->df_index; i++) {
		pr_err("First %px len %lu Caller %pSR \nSecond %px len "
		       "%lu Caller %pSR \n",
		       current->pairs[i].first->start_address,
		       current->pairs[i].first->len,
		       current->pairs[i].first->caller,
		       current->pairs[i].second->start_address,
		       current->pairs[i].second->len,
		       current->pairs[i].second->caller);
		if (current->pairs[i].first->stack) {
			unsigned long *entries;
			unsigned int nr_entries;
			pr_err("Stack for the first address range\n");
			nr_entries = stack_depot_fetch(
			    current->pairs[i].first->stack, &entries);
			stack_trace_print(entries, nr_entries, 0);
		} else {
			pr_err("(stack of first addrees range is not "
			       "available)\n");
		}
		if (current->pairs[i].second->stack) {
			unsigned long *entries;
			unsigned int nr_entries;
			pr_err("Stack for the second address range\n");
			nr_entries = stack_depot_fetch(
			    current->pairs[i].second->stack, &entries);
			stack_trace_print(entries, nr_entries, 0);
		} else {
			pr_err("(stack of second addrees range is not "
			       "available)\n");
		}
	}
	pr_err("==================================================================\n");
	if (panic_on_warn) {
		panic_on_warn = 0;
		panic("panic_on_warn set. \n");
	}
}
// return zero if detecting a false DF
bool check_valid_detection(void)
{
	if (current->syscall_num == 54 || current->syscall_num == 165 ||
	    current->syscall_num == 16)
		return false;
	return true;
}
depot_stack_handle_t df_save_stack(gfp_t flags)
{
	unsigned long entries[STACK_DEPTH];
	unsigned int nr_entries;

	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
	nr_entries = filter_irq_stacks(entries, nr_entries);
	return stack_depot_save(entries, nr_entries, flags);
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
		    !WARN_ON(current->df_size >
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