#include "linux/df-detection.h"
#include <asm/syscall.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
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
	char buf[64];
	int size;
	size = scnprintf(buf, sizeof(buf), "%ps", caller);
	/*ignore cases based on input(pointer and length)*/
	if (len > MAX_LEN || addr == 0 ||
	    strnstr(buf, "copy_from_user_nmi", size))
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
	unsigned long *first_entries;
	unsigned int first_nr_entries;
	unsigned long *second_entries;
	unsigned int second_nr_entries;
	unsigned long first_frame = 0;
	unsigned long second_frame = 0;

	for (i = 0; i < current->df_index; i++) {
		if (current->addresses[current->pairs[i].first].stack &&
		    current->addresses[current->pairs[i].second].stack) {
			first_nr_entries = stack_depot_fetch(
			    current->addresses[current->pairs[i].first].stack,
			    &first_entries);
			second_nr_entries = stack_depot_fetch(
			    current->addresses[current->pairs[i].second].stack,
			    &second_entries);
			int first_index =
			    filter_stack(first_entries, first_nr_entries);
			int second_index =
			    filter_stack(second_entries, second_nr_entries);
			first_frame = first_entries[first_index];
			second_frame = second_entries[second_index];
			char first_buf[64], second_buf[64];
			int first_len, second_len;
			/*check if this bug happent in perf_copy_attr*/
			first_len = scnprintf(first_buf, sizeof(first_buf),
					      "%ps", (void *)first_frame);
			second_len = scnprintf(second_buf, sizeof(second_buf),
					       "%ps", (void *)second_frame);
			if (strnstr(first_buf, "perf_copy_attr", first_len) &&
			    strnstr(second_buf, "perf_copy_attr", second_len))
				continue;
			pr_err("BUG: multi-read in %ps  "
			       "between %ps and %ps\n ",
			       sys_call_table[current->syscall_num],
			       first_frame, second_frame);
			pr_err("==============================================="
			       "===================\n");
			pr_err("======= First Address Range Stack =======");
			stack_trace_print(first_entries, first_nr_entries, 0);
			pr_err("======= Second Address Range Stack =======");
			stack_trace_print(second_entries, second_nr_entries, 0);
		} else {
			pr_err("BUG: Intersection Detected at syscall: %ps\n ",
			       sys_call_table[current->syscall_num]);
			pr_err("==============================================="
			       "===================\n");
		}
		pr_err("syscall number %ld  System Call: %pSR\n",
		       current->syscall_num,
		       sys_call_table[current->syscall_num]);
		pr_err(
		    "First %px len %lu Caller %pSR \nSecond %px len "
		    "%lu Caller %pSR \n",
		    current->addresses[current->pairs[i].first].start_address,
		    current->addresses[current->pairs[i].first].len,
		    current->addresses[current->pairs[i].first].caller,
		    current->addresses[current->pairs[i].second].start_address,
		    current->addresses[current->pairs[i].second].len,
		    current->addresses[current->pairs[i].second].caller);
		pr_err("======================================================="
		       "===========\n");
		if (panic_on_warn) {
			panic_on_warn = 0;
			panic("panic_on_warn set. \n");
		}
	}
}
int filter_stack(const unsigned long stack_entries[], int num_entries)
{
	char buf[64];
	int len, indx;
	/*we are not interested in first 2 entries as they are always
	 * add_address & df_save_stack*/
	for (indx = 2; indx < num_entries; indx++) {
		len = scnprintf(buf, sizeof(buf), "%ps",
				(void *)stack_entries[indx]);

		if (strnstr(buf, "copy_from_user", len) ||
		    strnstr(buf, "copyin", len) ||
		    strnstr(buf, "strncpy_from_user", len) ||
		    strnstr(buf, "get_user", len) ||
		    strnstr(buf, "memdup_user", len))
			continue;
		break;
	}

	return indx == num_entries ? 0 : indx;
}

// return zero if detecting a false DF
bool check_valid_detection(void)
{
	if (current->syscall_num == 54 || current->syscall_num == 165 ||
	    current->syscall_num == 16 || current->syscall_num == 47)
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
			current->pairs[current->df_index].first = i;
			current->pairs[current->df_index].second =
			    current->num_read;
			current->df_index++;
		}
	}
}
static int df_open(struct inode *inode, struct file *filep)
{
	return nonseekable_open(inode, filep);
}
static const struct file_operations df_fops = {
    .open = df_open,
};
static int __init df_detection_init(void)
{
	debugfs_create_file_unsafe("df_detection", 0600, NULL, NULL, &df_fops);

	return 0;
}
device_initcall(df_detection_init);