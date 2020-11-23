#include <linux/df-detection.h>
#include <asm/syscall.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>
#include <linux/sys.h>
#include <linux/types.h>

void add_address(const void *addr, size_t len, unsigned long caller,
		 void *kernel_addr)
{
	if (!in_task() || current->addresses == NULL || current->pairs == NULL ||
	    addr > TASK_SIZE)
		return;
	char buf[64], buf_caller[64];
	int size;
	size = scnprintf(buf, sizeof(buf), "%ps", caller);
	if (len > MAX_LEN || addr == 0 || strnstr(buf, "copy_from_user_nmi", size))
		return;
	if (current->num_read >= current->sz && current->sz < DF_MAX_RECORDS) {
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
		detect_intersection(kernel_addr);
		current->num_read++;
	}
}

void start_system_call(long syscall)
{
	if (!current->df_enable)
		return;
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
	if (!current->df_enable)
		return;
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
			pr_err("BUG: multi-read\n");
			pr_err("==================================================================\n");
			pr_err("First Address Range Stack:");
			stack_trace_print(first_entries, first_nr_entries, 0);
			pr_err("Second Address Range Stack\n");
			stack_trace_print(second_entries, second_nr_entries, 0);
		} else {
			pr_err("BUG: multi-read\n");
			pr_err("==================================================================\n");
		}
		pr_err("syscall number %ld  System Call: %pSR\n",
		       current->syscall_num,
		       sys_call_table[current->syscall_num]);
		pr_err(
		    "First %px len %lu Caller %pSR \nSecond %px len "
		    "%lu Caller %pSR \n \n",
		    current->addresses[current->pairs[i].first].start_address,
		    current->addresses[current->pairs[i].first].len,
		    current->addresses[current->pairs[i].first].caller,
		    current->addresses[current->pairs[i].second].start_address,
		    current->addresses[current->pairs[i].second].len,
		    current->addresses[current->pairs[i].second].caller);
		dump_stack_print_info(KERN_DEFAULT);
		pr_err("======================================================="
		       "===========\n");
		if (panic_on_warn) {
			panic_on_warn = 0;
			panic("panic_on_warn set. \n");
		}
	}
}

depot_stack_handle_t df_save_stack(gfp_t flags)
{
	unsigned long entries[STACK_DEPTH];
	unsigned int nr_entries;

	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
	nr_entries = filter_irq_stacks(entries, nr_entries);
	return stack_depot_save(entries, nr_entries, flags);
}

int is_intersect(struct df_address_range a, struct df_address_range b,
		 void *kernel_addr)
{
	void *a_end = (void *)((char *)a.start_address + a.len);
	void *b_end = (void *)((char *)b.start_address + b.len);
	if (a.start_address <= b.start_address && a_end > b.start_address) {
		size_t len = (char *)(a_end > b_end ? b_end : a_end) -
			     (char *)b.start_address;
		get_random_bytes(kernel_addr, len);
		return 1;
	} else if (b.start_address <= a.start_address &&
		   b_end > a.start_address) {
		unsigned long diff =
		    (char *)a.start_address - (char *)b.start_address;
		size_t len = (char *)(a_end > b_end ? b_end : a_end) -
			     (char *)a.start_address;
		get_random_bytes(((char *)kernel_addr + diff), len);
		return 1;
	}
	return 0;
}

void detect_intersection(void *kernel_addr)
{
	int i;
	for (i = 0; i < current->num_read; i++) {
		if (!is_intersect(current->addresses[i],
				  current->addresses[current->num_read],
				  kernel_addr))
			continue;
		if (current->df_index >= current->df_size &&
		    current->df_size < DF_MAX_RECORDS * DF_MAX_RECORDS) {
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

static long df_ioctl(struct file *filep, unsigned int cmd, unsigned long unused)
{
	switch (cmd) {
	case DFETCH_ENABLE:
		/* Enable DF for the current task.*/
		current->df_enable = true;
		return 0;
	case DFETCH_DISABLE:
		current->df_enable = false;
		return 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations df_fops = {
    .open = nonseekable_open,
    .unlocked_ioctl = df_ioctl,
    .compat_ioctl = df_ioctl,
};

static int __init df_detection_init(void)
{
	debugfs_create_file_unsafe("df_detection", 0600, NULL, NULL, &df_fops);

	return 0;
}
device_initcall(df_detection_init);