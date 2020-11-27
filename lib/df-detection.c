#include <linux/debugfs.h>
#include <linux/df-detection.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>
#include <linux/sys.h>
#include <linux/types.h>

void dfetch_add_address(const void *addr, size_t len, unsigned long caller,
			void *kernel_addr)
{
	if (!in_task() || current->dfetch_addresses == NULL ||
	    current->dfetch_pairs == NULL)
		return;
	if (len > MAX_LEN || addr == 0 || addr > TASK_SIZE)
		return;
	if (current->num_read >= current->ranges_size &&
	    current->ranges_size < DFETCH_MAX_RECORDS) {
		struct dfetch_address_range *temp =
		    (struct dfetch_address_range *)krealloc(
			current->dfetch_addresses,
			current->ranges_size * 2 *
			    sizeof(struct dfetch_address_range),
			GFP_KERNEL);
		current->dfetch_addresses =
		    temp ? temp : current->dfetch_addresses;
		current->ranges_size = current->dfetch_addresses
					   ? current->ranges_size * 2
					   : current->ranges_size;
	}
	if (current->num_read < current->ranges_size) {
		current->dfetch_addresses[current->num_read].start_address =
		    addr;
		current->dfetch_addresses[current->num_read].len = len;
		current->dfetch_addresses[current->num_read].caller = caller;
		current->dfetch_addresses[current->num_read].stack =
		    dfetch_save_stack(GFP_NOWAIT);
		detect_intersection(kernel_addr);
		current->num_read++;
	}
}
EXPORT_SYMBOL(dfetch_add_address);

void dfetch_start_system_call(void)
{
	if (!current->dfetch_enable)
		return;
	current->dfetch_addresses =
	    (struct dfetch_address_range *)kmalloc_array(
		DFETCH_INIT_SIZE, sizeof(struct dfetch_address_range),
		GFP_KERNEL);
	current->ranges_size = current->dfetch_addresses ? DFETCH_INIT_SIZE : 0;
	current->num_read = 0;
	current->dfetch_pairs = (struct dfetch_pair *)kmalloc_array(
	    DFETCH_INIT_SIZE, sizeof(struct dfetch_pair), GFP_KERNEL);
	current->dfetch_size = current->dfetch_pairs ? DFETCH_INIT_SIZE : 0;
	current->dfetch_index = 0;
}
EXPORT_SYMBOL(dfetch_start_system_call);

void dfetch_end_system_call(void)
{
	if (!current->dfetch_enable)
		return;
	if (current->dfetch_pairs != NULL) {
		if (current->dfetch_index)
			report();
		kfree(current->dfetch_pairs);
		current->dfetch_pairs = NULL;
		current->dfetch_index = 0;
		current->dfetch_size = 0;
	}
	if (current->dfetch_addresses != NULL) {
		current->num_read = 0;
		current->ranges_size = 0;
		kfree(current->dfetch_addresses);
		current->dfetch_addresses = NULL;
	}
}
EXPORT_SYMBOL(dfetch_end_system_call);

void report(void)
{
	int i;
	unsigned long *first_entries;
	unsigned int first_nr_entries;
	unsigned long *second_entries;
	unsigned int second_nr_entries;

	for (i = 0; i < current->dfetch_index; i++) {
		if (current->dfetch_addresses[current->dfetch_pairs[i].first]
			.stack &&
		    current->dfetch_addresses[current->dfetch_pairs[i].second]
			.stack) {
			first_nr_entries = stack_depot_fetch(
			    current
				->dfetch_addresses[current->dfetch_pairs[i]
						       .first]
				.stack,
			    &first_entries);
			second_nr_entries = stack_depot_fetch(
			    current
				->dfetch_addresses[current->dfetch_pairs[i]
						       .second]
				.stack,
			    &second_entries);
			pr_err("BUG: multi-read\n");
			pr_err("==================================================================\n");
			dump_stack_print_info(KERN_DEFAULT);
			pr_err("First Stack Trace:");
			stack_trace_print(first_entries, first_nr_entries, 0);
			pr_err("Second Stack Trace:");
			stack_trace_print(second_entries, second_nr_entries, 0);
		} else {
			pr_err("BUG: multi-read\n");
			pr_err("==================================================================\n");
		}
		pr_err(
		    "First %px len %lu Caller %pSR \nSecond %px len "
		    "%lu Caller %pSR \n \n",
		    current->dfetch_addresses[current->dfetch_pairs[i].first]
			.start_address,
		    current->dfetch_addresses[current->dfetch_pairs[i].first]
			.len,
		    current->dfetch_addresses[current->dfetch_pairs[i].first]
			.caller,
		    current->dfetch_addresses[current->dfetch_pairs[i].second]
			.start_address,
		    current->dfetch_addresses[current->dfetch_pairs[i].second]
			.len,
		    current->dfetch_addresses[current->dfetch_pairs[i].second]
			.caller);
		pr_err("==================================================================\n");
		if (panic_on_warn) {
			panic_on_warn = 0;
			panic("panic_on_warn set. \n");
		}
	}
}

depot_stack_handle_t dfetch_save_stack(gfp_t flags)
{
	unsigned long entries[STACK_DEPTH];
	unsigned int nr_entries;

	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
	nr_entries = filter_irq_stacks(entries, nr_entries);
	return stack_depot_save(entries, nr_entries, flags);
}

int is_intersect(struct dfetch_address_range a, struct dfetch_address_range b,
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
		if (!is_intersect(current->dfetch_addresses[i],
				  current->dfetch_addresses[current->num_read],
				  kernel_addr))
			continue;
		if (current->dfetch_index >= current->dfetch_size &&
		    current->dfetch_size <
			DFETCH_MAX_RECORDS * DFETCH_MAX_RECORDS) {
			struct dfetch_pair *temp =
			    (struct dfetch_pair *)krealloc(
				current->dfetch_pairs,
				current->dfetch_size * 2 *
				    sizeof(struct dfetch_pair),
				GFP_KERNEL);
			current->dfetch_pairs =
			    temp ? temp : current->dfetch_pairs;
			current->dfetch_size = temp ? current->dfetch_size * 2
						    : current->dfetch_size;
		}
		if (current->dfetch_index < current->dfetch_size) {
			current->dfetch_pairs[current->dfetch_index].first = i;
			current->dfetch_pairs[current->dfetch_index].second =
			    current->num_read;
			current->dfetch_index++;
		}
	}
}

static long dfetch_ioctl(struct file *filep, unsigned int cmd,
			 unsigned long unused)
{
	switch (cmd) {
	case DFETCH_ENABLE:
		/* Enable DF for the current task.*/
		current->dfetch_enable = true;
		return 0;
	case DFETCH_DISABLE:
		current->dfetch_enable = false;
		return 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations dfetch_fops = {
    .open = nonseekable_open,
    .unlocked_ioctl = dfetch_ioctl,
    .compat_ioctl = dfetch_ioctl,
};

static int __init dfetch_detection_init(void)
{
	debugfs_create_file_unsafe("dfetch_detection", 0600, NULL, NULL,
				   &dfetch_fops);

	return 0;
}
device_initcall(dfetch_detection_init);