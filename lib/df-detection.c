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

static int is_intersect(struct dfetch_address_range a,
			struct dfetch_address_range b, void *kernel_addr)
{
	void *a_end = (void *)((char *)a.start_address + a.len);
	void *b_end = (void *)((char *)b.start_address + b.len);
	size_t len;
	void *addr = kernel_addr;

	if (a.start_address <= b.start_address && a_end > b.start_address) {
		len = (char *)(a_end > b_end ? b_end : a_end) -
		      (char *)b.start_address;
	} else if (b.start_address <= a.start_address &&
		   b_end > a.start_address) {
		unsigned long diff =
		    (char *)a.start_address - (char *)b.start_address;

		len = (char *)(a_end > b_end ? b_end : a_end) -
		      (char *)a.start_address;
		addr = ((char *)kernel_addr + diff);
	} else
		return 0;
	get_random_bytes(addr, len);
	pr_err("Random injection in %px, Length %lu \n", addr, len);
	return 1;
}

static void detect_intersection(void *kernel_addr)
{
	int i;

	for (i = 0; i < current->dfetch.num_read; i++) {
		if (!is_intersect(
			current->dfetch.dfetch_addresses[i],
			current->dfetch
			    .dfetch_addresses[current->dfetch.num_read],
			kernel_addr))
			continue;
		if (current->dfetch.dfetch_index >=
			current->dfetch.dfetch_size &&
		    current->dfetch.dfetch_size <
			DFETCH_MAX_RECORDS * DFETCH_MAX_RECORDS) {
			struct dfetch_pair *temp =
			    (struct dfetch_pair *)krealloc(
				current->dfetch.dfetch_pairs,
				current->dfetch.dfetch_size * 2 *
				    sizeof(struct dfetch_pair),
				GFP_KERNEL);
			current->dfetch.dfetch_pairs =
			    temp ? temp : current->dfetch.dfetch_pairs;
			current->dfetch.dfetch_size =
			    temp ? current->dfetch.dfetch_size * 2
				 : current->dfetch.dfetch_size;
		}
		if (current->dfetch.dfetch_index <
		    current->dfetch.dfetch_size) {
			current->dfetch
			    .dfetch_pairs[current->dfetch.dfetch_index]
			    .first = i;
			current->dfetch
			    .dfetch_pairs[current->dfetch.dfetch_index]
			    .second = current->dfetch.num_read;
			current->dfetch.dfetch_index++;
		}
	}
}

static void report(void)
{
	int i;
	unsigned long *first_entries, *second_entries;
	unsigned int first_nr_entries, second_nr_entries;

	for (i = 0; i < current->dfetch.dfetch_index; i++) {
		if (current->dfetch
			.dfetch_addresses[current->dfetch.dfetch_pairs[i].first]
			.stack &&
		    current->dfetch
			.dfetch_addresses[current->dfetch.dfetch_pairs[i]
					      .second]
			.stack) {
			first_nr_entries = stack_depot_fetch(
			    current->dfetch
				.dfetch_addresses
				    [current->dfetch.dfetch_pairs[i].first]
				.stack,
			    &first_entries);
			second_nr_entries = stack_depot_fetch(
			    current->dfetch
				.dfetch_addresses
				    [current->dfetch.dfetch_pairs[i].second]
				.stack,
			    &second_entries);
			pr_err("BUG: multi-read\n");
			pr_err("============================================================\n");
			dump_stack_print_info(KERN_DEFAULT);
			pr_err("First Stack Trace:");
			stack_trace_print(first_entries, first_nr_entries, 0);
			pr_err("Second Stack Trace:");
			stack_trace_print(second_entries, second_nr_entries, 0);
		} else {
			pr_err("BUG: multi-read\n");
			pr_err("============================================================\n");
		}
		pr_err(
		    "First %px len %lu Caller %ps \nSecond %px len %lu Caller "
		    "%ps \n \n",
		    current->dfetch
			.dfetch_addresses[current->dfetch.dfetch_pairs[i].first]
			.start_address,
		    current->dfetch
			.dfetch_addresses[current->dfetch.dfetch_pairs[i].first]
			.len,
		    current->dfetch
			.dfetch_addresses[current->dfetch.dfetch_pairs[i].first]
			.caller,
		    current->dfetch
			.dfetch_addresses[current->dfetch.dfetch_pairs[i]
					      .second]
			.start_address,
		    current->dfetch
			.dfetch_addresses[current->dfetch.dfetch_pairs[i]
					      .second]
			.len,
		    current->dfetch
			.dfetch_addresses[current->dfetch.dfetch_pairs[i]
					      .second]
			.caller);
		pr_err("============================================================\n");
		if (panic_on_warn) {
			panic_on_warn = 0;
			panic("panic_on_warn set. \n");
		}
	}
}

static depot_stack_handle_t dfetch_save_stack(gfp_t flags)
{
	unsigned long entries[STACK_DEPTH];
	unsigned int nr_entries;

	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
	nr_entries = filter_irq_stacks(entries, nr_entries);
	return stack_depot_save(entries, nr_entries, flags);
}

void dfetch_add_address(const void *addr, size_t len, unsigned long caller,
			void *kernel_addr)
{
	if (!in_task() || current->dfetch.dfetch_addresses == NULL ||
	    current->dfetch.dfetch_pairs == NULL)
		return;
	if (len > MAX_LEN || addr == 0 || addr > TASK_SIZE)
		return;
	if (current->dfetch.num_read >= current->dfetch.ranges_size &&
	    current->dfetch.ranges_size < DFETCH_MAX_RECORDS) {
		struct dfetch_address_range *temp =
		    (struct dfetch_address_range *)krealloc(
			current->dfetch.dfetch_addresses,
			current->dfetch.ranges_size * 2 *
			    sizeof(struct dfetch_address_range),
			GFP_KERNEL);
		current->dfetch.dfetch_addresses =
		    temp ? temp : current->dfetch.dfetch_addresses;
		current->dfetch.ranges_size =
		    current->dfetch.dfetch_addresses
			? current->dfetch.ranges_size * 2
			: current->dfetch.ranges_size;
	}
	if (current->dfetch.num_read < current->dfetch.ranges_size) {
		current->dfetch.dfetch_addresses[current->dfetch.num_read]
		    .start_address = addr;
		current->dfetch.dfetch_addresses[current->dfetch.num_read].len =
		    len;
		current->dfetch.dfetch_addresses[current->dfetch.num_read]
		    .caller = caller;
		current->dfetch.dfetch_addresses[current->dfetch.num_read]
		    .stack = dfetch_save_stack(GFP_NOWAIT);
		detect_intersection(kernel_addr);
		current->dfetch.num_read++;
	}
}
EXPORT_SYMBOL(dfetch_add_address);

void dfetch_start_system_call(void)
{
	if (!current->dfetch.dfetch_enable)
		return;
	current->dfetch.dfetch_addresses =
	    (struct dfetch_address_range *)kmalloc_array(
		DFETCH_INIT_SIZE, sizeof(struct dfetch_address_range),
		GFP_KERNEL);
	current->dfetch.ranges_size =
	    current->dfetch.dfetch_addresses ? DFETCH_INIT_SIZE : 0;
	current->dfetch.num_read = 0;
	current->dfetch.dfetch_pairs = (struct dfetch_pair *)kmalloc_array(
	    DFETCH_INIT_SIZE, sizeof(struct dfetch_pair), GFP_KERNEL);
	current->dfetch.dfetch_size =
	    current->dfetch.dfetch_pairs ? DFETCH_INIT_SIZE : 0;
	current->dfetch.dfetch_index = 0;
}
EXPORT_SYMBOL(dfetch_start_system_call);

void dfetch_end_system_call(void)
{
	if (!current->dfetch.dfetch_enable)
		return;
	if (current->dfetch.dfetch_pairs != NULL) {
		if (current->dfetch.dfetch_index)
			report();
		kfree(current->dfetch.dfetch_pairs);
		current->dfetch.dfetch_pairs = NULL;
		current->dfetch.dfetch_index = 0;
		current->dfetch.dfetch_size = 0;
	}
	if (current->dfetch.dfetch_addresses != NULL) {
		current->dfetch.num_read = 0;
		current->dfetch.ranges_size = 0;
		kfree(current->dfetch.dfetch_addresses);
		current->dfetch.dfetch_addresses = NULL;
	}
}
EXPORT_SYMBOL(dfetch_end_system_call);

/* Enable/Disable DF for the current task.*/
static long dfetch_ioctl(struct file *filep, unsigned int cmd,
			 unsigned long unused)
{
	switch (cmd) {
	case DFETCH_ENABLE:
		current->dfetch.dfetch_enable = true;
		return 0;
	case DFETCH_DISABLE:
		current->dfetch.dfetch_enable = false;
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