/*
 *  Copyright (c) 2016-2017, NVIDIA CORPORATION. All rights reserved.
 */

#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/time.h>
#include <linux/kernel_stat.h>
#include <linux/ctype.h>
#include <linux/string.h>

#define MAX_SINGLE_INPUT (10+1+6+1)
#define INPUT_BUFFER_SIZE 256

static ssize_t task_weight_proc_write(struct file *filp, const char __user *buf,
				      size_t count, loff_t *f_pos)
{
	size_t total = count;
	int input_left = 0;
	char tmpbuf[INPUT_BUFFER_SIZE], *head = tmpbuf;

	tmpbuf[0] = 0;

	while (count || input_left) {
		char *end;
		int vpid, weight;
		struct task_struct *task;
		struct pid *pid;
		size_t length;

		if (input_left < MAX_SINGLE_INPUT) {
			int readcount = count >= sizeof(tmpbuf)-input_left ? sizeof(tmpbuf)-1-input_left : count;
			if (readcount) {
				memmove(tmpbuf, head, input_left);
				head = tmpbuf;

				if (copy_from_user(tmpbuf+input_left, buf, readcount))
					return -EFAULT;

				tmpbuf[input_left+readcount] = 0;

				buf += readcount;
				count -= readcount;
				input_left += readcount;
			}
		}

		vpid = simple_strtol(skip_spaces(head), &end, 0);
		weight = simple_strtol(skip_spaces(end), &end, 0);
		length = skip_spaces(end) - head;

		if (!length || weight < 0 || weight > (32<<10))
			return -EINVAL;

		rcu_read_lock();
		pid = find_vpid(vpid);
		task = pid_task(pid, PIDTYPE_PID);
		if (pid && task)
			task->se.avg.weight = weight;
		rcu_read_unlock();

		input_left -= length;
		head += length;
	}

	return total;
}

static atomic_t total_open = ATOMIC_INIT(0);

static int task_weight_proc_open(struct inode *inode, struct file *file)
{
	atomic_inc(&total_open);

	return 0;
}

static int task_weight_proc_release(struct inode *inode, struct file *file)
{
	if (atomic_dec_and_test(&total_open)) {
		struct task_struct *g, *p;

		rcu_read_lock();
		do_each_thread(g, p) {
			p->se.avg.weight = 1024;
		} while_each_thread(g, p);
		rcu_read_unlock();
	}

	return 0;
}

static const struct file_operations task_weight_proc_fops = {
	.open		= task_weight_proc_open,
	.release	= task_weight_proc_release,
	.write		= task_weight_proc_write,
};

static int __init proc_task_weight_init(void)
{
	proc_create("task_weight", 0200, NULL, &task_weight_proc_fops);

	return 0;
}

fs_initcall(proc_task_weight_init);
