// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022
 * Kent Hall <kjh2166@columbia.edu>
 */

#include <linux/horizon/handle_table.h>
#include <linux/poll.h>
#include <linux/pid.h>
#include <linux/types.h>

static int thread_release(struct inode *inode, struct file *file)
{
	put_pid(file->private_data);
	return 0;
}

static __poll_t thread_poll(struct file *file, struct poll_table_struct *pts)
{
	struct pid *pid = file->private_data;
	__poll_t poll_flags = 0;
	struct task_struct *task;
	bool exited;

	poll_wait(file, &pid->wait_pidfd, pts);

	rcu_read_lock();
	task = pid_task(pid, PIDTYPE_PID);
	exited = !task || READ_ONCE(task->exit_state);
	rcu_read_unlock();

	/*
	 * Inform pollers only when the whole thread group exits.
	 * If the thread group leader exits before all other threads in the
	 * group, then poll(2) should block, similar to the wait(2) family.
	 */
	if (exited)
		poll_flags = EPOLLIN | EPOLLRDNORM;

	return poll_flags;
}

const struct file_operations hzn_thread_fops = {
	.release = thread_release,
	.poll = thread_poll,
};

static int session_release(struct inode *inode, struct file *file)
{
	struct hzn_session_handler *handler = file->private_data;
	struct hzn_session_request *close_request;
	struct task_struct *service_task;

	if (handler->service) {
		if ((service_task = get_pid_task(handler->service, PIDTYPE_PID))) {
			if (handler->id) {
				close_request = kmalloc(sizeof(struct hzn_session_request), GFP_KERNEL);
				if (close_request == NULL)
					// no way to recover from this really, just report it and move on
					pr_crit("horizon session_release: kmalloc failed\n");
				else {
					// special NULL command request to indicate the service should just cleanup
					close_request->cmd = NULL;
					close_request->close_session_id = handler->id;

					spin_lock(&service_task->hzn_requests_lock);
					// ignore hzn_requests_stop, we're not sleeping
					// for this pseudo-request so it doesn't matter
					list_add_tail(&close_request->entry, &service_task->hzn_requests);
					spin_unlock(&service_task->hzn_requests_lock);
					wake_up_process(service_task);
				}
			}
			put_task_struct(service_task);
		}
		put_pid(handler->service);
	}

	kfree(handler);
	return 0;
}

const struct file_operations hzn_session_fops = {
	.release = session_release,
};
