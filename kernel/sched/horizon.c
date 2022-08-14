#include <linux/sched/horizon.h>

#include "sched.h"

#define for_each_queue(rq, high, low, queue)					\
	for ((queue) = (rq)->queue + (high) - HZN_HIGHEST_THREAD_PRIORITY;	\
	     (queue) <= (rq)->queue + (low) - HZN_HIGHEST_THREAD_PRIORITY;	\
	     ++(queue))

#define entity_queue(hzn_rq, entity) \
	((hzn_rq)->queue + ((entity)->priority - HZN_HIGHEST_THREAD_PRIORITY))

static inline struct task_struct *task_of(struct sched_hzn_entity *entity)
{
	return container_of(entity, struct task_struct, hzn);
}

static void
enqueue_task_horizon(struct rq *rq, struct task_struct *p, int flags)
{
	struct hzn_rq *hzn_rq = &rq->hzn;
	struct sched_hzn_entity *entity = &p->hzn;

	hzn_rq->nr_running++;
	entity->rq = rq;
	list_add_tail(&entity->list, entity_queue(hzn_rq, entity));
	add_nr_running(rq, 1);
}

static void
dequeue_task_horizon(struct rq *rq, struct task_struct *p, int flags)
{
	struct hzn_rq *hzn_rq = &rq->hzn;
	struct sched_hzn_entity *entity = &p->hzn;

	if (hzn_rq->curr == entity && (entity->state == HZN_SWITCHABLE
	    || unlikely(p->state == TASK_DEAD)))
		hzn_rq->curr = NULL;

	entity->rq = NULL;
	if (hzn_rq->nr_running) {
		hzn_rq->nr_running--;
		list_del(&entity->list);
		sub_nr_running(rq, 1);
	}
}

static void
yield_task_horizon(struct rq *rq, enum hzn_yield_type type)
{
	rq->curr->hzn.yield_type = type;
}

static void
check_preempt_curr_horizon(struct rq *rq, struct task_struct *p, int flags)
{
}

struct task_struct *
pick_next_task_horizon(struct rq *rq)
{
	struct hzn_rq *hzn_rq = &rq->hzn;
	struct list_head *queue;
	int next_queue;
	struct sched_hzn_entity *entity, *first;
	struct task_struct *p;
	s32 high = HZN_HIGHEST_THREAD_PRIORITY;
	s32 low = HZN_LOWEST_THREAD_PRIORITY;

	if (hzn_rq->curr) {
		if (hzn_rq->curr->rq != rq)
			return NULL;
		switch (hzn_rq->curr->yield_type) {
		case HZN_YIELD_NONE:
			return task_of(hzn_rq->curr);
		case HZN_YIELD_TYPE_WITHOUT_CORE_MIGRATION:
			high = hzn_rq->curr->priority;
			fallthrough;
		case HZN_YIELD_TYPE_WITH_CORE_MIGRATION:
			low = hzn_rq->curr->priority;
			break;
		case HZN_YIELD_TYPE_TO_ANY_THREAD:
			break;
		}
	}

	for_each_queue(hzn_rq, high, low, queue) {
		if (list_empty(queue))
			continue;

		entity = first = list_first_entry(queue,
				struct sched_hzn_entity, list);

		next_queue = 0;
		while (entity->yield_type != HZN_YIELD_NONE) {
			list_move_tail(&entity->list, queue);
			entity->yield_type = HZN_YIELD_NONE;
			entity = list_first_entry(queue,
					struct sched_hzn_entity, list);
			if (entity == first) { // everyone on this queue yielded
				next_queue = 1;
				break;
			}
		}
		if (next_queue)
			continue;

		p = container_of(entity, struct task_struct, hzn);

		p->se.exec_start = rq_clock_task(rq);

		hzn_rq->curr = &p->hzn;
		return p;
	}

	if (hzn_rq->curr &&
	    hzn_rq->curr->yield_type == HZN_YIELD_TYPE_TO_ANY_THREAD)
		hzn_rq->curr = NULL;
	return hzn_rq->curr ? task_of(hzn_rq->curr) : NULL;
}

void update_curr_horizon(struct rq *rq)
{
	struct task_struct *curr = rq->curr;
	u64 delta_exec;
	u64 now;

	if (curr->sched_class != &hzn_sched_class)
		return;

	now = rq_clock_task(rq);
	delta_exec = now - curr->se.exec_start;
	if (unlikely((s64)delta_exec <= 0))
		return;

	schedstat_set(curr->se.statistics.exec_max,
			max(curr->se.statistics.exec_max, delta_exec));

	curr->se.sum_exec_runtime += delta_exec;
	account_group_exec_runtime(curr, delta_exec);

	curr->se.exec_start = now;
	cgroup_account_cputime(curr, delta_exec);
}

static void put_prev_task_horizon(struct rq *rq, struct task_struct *prev)
{
	update_curr_horizon(rq);
}

#ifdef CONFIG_SMP
static int
select_task_rq_horizon(struct task_struct *p, int cpu, int sd_flag, int flags)
{
	int c, min_cpu = cpu, min_running = INT_MAX;
	struct rq *rq;
	struct hzn_rq *hzn_rq;

	for_each_cpu(c, p->cpus_ptr) {
		rq = cpu_rq(c);
		hzn_rq = &rq->hzn;

		raw_spin_lock(&rq->lock);
		if (min_running > rq->hzn.nr_running) {
			min_running = rq->hzn.nr_running;
			min_cpu = c;
		}
		raw_spin_unlock(&rq->lock);
	}

	return min_cpu;
}

static int
balance_horizon(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
	return sched_stop_runnable(rq) || sched_dl_runnable(rq) ||
	       sched_rt_runnable(rq) || sched_hzn_runnable(rq);
}
#endif

static void
set_next_task_horizon(struct rq *rq, struct task_struct *p, bool first)
{
	p->se.exec_start = rq_clock_task(rq);
}

static void
task_tick_horizon(struct rq *rq, struct task_struct *curr, int queued)
{
	update_curr_horizon(rq);
}

static void
prio_changed_horizon(struct rq *rq, struct task_struct *p, int oldprio)
{
}

static void switched_to_horizon(struct rq *rq, struct task_struct *p)
{
}

void init_hzn_rq(struct hzn_rq *hzn_rq)
{
	struct list_head *queue;

	hzn_rq->nr_running = 0;
	hzn_rq->curr = NULL;
	for_each_queue(hzn_rq,
		       HZN_HIGHEST_THREAD_PRIORITY, HZN_LOWEST_THREAD_PRIORITY,
		       queue)
		INIT_LIST_HEAD(queue);
}

int get_hzn_priority(struct task_struct *p)
{
	struct rq_flags rf;
	struct rq *rq;
	int priority;

	rq = task_rq_lock(p, &rf);

	priority = p->hzn.priority;

	task_rq_unlock(rq, p, &rf);

	return priority;
}

bool set_hzn_priority(struct task_struct *p, int priority)
{
	struct sched_hzn_entity *entity = &p->hzn;
	struct list_head *queue;
	struct rq_flags rf;
	struct rq *rq;

	if (priority > HZN_LOWEST_THREAD_PRIORITY ||
	    priority < HZN_HIGHEST_THREAD_PRIORITY)
		return false;

	rq = task_rq_lock(p, &rf);
	update_rq_clock(rq);

	entity->priority = priority;
	if (entity->rq) {
		list_del(&entity->list);
		queue = entity_queue(&rq->hzn, entity);
		// according to yuzu, keep running if it's already running
		if (rq->curr == p)
			list_add(&entity->list, queue);
		else
			list_add_tail(&entity->list, queue);
	}

	task_rq_unlock(rq, p, &rf);

	return true;
}

const struct sched_class hzn_sched_class
	__section("__hzn_sched_class") = {
	.enqueue_task		= enqueue_task_horizon,
	.dequeue_task		= dequeue_task_horizon,
	.yield_task		= (void (*)(struct rq *))yield_task_horizon,
	.check_preempt_curr	= check_preempt_curr_horizon,
	.pick_next_task		= pick_next_task_horizon,
	.put_prev_task		= put_prev_task_horizon,
#ifdef CONFIG_SMP
	.balance		= balance_horizon,
	.select_task_rq		= select_task_rq_horizon,
	.set_cpus_allowed       = set_cpus_allowed_common,
#endif
	.set_next_task          = set_next_task_horizon,
	.task_tick		= task_tick_horizon,
	.update_curr		= update_curr_horizon,
	.prio_changed		= prio_changed_horizon,
	.switched_to		= switched_to_horizon,
};
