#include <linux/sched/cputime.h>
#include <linux/sched/horizon.h>

#include "sched.h"

#define for_each_queue(rq, high, low, queue)					\
	for ((queue) = (rq)->queue + (high) - HZN_HIGHEST_THREAD_PRIORITY;	\
	     (queue) <= (rq)->queue + (low) - HZN_HIGHEST_THREAD_PRIORITY;	\
	     ++(queue))

#define entity_queue(hzn_rq, entity) \
	((hzn_rq)->queue + ((entity)->priority - HZN_HIGHEST_THREAD_PRIORITY))

static inline struct task_struct *hzn_task_of(struct sched_hzn_entity *entity)
{
	return container_of(entity, struct task_struct, hzn);
}

static inline int hzn_overloaded(struct rq *rq)
{
	return atomic_read(&rq->rd->hzno_count);
}

static inline void hzn_set_overload(struct rq *rq)
{
	if (!rq->online)
		return;

	cpumask_set_cpu(rq->cpu, rq->rd->hzno_mask);
	/*
	 * Make sure the mask is visible before we set
	 * the overload count. That is checked to determine
	 * if we should look at the mask. It would be a shame
	 * if we looked at the mask, but the mask was not
	 * updated yet.
	 *
	 * Matched by the barrier in pull_hzn_task().
	 */
	smp_wmb();
	atomic_inc(&rq->rd->hzno_count);
}

static inline void hzn_clear_overload(struct rq *rq)
{
	if (!rq->online)
		return;

	/* the order here really doesn't matter */
	atomic_dec(&rq->rd->hzno_count);
	cpumask_clear_cpu(rq->cpu, rq->rd->hzno_mask);
}

static void
enqueue_task_horizon(struct rq *rq, struct task_struct *p, int flags)
{
	struct hzn_rq *hzn_rq = &rq->hzn;
	struct sched_hzn_entity *entity = &p->hzn;

	if (++hzn_rq->nr_running > 1)
		hzn_set_overload(rq);
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
	    || unlikely(READ_ONCE(p->__state) == TASK_DEAD)))
		hzn_rq->curr = NULL;

	entity->rq = NULL;
	if (hzn_rq->nr_running) {
		if (--hzn_rq->nr_running <= 1)
			hzn_clear_overload(rq);
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
			return hzn_task_of(hzn_rq->curr);
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
	return hzn_rq->curr ? hzn_task_of(hzn_rq->curr) : NULL;
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

	schedstat_set(curr->stats.exec_max,
		      max(curr->stats.exec_max, delta_exec));

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
select_task_rq_horizon(struct task_struct *p, int cpu, int flags)
{
	if (p->hzn.state != HZN_SWITCHABLE)
		return task_cpu(p);

	return cpu;
}

static inline bool need_pull_hzn_task(struct rq *rq, struct task_struct *prev)
{
	/* Try to pull Horizon tasks here if we had a task defer */
	return rq->online && rq->hzn.curr != &prev->hzn;
}

static int pick_hzn_task(struct rq *rq, struct task_struct *p, int cpu)
{
	if (!task_running(rq, p) &&
	    cpumask_test_cpu(cpu, &p->cpus_mask))
		return 1;

	return 0;
}

/*
 * Return the highest pushable rq's task, which is suitable to be executed
 * on the CPU, NULL otherwise
 */
static struct task_struct *pick_highest_pushable_task(struct rq *rq, int cpu)
{
	struct hzn_rq *hzn_rq = &rq->hzn;
	struct sched_hzn_entity *entity;
	struct list_head *queue;

	if (!hzn_rq->curr)
		return NULL;

	for_each_queue(hzn_rq,
		       hzn_rq->curr->priority + 1, HZN_LOWEST_THREAD_PRIORITY,
		       queue) {
		if (list_empty(queue))
			continue;

		entity = list_first_entry(queue, struct sched_hzn_entity, list);

		// this would mean that curr is on the wrong queue somehow
		BUG_ON(hzn_rq->curr == entity);

		if (pick_hzn_task(rq, hzn_task_of(entity), cpu))
			return hzn_task_of(entity);
	}

	return NULL;
}

static void pull_hzn_task(struct rq *this_rq)
{
	int this_cpu = this_rq->cpu, cpu;
	bool resched = false;
	struct task_struct *p, *push_task;
	struct rq *src_rq;
	int hzn_overload_count = hzn_overloaded(this_rq);

	if (likely(!hzn_overload_count))
		return;

	/*
	 * Match the barrier from rt_set_overloaded; this guarantees that if we
	 * see overloaded we must also see the hzno_mask bit.
	 */
	smp_rmb();

	/* If we are the only overloaded CPU do nothing */
	if (hzn_overload_count == 1 &&
	    cpumask_test_cpu(this_rq->cpu, this_rq->rd->hzno_mask))
		return;

	for_each_cpu(cpu, this_rq->rd->hzno_mask) {
		if (this_cpu == cpu)
			continue;

		src_rq = cpu_rq(cpu);

		/*
		 * We can potentially drop this_rq's lock in
		 * double_lock_balance, and another CPU could
		 * alter this_rq
		 */
		push_task = NULL;
		double_lock_balance(this_rq, src_rq);

		/*
		 * If there are no more pullable tasks on the
		 * rq, we're done with it.
		 */
		if (src_rq->hzn.nr_running <= 1)
			goto skip;

		/*
		 * We can pull only a task, which is pushable
		 * on its rq, and no others.
		 */
		p = pick_highest_pushable_task(src_rq, this_cpu);

		/*
		 * Do we have a Horizon task that's likely to be scheduled?
		 */
		if (p &&
		    (!this_rq->hzn.curr ||
		     p->hzn.priority <= this_rq->hzn.curr->priority)) {
			WARN_ON(p == src_rq->curr);
			WARN_ON(!task_on_rq_queued(p));

			if (is_migration_disabled(p)) {
				push_task = get_push_task(src_rq);
			} else {
				deactivate_task(src_rq, p, 0);
				set_task_cpu(p, this_cpu);
				activate_task(this_rq, p, 0);
				resched = true;
			}
			/*
			 * We continue with the search, just in
			 * case there's an even higher prio task
			 * in another runqueue. (low likelihood
			 * but possible)
			 */
		}
skip:
		double_unlock_balance(this_rq, src_rq);

		if (push_task) {
			raw_spin_rq_unlock(this_rq);
			stop_one_cpu_nowait(src_rq->cpu, push_cpu_stop,
					    push_task, &src_rq->push_work);
			raw_spin_rq_lock(this_rq);
		}
	}

	if (resched)
		resched_curr(this_rq);
}

static int
balance_horizon(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
	if (!prev->hzn.rq && need_pull_hzn_task(rq, prev)) {
		/*
		 * This is OK, because current is on_cpu, which avoids it being
		 * picked for load-balance and preemption/IRQs are still
		 * disabled avoiding further scheduler activity on it and we've
		 * not yet started the picking loop.
		 */
		rq_unpin_lock(rq, rf);
		pull_hzn_task(rq);
		rq_repin_lock(rq, rf);
	}
	return sched_stop_runnable(rq) || sched_dl_runnable(rq) ||
	       sched_rt_runnable(rq) || sched_fair_runnable(rq) ||
	       sched_hzn_runnable(rq);
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

DEFINE_SCHED_CLASS(hzn) = {

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
