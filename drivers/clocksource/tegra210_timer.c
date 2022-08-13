/*
 * Copyright (c) 2014-2017, NVIDIA CORPORATION.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/clk.h>
#include <linux/clockchips.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/percpu.h>
#include <linux/syscore_ops.h>
#include <linux/version.h>

static u32 tegra210_timer_freq;
static void __iomem *tegra210_timer_reg_base;
static u32 usec_config;
static u32 timer_us_mult, timer_us_shift;

#define TIMER_PTV		0x0
#define TIMER_PTV_EN		BIT(31)
#define TIMER_PTV_PER		BIT(30)
#define TIMER_PCR		0x4
#define TIMER_PCR_INTR_CLR	BIT(30)
#define TIMERUS_CNTR_1US	0x10
#define TIMERUS_USEC_CFG	0x14

#define TIMER10_OFFSET		0x90

#define TIMER_FOR_CPU(cpu) (TIMER10_OFFSET + (cpu) * 8)

struct tegra210_clockevent {
	struct clock_event_device evt;
	char name[20];
	void __iomem *reg_base;
	struct irqaction irq_action;
	bool irq_requested;
};
#define to_tegra_cevt(p) (container_of(p, struct tegra210_clockevent, evt))

static DEFINE_PER_CPU(struct tegra210_clockevent, tegra210_evt);

static int tegra210_timer_set_next_event(unsigned long cycles,
					 struct clock_event_device *evt)
{
	struct tegra210_clockevent *tevt;

	tevt = to_tegra_cevt(evt);
	writel(TIMER_PTV_EN |
	       ((cycles > 1) ? (cycles - 1) : 0), /* n+1 scheme */
	       tevt->reg_base + TIMER_PTV);
	return 0;
}

static inline void timer_shutdown(struct tegra210_clockevent *tevt)
{
	writel(0, tevt->reg_base + TIMER_PTV);
}

static int tegra210_timer_shutdown(struct clock_event_device *evt)
{
	struct tegra210_clockevent *tevt;

	tevt = to_tegra_cevt(evt);
	timer_shutdown(tevt);
	return 0;
}

static int tegra210_timer_set_periodic(struct clock_event_device *evt)
{
	struct tegra210_clockevent *tevt;

	tevt = to_tegra_cevt(evt);
	writel(TIMER_PTV_EN | TIMER_PTV_PER | ((tegra210_timer_freq / HZ) - 1),
	       tevt->reg_base + TIMER_PTV);
	return 0;
}

static irqreturn_t tegra210_timer_isr(int irq, void *dev_id)
{
	struct tegra210_clockevent *tevt;

	tevt = dev_id;
	writel(TIMER_PCR_INTR_CLR, tevt->reg_base + TIMER_PCR);
	tevt->evt.event_handler(&tevt->evt);
	return IRQ_HANDLED;
}

static int tegra210_timer_setup(unsigned int cpu)
{
	struct tegra210_clockevent *tevt = &per_cpu(tegra210_evt, cpu);
	int ret;

	if (!tevt->irq_requested) {
		ret = setup_irq(tevt->evt.irq, &tevt->irq_action);
		if (ret) {
			pr_err("%s: cannot setup irq %d for CPU%d\n",
				__func__, tevt->evt.irq, cpu);
			return -EPERM;
		}
		irq_force_affinity(tevt->evt.irq, cpumask_of(cpu));
		tevt->irq_requested = true;
	} else {
		irq_force_affinity(tevt->evt.irq, cpumask_of(cpu));
		enable_irq(tevt->evt.irq);
	}

	clockevents_config_and_register(&tevt->evt, tegra210_timer_freq,
					1, /* min */
					0x1fffffff); /* 29 bits */
	return 0;
}

static int tegra210_timer_stop(unsigned int cpu)
{
	struct tegra210_clockevent *tevt = &per_cpu(tegra210_evt, cpu);

	tevt->evt.set_state_shutdown(&tevt->evt);
	disable_irq_nosync(tevt->evt.irq);

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
static int tegra210_timer_cpu_notify(struct notifier_block *self,
				     unsigned long action, void *hcpu)
{
	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_STARTING:
		tegra210_timer_setup(smp_processor_id());
		break;
	case CPU_DYING:
		tegra210_timer_stop(smp_processor_id());
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block tegra210_timer_cpu_nb = {
	.notifier_call = tegra210_timer_cpu_notify,
};
#endif

static int tegra_timer_suspend(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		void __iomem *reg_base = tegra210_timer_reg_base +
					 TIMER_FOR_CPU(cpu);
		writel(TIMER_PCR_INTR_CLR, reg_base + TIMER_PCR);
	}
	return 0;
}

static void tegra_timer_resume(void)
{
	writel(usec_config, tegra210_timer_reg_base + TIMERUS_USEC_CFG);
}

static struct syscore_ops tegra_timer_syscore_ops = {
	.suspend = tegra_timer_suspend,
	.resume = tegra_timer_resume,
};

static void __init tegra210_timer_init(struct device_node *np)
{
	int cpu;
	struct tegra210_clockevent *tevt;
	struct clk *clk;

	tegra210_timer_reg_base = of_iomap(np, 0);
	if (!tegra210_timer_reg_base) {
		WARN(1, "Can't map timer registers\n");
		return;
	}

	clk = of_clk_get(np, 0);
	if (IS_ERR(clk)) {
		WARN(1, "Unable to get timer clock.\n");
		return;
	}
	clk_prepare_enable(clk);
	tegra210_timer_freq = clk_get_rate(clk);

	for_each_possible_cpu(cpu) {
		tevt = &per_cpu(tegra210_evt, cpu);
		tevt->reg_base = tegra210_timer_reg_base + TIMER_FOR_CPU(cpu);
		tevt->evt.irq = irq_of_parse_and_map(np, cpu);
		if (!tevt->evt.irq) {
			pr_err("%s: can't map IRQ for CPU%d\n",
			       __func__, cpu);
			BUG();
		}

		snprintf(tevt->name, ARRAY_SIZE(tevt->name),
			 "tegra210_timer%d", cpu);
		tevt->evt.name = tevt->name;
		tevt->evt.cpumask = cpumask_of(cpu);
		tevt->evt.set_next_event = tegra210_timer_set_next_event;
		tevt->evt.set_state_shutdown = tegra210_timer_shutdown;
		tevt->evt.set_state_periodic = tegra210_timer_set_periodic;
		tevt->evt.set_state_oneshot = tegra210_timer_shutdown;
		tevt->evt.tick_resume = tegra210_timer_shutdown;
		tevt->evt.features = CLOCK_EVT_FEAT_PERIODIC |
			CLOCK_EVT_FEAT_ONESHOT;

		/* want to be preferred over arch timers */
		tevt->evt.rating = 460;

		tevt->irq_action.name = tevt->evt.name;
		tevt->irq_action.flags = IRQF_TIMER | IRQF_NOBALANCING;
		tevt->irq_action.handler = tegra210_timer_isr;
		tevt->irq_action.dev_id = tevt;
	}

	/*
	 * Configure microsecond timers to have 1MHz clock
	 * Config register is 0xqqww, where qq is "dividend", ww is "divisor"
	 * Uses n+1 scheme
	 */
	switch (tegra210_timer_freq) {
	case 12000000:
		usec_config = 0x000b; /* (11+1)/(0+1) */
		break;
	case 12800000:
		usec_config = 0x043f; /* (63+1)/(4+1) */
		break;
	case 13000000:
		usec_config = 0x000c; /* (12+1)/(0+1) */
		break;
	case 16800000:
		usec_config = 0x0453; /* (83+1)/(4+1) */
		break;
	case 19200000:
		usec_config = 0x045f; /* (95+1)/(4+1) */
		break;
	case 26000000:
		usec_config = 0x0019; /* (25+1)/(0+1) */
		break;
	case 38400000:
		usec_config = 0x04bf; /* (191+1)/(4+1) */
		break;
	case 48000000:
		usec_config = 0x002f; /* (47+1)/(0+1) */
		break;
	default:
		BUG();
	}

	writel(usec_config, tegra210_timer_reg_base + TIMERUS_USEC_CFG);
	clocks_calc_mult_shift(&timer_us_mult, &timer_us_shift,
				tegra210_timer_freq, USEC_PER_SEC, 0);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
	/* boot cpu is online */
	tegra210_timer_setup(0);

	if (register_cpu_notifier(&tegra210_timer_cpu_nb)) {
		WARN(1, "Cannot setup CPU notifier\n");
		return;
	}
#else
	cpuhp_setup_state(CPUHP_AP_TEGRA_TIMER_STARTING,
			  "AP_TEGRA_TIMER_STARTING", tegra210_timer_setup,
			  tegra210_timer_stop);
#endif

	register_syscore_ops(&tegra_timer_syscore_ops);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
#define tegra210_timer_init_func tegra210_timer_init
#else
static int __init tegra210_timer_init_ret(struct device_node *np)
{
	tegra210_timer_init(np);
	return 0;
}
#define tegra210_timer_init_func tegra210_timer_init_ret
#endif

CLOCKSOURCE_OF_DECLARE(tegra210_timer, "nvidia,tegra210-timer",
		       tegra210_timer_init_func);
