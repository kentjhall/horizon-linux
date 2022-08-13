#ifndef WATCHDOG_HLD_H
#define WATCHDOG_HLD_H

DECLARE_PER_CPU(unsigned long, hrtimer_interrupts);

#ifdef CONFIG_HARDLOCKUP_DETECTOR_OTHER_CPU
void watchdog_check_hardlockup_other_cpu(void);
#endif /* CONFIG_HARDLOCKUP_DETECTOR_OTHER_CPU */

#endif
