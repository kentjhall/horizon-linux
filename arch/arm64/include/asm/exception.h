/*
 * Based on arch/arm/include/asm/exception.h
 *
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_EXCEPTION_H
#define __ASM_EXCEPTION_H

#include <linux/interrupt.h>

#define __exception	__attribute__((section(".exception.text")))
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
#define __exception_irq_entry	__irq_entry
#else
#define __exception_irq_entry	__exception
#endif

void do_sp_pc_abort(unsigned long addr, unsigned int esr, struct pt_regs *regs);
void bad_el0_sync(struct pt_regs *regs, int reason, unsigned int esr);
void do_cp15instr(unsigned int esr, struct pt_regs *regs);
#ifdef CONFIG_HORIZON
void do_el0_svc(unsigned long esr, struct pt_regs *regs);
void do_el0_svc_compat(unsigned long esr, struct pt_regs *regs);
#endif
#endif	/* __ASM_EXCEPTION_H */
