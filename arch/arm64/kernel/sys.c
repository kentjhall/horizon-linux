/*
 * AArch64-specific system calls implementation
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
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

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <asm/cpufeature.h>
#include <asm/esr.h>

asmlinkage long sys_mmap(unsigned long addr, unsigned long len,
			 unsigned long prot, unsigned long flags,
			 unsigned long fd, off_t off)
{
	if (offset_in_page(off) != 0)
		return -EINVAL;

	return sys_mmap_pgoff(addr, len, prot, flags, fd, off >> PAGE_SHIFT);
}

SYSCALL_DEFINE1(arm64_personality, unsigned int, personality)
{
	if (personality(personality) == PER_LINUX32 &&
		!system_supports_32bit_el0())
		return -EINVAL;
	return sys_personality(personality);
}

#ifdef CONFIG_HORIZON
asmlinkage long __hsys_ni_syscall(u64 reg0, u64 reg1, u64 reg2, u64 reg3,
		u64 reg4, u64 reg5, int scno);

asmlinkage long hsys_ni_syscall(u64 reg0, u64 reg1, u64 reg2, u64 reg3,
				u64 reg4, u64 reg5)
{
	return __hsys_ni_syscall(reg0, reg1, reg2, reg3, reg4, reg5,
			read_sysreg(esr_el1) & ESR_ELx_xVC_IMM_MASK);
}
#endif

/*
 * Wrappers to pass the pt_regs argument.
 */
asmlinkage long sys_rt_sigreturn_wrapper(void);
#define sys_rt_sigreturn	sys_rt_sigreturn_wrapper
#define sys_personality		sys_arm64_personality

#ifndef CONFIG_HORIZON
#define __NO_HORIZON
#endif

#include <asm/horizon/unistd.h> // for __HNR_syscalls

#undef __SYSCALL
#define __SYSCALL(nr, sym)	[nr] = sym,

/*
 * The sys_call_table array must be 4K aligned to be accessible from
 * kernel/entry.S.
 */
void * const sys_call_table[__NR_syscalls] __aligned(4096) = {
	[0 ... __NR_syscalls - 1] = sys_ni_syscall,
#include <asm/unistd.h>
};

#ifdef CONFIG_HORIZON
void * const horizon_sys_call_table[__HNR_syscalls] __aligned(4096) = {
	[0 ... __HNR_syscalls - 1] = hsys_ni_syscall,
#include <asm/horizon/unistd.h>
};
#endif
