// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022
 * Kent Hall <kjh2166@columbia.edu>
 */

#include <linux/horizon.h>
#include <asm/processor.h>

#undef	horizon_hdr_check_arch
#define	horizon_hdr_check_arch(hdr)	(!(hdr->is_64bit))

#undef	horizon_set_personality
#define	horizon_set_personality()		\
({					\
	set_thread_flag(TIF_32BIT);	\
})

#undef	start_thread
#define	start_thread		compat_start_thread

/*
 * Rename a few of the symbols that binfmt_horizon.c will define.
 * These are all local so the names don't really matter, but it
 * might make some debugging less confusing not to duplicate them.
 */
#define horizon_format		compat_horizon_format
#define init_horizon_binfmt		init_compat_horizon_binfmt
#define exit_horizon_binfmt		exit_compat_horizon_binfmt

/*
 * We share all the actual code with the native (64-bit) version.
 */
#include "binfmt_horizon.c"
