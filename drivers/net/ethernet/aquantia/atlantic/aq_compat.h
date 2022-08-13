/*
 * aQuantia Corporation Network Driver
 * Copyright (C) 2014-2017 aQuantia Corporation. All rights reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 */

/* File aq_compat.h: Backward compat with previous linux kernel versions */

#ifndef AQ_COMPAT_H
#define AQ_COMPAT_H

#include <linux/version.h>

#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a,b) (((a) << 8) + (b))
#endif

#ifndef RHEL_RELEASE_CODE
#define RHEL_RELEASE_CODE 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)

#define from_timer(var, callback_timer, timer_fieldname) \
	container_of(callback_timer, typeof(*var), timer_fieldname)

static inline void timer_setup(struct timer_list *timer,
			       void (*callback)(struct timer_list *),
			       unsigned int flags)
{
	setup_timer(timer, (void (*)(unsigned long))callback, (unsigned long)timer);
}

#endif

#ifndef SPEED_5000
#define SPEED_5000 5000
#endif

#ifndef ETH_MIN_MTU
#define ETH_MIN_MTU	68
#endif

#ifndef SKB_ALLOC_NAPI
static inline struct sk_buff *napi_alloc_skb(struct napi_struct *napi, unsigned int length)
{
	return netdev_alloc_skb_ip_align(napi->dev, length);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
/* from commit 1dff8083a024650c75a9c961c38082473ceae8cf */
#define page_to_virt(x)	__va(PFN_PHYS(page_to_pfn(x)))
#endif	/* 4.7.0 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)

#if !(RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,2)))
/* from commit fe896d1878949ea92ba547587bc3075cc688fb8f */
static inline void page_ref_inc(struct page *page)
{
	atomic_inc(&page->_count);
}

static inline int page_ref_count(struct page *page)
{
	return atomic_read(&page->_count);
}
#endif

#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)) && !(RHEL_RELEASE_CODE)

/* from commit 286ab723d4b83d37deb4017008ef1444a95cfb0d */
static inline void ether_addr_copy(u8 *dst, const u8 *src)
{
	memcpy(dst, src, 6);
}
#endif /* 3.14.0 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)

/* introduced in commit 56193d1bce2b2759cb4bdcc00cd05544894a0c90
 * pull the whole head buffer len for now*/
#define eth_get_headlen(__data, __max_len) (__max_len)

/* ->xmit_more introduced in commit
 * 0b725a2ca61bedc33a2a63d0451d528b268cf975 for 3.18-rc1 */
static inline int skb_xmit_more(struct sk_buff *skb)
{
	return 0;
}

#else /* 3.18.0 */
static inline int skb_xmit_more(struct sk_buff *skb)
{
	return skb->xmit_more;
}

#endif	/* 3.18.0 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
#define IFF_UNICAST_FLT        0
#define dev_alloc_pages(__order) alloc_pages_node(NUMA_NO_NODE,                         \
                                                  GFP_ATOMIC | __GFP_COMP | __GFP_COLD, \
                                                  __order)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
/* introduced in commit 71dfda58aaaf4bf6b1bc59f9d8afa635fa1337d4 */
#define dev_alloc_pages(__order) __skb_alloc_pages(GFP_ATOMIC | __GFP_COMP, NULL, __order)
#endif  /* 3.19.0 */

#endif /* AQ_COMMON_H */
