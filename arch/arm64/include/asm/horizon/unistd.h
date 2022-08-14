// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022
 * Kent Hall <kjh2166@columbia.edu>
 */

#ifndef __SYSCALL
#define __SYSCALL(x, y)
#endif

#define __HNR_set_heap_size			0x01
#define __HNR_set_memory_attribute		0x03
#define __HNR_map_memory			0x04
#define __HNR_unmap_memory			0x05
#define __HNR_query_memory			0x06
#define __HNR_exit_process			0x07
#define __HNR_create_thread			0x08
#define __HNR_start_thread			0x09
#define __HNR_exit_thread			0x0A
#define __HNR_sleep_thread			0x0B
#define __HNR_get_thread_priority		0x0C
#define __HNR_set_thread_priority		0x0D
#define __HNR_set_thread_core_mask		0x0F
#define __HNR_get_current_processor_number	0x10
#define __HNR_clear_event			0x12
#define __HNR_map_shared_memory			0x13
#define __HNR_unmap_shared_memory		0x14
#define __HNR_create_transfer_memory		0x15
#define __HNR_close_handle			0x16
#define __HNR_reset_signal			0x17
#define __HNR_wait_synchronization		0x18
#define __HNR_arbitrate_lock			0x1A
#define __HNR_arbitrate_unlock			0x1B
#define __HNR_wait_process_wide_key_atomic	0x1C
#define __HNR_signal_process_wide_key		0x1D
#define __HNR_get_system_tick			0x1E
#define __HNR_connect_to_named_port		0x1F
#define __HNR_send_sync_request			0x21
#define __HNR_get_thread_id			0x25
#define __HNR_break				0x26
#define __HNR_output_debug_string		0x27
#define __HNR_get_info				0x29
#define __HNR_map_physical_memory		0x2C
#define __HNR_unmap_physical_memory		0x2D

#define __HNR_syscalls				(__HNR_unmap_physical_memory+1)

__SYSCALL(__HNR_set_heap_size, hsys_set_heap_size)
__SYSCALL(__HNR_set_memory_attribute, hsys_set_memory_attribute)
__SYSCALL(__HNR_map_memory, hsys_map_memory)
__SYSCALL(__HNR_unmap_memory, hsys_unmap_memory)
__SYSCALL(__HNR_query_memory, hsys_query_memory)
__SYSCALL(__HNR_exit_process, hsys_exit_process)
__SYSCALL(__HNR_create_thread, hsys_create_thread)
__SYSCALL(__HNR_start_thread, hsys_start_thread)
__SYSCALL(__HNR_exit_thread, hsys_exit_thread)
__SYSCALL(__HNR_sleep_thread, hsys_sleep_thread)
__SYSCALL(__HNR_get_thread_priority, hsys_get_thread_priority)
__SYSCALL(__HNR_set_thread_priority, hsys_set_thread_priority)
__SYSCALL(__HNR_set_thread_core_mask, hsys_set_thread_core_mask)
__SYSCALL(__HNR_get_current_processor_number, hsys_get_current_processor_number)
__SYSCALL(__HNR_clear_event, hsys_clear_event)
__SYSCALL(__HNR_map_shared_memory, hsys_map_shared_memory)
__SYSCALL(__HNR_unmap_shared_memory, hsys_unmap_shared_memory)
__SYSCALL(__HNR_create_transfer_memory, hsys_create_transfer_memory)
__SYSCALL(__HNR_close_handle, hsys_close_handle)
__SYSCALL(__HNR_reset_signal, hsys_reset_signal)
__SYSCALL(__HNR_wait_synchronization, hsys_wait_synchronization)
__SYSCALL(__HNR_arbitrate_lock, hsys_arbitrate_lock)
__SYSCALL(__HNR_arbitrate_unlock, hsys_arbitrate_unlock)
__SYSCALL(__HNR_wait_process_wide_key_atomic, hsys_wait_process_wide_key_atomic)
__SYSCALL(__HNR_signal_process_wide_key, hsys_signal_process_wide_key)
__SYSCALL(__HNR_get_system_tick, hsys_get_system_tick)
__SYSCALL(__HNR_connect_to_named_port, hsys_connect_to_named_port)
__SYSCALL(__HNR_send_sync_request, hsys_send_sync_request)
__SYSCALL(__HNR_get_thread_id, hsys_get_thread_id)
__SYSCALL(__HNR_break, hsys_break)
__SYSCALL(__HNR_output_debug_string, hsys_output_debug_string)
__SYSCALL(__HNR_get_info, hsys_get_info)
__SYSCALL(__HNR_map_physical_memory, hsys_map_physical_memory)
__SYSCALL(__HNR_unmap_physical_memory, hsys_unmap_physical_memory)
