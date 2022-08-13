/*
 * Copyright (C) 2015 Google, Inc.
 * Copyright (c) 2016-2017, NVIDIA CORPORATION. All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#ifndef __LINUX_TRUSTY_TRUSTY_IPC_H
#define __LINUX_TRUSTY_TRUSTY_IPC_H

/*
 * Errnos below must be in sync with the corresponding errnos
 * defined in 3rdparty/trusty/external/lk/include/err.h
 */
#define NO_ERROR                (0)
#define ERR_NOT_FOUND           (-2)

struct tipc_chan;

struct tipc_msg_buf {
	void *buf_va;
	phys_addr_t buf_pa;
	size_t buf_sz;
	size_t wpos;
	size_t rpos;
	struct list_head node;
};

enum tipc_chan_event {
	TIPC_CHANNEL_CONNECTED = 1,
	TIPC_CHANNEL_DISCONNECTED,
	TIPC_CHANNEL_SHUTDOWN,
	TIPC_CHANNEL_NOT_FOUND,
};

struct tipc_chan_ops {
	void (*handle_event)(void *cb_arg, int event);
	struct tipc_msg_buf *(*handle_msg)(void *cb_arg,
					   struct tipc_msg_buf *mb);
	void (*handle_release)(void *cb_arg);
};

struct tipc_chan *tipc_create_channel(struct device *dev,
				      const struct tipc_chan_ops *ops,
				      void *cb_arg);

int tipc_chan_connect(struct tipc_chan *chan, const char *port);

int tipc_chan_queue_msg(struct tipc_chan *chan, struct tipc_msg_buf *mb);

int tipc_chan_shutdown(struct tipc_chan *chan);

void tipc_chan_destroy(struct tipc_chan *chan);

struct tipc_msg_buf *tipc_chan_get_rxbuf(struct tipc_chan *chan);

void tipc_chan_put_rxbuf(struct tipc_chan *chan, struct tipc_msg_buf *mb);

struct tipc_msg_buf *
tipc_chan_get_txbuf_timeout(struct tipc_chan *chan, long timeout);

void tipc_chan_put_txbuf(struct tipc_chan *chan, struct tipc_msg_buf *mb);

static inline size_t mb_avail_space(struct tipc_msg_buf *mb)
{
	return mb->buf_sz - mb->wpos;
}

static inline size_t mb_avail_data(struct tipc_msg_buf *mb)
{
	return mb->wpos - mb->rpos;
}

static inline void *mb_put_data(struct tipc_msg_buf *mb, size_t len)
{
	void *pos = (u8 *)mb->buf_va + mb->wpos;
	BUG_ON(mb->wpos + len > mb->buf_sz);
	mb->wpos += len;
	return pos;
}

static inline void *mb_get_data(struct tipc_msg_buf *mb, size_t len)
{
	void *pos = (u8 *)mb->buf_va + mb->rpos;
	BUG_ON(mb->rpos + len > mb->wpos);
	mb->rpos += len;
	return pos;
}

/* OTE-TIPC wrapper APIs*/
/*
 * te_open_trusted_session - Establishes the session with TA
 * @name(in): name of the TA to connect to.
 * @ctx(out): pointer to the private data associated to the open session
 * Returns 0 on Success else error code.
 */
int te_open_trusted_session(char *name, void **ctx);
/*
 * te_close_trusted_session - Closes the session established
 * @ctx: ctx returned by open session
 */
void te_close_trusted_session(void *ctx);
/*
 * te_launch_trusted_oper - Communicate with TA to perform any operation
 * @buf: Buffer to sent to secure world.
 * @buf_len: length of the buffer.
 * @ta_cmd: command to sent to secure world.
 * @ctx: ctx returned by open session.
 * Returns 0 on Success else error code.
 */
int te_launch_trusted_oper(void *buf, size_t buf_len, uint32_t ta_cmd,
		void *ctx);

#endif /* __LINUX_TRUSTY_TRUSTY_IPC_H */

