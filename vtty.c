/*
 * 	VTTY - virtual serial port driver
 *
 * 	(C) 2019 Andrzej Szombierski <qq@kuku.eu.org>
 *
 * 	Based loosely on pty & various serial drivers from the Linux kernel.
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/mutex.h>
#include <linux/miscdevice.h>
#include <linux/circ_buf.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/poll.h>
#include <linux/version.h>

#include "vtty.h"

// FIXME tty_port_tty_get refcounting needed?

// borrowed from serial_core.h
#define VTTY_XMIT_SIZE  PAGE_SIZE
#define WAKEUP_CHARS 256

#define vtty_circ_empty(circ)	   ((circ)->head == (circ)->tail)
#define vtty_circ_clear(circ)	   ((circ)->head = (circ)->tail = 0)

#define vtty_circ_chars_pending(circ)   \
	(CIRC_CNT((circ)->head, (circ)->tail, VTTY_XMIT_SIZE))

#define vtty_circ_chars_free(circ)      \
	(CIRC_SPACE((circ)->head, (circ)->tail, VTTY_XMIT_SIZE))
// --

#define VTTY_MAX 	(16)

static struct tty_driver *vtty_driver;

static bool user_break_timing = true;
static char* tty_name_template = "ttyV";
static char* mux_name = "vtmx";

#ifndef TCGETS2
#error "This code is not adapted to run on an arch lacking TCGETS2/termios2"
#endif

union vtty_oob_data {
	struct ktermios termios;
	struct termios2 user_termios; // used only for sizeof
	unsigned int modem_lines;
	int break_val;
};

// protects creation/destruction of tty ports
// per-port data is protected by the tty spinlock
static struct mutex portlock;

struct vtty_port {
	struct tty_port port;
	struct circ_buf xmit;
	struct device *dev;
	struct tty_struct *tty;

	int oob_tag;
	union vtty_oob_data oob_data;
	size_t oob_size;

	unsigned int modem_state;
	bool master_is_open;

	wait_queue_head_t read_wait, write_wait; // read/write from vtmx perspective
	wait_queue_head_t oob_wait; // vtty-side ioctl => vtmx-side read
};
static struct vtty_port ports[VTTY_MAX];

static void vtty_destroy_port(int index);

static int vtty_open(struct tty_struct *tty, struct file *filp)
{
	int ret = 0;
	struct vtty_port *vtty = &ports[tty->index];
	mutex_lock(&portlock);
	if(vtty->dev) {
		dev_dbg(tty->dev, "%s enter\n", __func__);
		vtty->tty = tty;

		// just like pty_open, we keep the tty in the THROTTLED state permanently
		// this will cause the ldisc layer to call vtty_unthrottle whenever the
		// free space is above the watermark
		set_bit(TTY_THROTTLED, &tty->flags);

		// push buffered data out
		tty_flip_buffer_push(&vtty->port);

		dev_dbg(tty->dev, "%s exit\n", __func__);
	} else {
		// race between vtmx_release() & vtty_open()
		ret = -EIO;
	}

	mutex_unlock(&portlock);
	return ret;
}

static void vtty_close(struct tty_struct *tty, struct file *filp)
{
	struct vtty_port *vtty = &ports[tty->index];

	mutex_lock(&portlock);

	dev_dbg(tty->dev, "%s enter\n", __func__);

	vtty->tty = NULL;

	if (! vtty->master_is_open)
		vtty_destroy_port(tty->index);

	dev_dbg(tty->dev, "%s exit\n", __func__);

	mutex_unlock(&portlock);

	return;
}

static int vtty_write(struct tty_struct *tty, const unsigned char *buf, int count)
{
	// the TTY layer manages -EAGAIN and (non-)blocking writes
	struct vtty_port *port = &ports[tty->index];
	struct circ_buf *circ = &port->xmit;
	unsigned long flags;
	int ret = 0;

	dev_dbg(tty->dev, "%s enter\n", __func__);

	spin_lock_irqsave(&port->port.lock, flags);

	while (1) {
		int c = CIRC_SPACE_TO_END(circ->head, circ->tail, VTTY_XMIT_SIZE);
		if (count < c)
			c = count;

		if (c == 0) {
			break;
		}
		memcpy(circ->buf + circ->head, buf, c);
		circ->head = (circ->head + c) & (VTTY_XMIT_SIZE - 1);
		buf += c;
		count -= c;
		ret += c;
	}

	wake_up_interruptible_sync_poll(&port->read_wait, POLLIN | POLLRDNORM);
	spin_unlock_irqrestore(&port->port.lock, flags);

	dev_dbg(tty->dev, "%s written %d (cste=%d)\n", __func__, ret, CIRC_SPACE_TO_END(circ->head, circ->tail, VTTY_XMIT_SIZE));
	dev_dbg(tty->dev, "%s exit\n", __func__);

	return ret;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(5,6,0)
static unsigned int vtty_write_room(struct tty_struct *tty)
#else
static int vtty_write_room(struct tty_struct *tty)
#endif
{
	struct vtty_port *port = &ports[tty->index];
	struct circ_buf *circ = &port->xmit;
	unsigned long flags;
	unsigned int ret;

	dev_dbg(tty->dev, "%s enter\n", __func__);

	spin_lock_irqsave(&port->port.lock, flags);
	ret = vtty_circ_chars_free(circ);
	spin_unlock_irqrestore(&port->port.lock, flags);

	dev_dbg(tty->dev, "write room = %d\n", ret);
	dev_dbg(tty->dev, "%s exit\n", __func__);

	return ret;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(5,6,0)
static unsigned int vtty_chars_in_buffer(struct tty_struct *tty)
#else
static int vtty_chars_in_buffer(struct tty_struct *tty)
#endif
{
	struct vtty_port *port = &ports[tty->index];
	struct circ_buf *circ = &port->xmit;
	unsigned long flags;
	unsigned int ret;

	dev_dbg(tty->dev, "%s enter\n", __func__);

	spin_lock_irqsave(&port->port.lock, flags);
	ret = vtty_circ_chars_pending(circ);
	spin_unlock_irqrestore(&port->port.lock, flags);

	dev_dbg(tty->dev, "%s exit\n", __func__);

	return ret;
}


// call with port spinlock
static int vtty_wait_oob(struct vtty_port *port, unsigned long *pflags)
{
	DEFINE_WAIT(wait);

	dev_dbg(port->tty->dev, "%s enter\n", __func__);

	while(port->oob_size != 0) {
		if (signal_pending(current))
			return -ERESTARTSYS;

		prepare_to_wait(&port->oob_wait, &wait, TASK_INTERRUPTIBLE);
		spin_unlock_irqrestore(&port->port.lock, *pflags);
		schedule();
		finish_wait(&port->oob_wait, &wait);
		spin_lock_irqsave(&port->port.lock, *pflags);
	}

	dev_dbg(port->tty->dev, "%s exit\n", __func__);

	return 0;
}

static void vtty_do_queue_oob(struct vtty_port *port, int tag, void *data, size_t len)
{
	port->oob_tag = tag;
	memcpy(&port->oob_data, data, port->oob_size = len);
	wake_up_interruptible_sync_poll(&port->read_wait, POLLIN | POLLRDNORM);
}

static int vtty_queue_oob(struct vtty_port *port, int tag, void *data, size_t len)
{
	int ret = 0;
	unsigned long flags;

	dev_dbg(port->tty->dev, "%s enter\n", __func__);

	spin_lock_irqsave(&port->port.lock, flags);
	ret = vtty_wait_oob(port, &flags);

	if(ret == 0)
		vtty_do_queue_oob(port, tag, data, len);

	spin_unlock_irqrestore(&port->port.lock, flags);

	dev_dbg(port->tty->dev, "%s exit\n", __func__);

	return ret;
}

static void vtty_set_termios(struct tty_struct *tty, struct ktermios *old_termios)
{
	struct vtty_port *port = &ports[tty->index];

	dev_dbg(tty->dev, "%s enter\n", __func__);

	// this may sleep
	vtty_queue_oob(port, TAG_SET_TERMIOS, &tty->termios, sizeof(tty->termios));

	dev_dbg(tty->dev, "%s exit\n", __func__);
}

static void vtty_throttle(struct tty_struct *tty)
{
	dev_dbg(tty->dev, "%s\n", __func__);
}

static void vtty_unthrottle(struct tty_struct *tty)
{
	struct vtty_port *port = &ports[tty->index];

	dev_dbg(tty->dev, "%s enter\n", __func__);

	wake_up_interruptible_sync_poll(&port->write_wait, POLLOUT | POLLWRNORM);
	set_bit(TTY_THROTTLED, &tty->flags); 	// just like pty_unthrottle

	dev_dbg(tty->dev, "%s exit\n", __func__);
}

static int vtty_tiocmget(struct tty_struct *tty)
{
	struct vtty_port *port = &ports[tty->index];
	unsigned long flags;
	unsigned int ret;

	dev_dbg(tty->dev, "%s enter\n", __func__);

	spin_lock_irqsave(&port->port.lock, flags);
	ret = port->modem_state;
	spin_unlock_irqrestore(&port->port.lock, flags);

	dev_dbg(tty->dev, "%s exit\n", __func__);

	return ret;
}

static int vtty_tiocmset(struct tty_struct *tty, unsigned int set, unsigned int clear)
{
	struct vtty_port *port = &ports[tty->index];
	unsigned long flags;
	int ret;

	dev_dbg(tty->dev, "%s enter\n", __func__);

	spin_lock_irqsave(&port->port.lock, flags);
	ret = vtty_wait_oob(port, &flags);

	if(ret == 0) {
		port->modem_state = (port->modem_state | set) & (~clear);

		dev_dbg(tty->dev, "new modem state %x (%x %x)\n", port->modem_state, set, clear);

		vtty_do_queue_oob(port, TAG_SET_MODEM, &port->modem_state, sizeof(port->modem_state));
	}

	spin_unlock_irqrestore(&port->port.lock, flags);

	dev_dbg(tty->dev, "%s exit\n", __func__);

	return ret;
}

static int vtty_break_ctl(struct tty_struct *tty, int state)
{
	struct vtty_port *port = &ports[tty->index];

	dev_dbg(tty->dev, "%s enter\n", __func__);

	// state = -1 	-> on
	// state = 0 	-> off
	// state > 0 	-> on for X ms
	vtty_queue_oob(port, TAG_BREAK_CTL, &state, sizeof(state));

	dev_dbg(tty->dev, "%s exit\n", __func__);

	return 0;
}

static const struct tty_operations vtty_ops = {
	.open = vtty_open,
	.close = vtty_close,
	.write = vtty_write,
	.write_room = vtty_write_room,
	.chars_in_buffer = vtty_chars_in_buffer,
	.set_termios = vtty_set_termios,
	.throttle = vtty_throttle,
	.unthrottle = vtty_unthrottle,
	.tiocmget = vtty_tiocmget,
	.tiocmset = vtty_tiocmset,
	.break_ctl = vtty_break_ctl,
};

static int vtty_create_port(int index)
{
	struct vtty_port *port = &ports[index];
	struct device *dev;
	unsigned long page;
	int ret = 0;

	pr_debug("%s %s port[%d] enter\n", module_name(THIS_MODULE), __func__, (int)index);

	memset(port, 0, sizeof(*port));
	tty_port_init(&port->port);
	tty_buffer_set_limit(&port->port, 8192);

	page = get_zeroed_page(GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto fail_destroy;
	}

	port->xmit.buf = (unsigned char *) page;
	vtty_circ_clear(&port->xmit);

	dev = tty_port_register_device(&port->port, vtty_driver, index, NULL);

	if(IS_ERR(dev)) {
		ret = PTR_ERR(dev);
		goto fail_free;
	}

	init_waitqueue_head(&port->read_wait);
	init_waitqueue_head(&port->write_wait);
	init_waitqueue_head(&port->oob_wait);
	port->dev = dev;

	pr_debug("%s %s port[%d] exit\n", module_name(THIS_MODULE), __func__, (int)index);

	return 0;

fail_free:
	free_page((unsigned long)port->xmit.buf);
	port->xmit.buf = NULL;

fail_destroy:
	tty_port_destroy(&port->port);

	pr_debug("%s %s port[%d] err exit\n", module_name(THIS_MODULE), __func__, (int)index);

	return ret;
}

// called with portlock
static void vtty_destroy_port(int index)
{
	struct vtty_port *port = &ports[index];
//	unsigned long flags;
//	spin_lock_irqsave(&port->port.lock, flags);
//	spin_unlock_irqrestore(&port->port.lock, flags);

	pr_debug("%s %s port[%d] enter\n", module_name(THIS_MODULE), __func__, (int)index);

	tty_port_unregister_device(&port->port, vtty_driver, index);

	free_page((unsigned long)port->xmit.buf);
	port->xmit.buf = NULL;

	port->dev = NULL;
	tty_port_destroy(&port->port);

	pr_debug("%s %s port[%d] exit\n", module_name(THIS_MODULE), __func__, (int)index);
}

static int vtty_find_free_port(void)
{
	int i;
	for(i=0;i < VTTY_MAX;i++)
		if(!ports[i].dev)
			return i;
	return -ENOSPC;
}

static int vtmx_open(struct inode *nodp, struct file *filp)
{
	int rv = 0;
	int index;

	pr_debug("%s %s enter\n", module_name(THIS_MODULE), __func__);

	nonseekable_open(nodp, filp);

	/* We refuse fsnotify events on vtmx, since it's a shared resource */
	filp->f_mode |= FMODE_NONOTIFY;

	mutex_lock(&portlock);
	index = vtty_find_free_port();
	if(index < 0) {
		rv = index;
		goto fail_unlock;
	}

	rv = vtty_create_port(index);
	if(rv < 0)
		goto fail_unlock;

	ports[index].master_is_open = true;
	filp->private_data = &ports[index];

	pr_debug("%s %s port %d created\n", module_name(THIS_MODULE), __func__, index);

	mutex_unlock(&portlock);

	pr_debug("%s %s exit\n", module_name(THIS_MODULE), __func__);

	return rv;

fail_unlock:
	mutex_unlock(&portlock);

	pr_debug("%s %s err exit\n", module_name(THIS_MODULE), __func__);

	return rv;
}

static int vtmx_release (struct inode *nodp, struct file *filp)
{
	int idx;
	struct vtty_port *port = filp->private_data;

	mutex_lock(&portlock);

	idx = port - ports;

	pr_debug("%s %s port[%d] enter\n", module_name(THIS_MODULE), __func__, (int)idx);

	if(port->tty) {
		set_bit(TTY_IO_ERROR, &port->tty->flags);
		wake_up_interruptible(&port->read_wait);
		wake_up_interruptible(&port->write_wait);
	}

	if(port->tty) {
		// FIXME locking?
		set_bit(TTY_OTHER_CLOSED, &port->tty->flags);
		wake_up_interruptible(&port->read_wait);
		wake_up_interruptible(&port->write_wait);
	}

	if(port->tty) {
		tty_vhangup(port->tty);
		wake_up_interruptible(&port->read_wait);
		wake_up_interruptible(&port->write_wait);
	}

	port->master_is_open = false;

	if (!port->tty)
		vtty_destroy_port(idx);

	mutex_unlock(&portlock);

	pr_debug("%s %s port[%d] exit\n", module_name(THIS_MODULE), __func__, idx);

	return 0;
}

static ssize_t vtmx_read (struct file *filp, char __user *ptr, size_t size, loff_t *off)
{
	struct vtty_port *port = filp->private_data;
	struct circ_buf *circ = &port->xmit;
	unsigned long flags;
	int ret = 0;
	DEFINE_WAIT(wait);

	if(size < 1 + sizeof(union vtty_oob_data))
		return -EMSGSIZE; // don't bother with clueless userspace apps

	pr_debug("%s %s port[%d] enter\n", module_name(THIS_MODULE), __func__, (int)(port - ports));

	spin_lock_irqsave(&port->port.lock, flags);

#if 0
	// FIXME tty->stopped (handling xon/xoff)
	// FIXME if (file->f_flags & O_NONBLOCK) {
	if(vtty_circ_empty(circ)/* || uart_tx_stopped */) {
		//?
		ret = 0;
		goto out;
	}
#endif
	pr_debug("%s %s port[%d] read(%d)\n", module_name(THIS_MODULE), __func__, (int)(port - ports), (int)size);

	while(size > 0) {
		int c;

		pr_debug("%s %s port[%d] (size=%d ret=%d)\n", module_name(THIS_MODULE), __func__, (int)(port - ports), (int)size, (int)ret);

		if(ret == 0) {
			// oob
			if(port->oob_size > 0) {
				char tag = (char)port->oob_tag;
				int copystatus;

				pr_debug("%s %s port[%d] -> oob %d\n", module_name(THIS_MODULE), __func__, (int)(port - ports), tag);

				if(copy_to_user(ptr, &tag, 1)) {
					ret = -EFAULT;
					break;
				}

				ptr++;
				ret++;
				size--;

				if(tag == TAG_SET_TERMIOS) {
					copystatus = kernel_termios_to_user_termios((struct termios2 __user*)ptr, &port->oob_data.termios);
					ret += sizeof(struct termios2);
				} else {
					copystatus = copy_to_user(ptr, &port->oob_data, port->oob_size);
					ret += port->oob_size;
				}

				if(copystatus) {
					ret = -EFAULT;
					break;
				}

				port->oob_size = 0;
				wake_up_interruptible_sync(&port->oob_wait);
				break;
			}
		}

		// normal data, or wait for events
		c = CIRC_CNT_TO_END(circ->head, circ->tail, VTTY_XMIT_SIZE);

		pr_debug("%s %s port[%d] -> circ=%d\n", module_name(THIS_MODULE), __func__, (int)(port - ports), c);

		if(c == 0) {
			if(ret > 0)
				break;

			if(filp->f_flags & O_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}

			if (signal_pending(current)) {
				if (ret == 0)
					ret = -ERESTARTSYS;
				break;
			}

			prepare_to_wait(&port->read_wait, &wait, TASK_INTERRUPTIBLE);
			spin_unlock_irqrestore(&port->port.lock, flags);
			schedule();
			finish_wait(&port->read_wait, &wait);
			spin_lock_irqsave(&port->port.lock, flags);
			continue;
		}

		if(ret == 0) {
			// insert tag byte first
			char tag = TAG_UART_RX;
			if(copy_to_user(ptr, &tag, 1)) {
				ret = -EFAULT;
				break;
			}

			ret = 1;
			++ptr;
			--size;
		}

		if(c > size)
			c = size;

		if(copy_to_user(ptr, circ->buf + circ->tail, c)) {
			ret = -EFAULT;
			break;
		}

		ret += c;
		ptr += c;
		size -= c;
		circ->tail = (circ->tail + c) & (VTTY_XMIT_SIZE - 1);
	}

	spin_unlock_irqrestore(&port->port.lock, flags);

	mutex_lock(&portlock);
	if (vtty_circ_chars_pending(circ) < WAKEUP_CHARS) {
		if(port->tty) {
			dev_dbg(port->tty->dev, "%s tty_wakeup\n", __func__);
			tty_wakeup(port->tty);
		} else {
			pr_debug("%s %s port[%d] no tty_wakeup\n", module_name(THIS_MODULE), __func__, (int)(port - ports));
		}
	}

	mutex_unlock(&portlock);

	pr_debug("%s %s port[%d] exit\n", module_name(THIS_MODULE), __func__, (int)(port - ports));

	return ret;
}

static ssize_t vtmx_write (struct file *filp, const char __user *ptr, size_t size, loff_t *off)
{
	struct vtty_port *port = filp->private_data;
	char temp_buffer[256];
	ssize_t written = 0;
	int ret = 0;
	DEFINE_WAIT(wait);

	pr_debug("%s %s port[%d] enter (%d %d)\n", module_name(THIS_MODULE), __func__, (int)(port - ports), (int)size, (int)tty_buffer_space_avail(&port->port));

	while(size > 0) {
		size_t tmp_size = size;
		if(tmp_size > sizeof(temp_buffer))
			tmp_size = sizeof(temp_buffer);

		if (copy_from_user(temp_buffer, ptr, tmp_size)) {
			ret = -EFAULT;
			break;
		}

		if(tty_buffer_space_avail(&port->port) == 0)
			tmp_size = 0;

		/*
		if(test_bit(TTY_THROTTLED, &port->tty->flags)) {
			// this would be required for consistency with poll(), but real ttys don't follow this
			// this means that write() can succeed even if poll() claims that it wouldn't
			pr_debug("vtmx write throttled\n");
			tmp_size = 0;
		} else */

		tmp_size = tty_insert_flip_string(&port->port, temp_buffer, tmp_size);

		// tty_insert_flip_string can return zero if the buffers are full
		// however tty_buffer_space_avail will return zero much earlier, so poll() results will be
		// somewhat consistent. Otherwise we would need to set a flag now so that poll() knows
		// that the buffer space has really ran out.

		if(tmp_size == 0) {
			if(written > 0)
				break;

			if(filp->f_flags & O_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}

			if (signal_pending(current)) {
				if (ret == 0)
					ret = -ERESTARTSYS;
				break;
			}

			prepare_to_wait(&port->write_wait, &wait, TASK_INTERRUPTIBLE);
//			spin_unlock_irqrestore(&port->port.lock, flags);
			schedule();
			finish_wait(&port->write_wait, &wait);
//			spin_lock_irqsave(&port->port.lock, flags);
			continue;
		}


		written += tmp_size;
		size -= tmp_size;
		ptr += tmp_size;
	}

	if(written > 0)
		tty_flip_buffer_push(&port->port);

	pr_debug("%s %s port[%d] exit %d %d %d\n", module_name(THIS_MODULE), __func__, (int)(port - ports), (int)written, (int)ret, (int)tty_buffer_space_avail(&port->port));

	if(ret)
		return ret;

	return written;
}

// FIXME POLLHUP ?
static unsigned int vtmx_poll(struct file *filp, poll_table *wait)
{
	unsigned int mask = 0;
	struct vtty_port *port = filp->private_data;
	struct circ_buf *circ = &port->xmit;
	unsigned long flags;

	pr_debug("%s %s port[%d] enter\n", module_name(THIS_MODULE), __func__, (int)(port - ports));

	poll_wait(filp, &port->read_wait, wait);
	poll_wait(filp, &port->write_wait, wait);

	spin_lock_irqsave(&port->port.lock, flags);
	// is there anything to read?
	if(CIRC_CNT_TO_END(circ->head, circ->tail, VTTY_XMIT_SIZE) > 0)
		mask |= POLLIN | POLLRDNORM;

	// any oob data?
	if(port->oob_size > 0)
		mask |= POLLIN | POLLRDNORM | POLLPRI;

	if(tty_buffer_space_avail(&port->port) > 0)
		mask |= POLLOUT | POLLWRNORM;

	spin_unlock_irqrestore(&port->port.lock, flags);

	pr_debug("%s %s port[%d] exit (%d, %d) 0x%x\n", module_name(THIS_MODULE), __func__, (int)(port - ports), (int)CIRC_CNT_TO_END(circ->head, circ->tail, VTTY_XMIT_SIZE), (int)port->oob_size, (int)mask);

	return mask;
}

#define ALLOWED_STATES (~(TIOCM_DTR|TIOCM_RTS|TIOCM_OUT1|TIOCM_OUT2|TIOCM_LOOP))

static int vtty_modem_state_set(struct vtty_port *port, unsigned int __user *arg)
{
	unsigned long flags;
	int ret;
	unsigned int mstate;

	pr_debug("%s %s port[%d] enter\n", module_name(THIS_MODULE), __func__, (int)(port - ports));

	spin_lock_irqsave(&port->port.lock, flags);

	ret = get_user(mstate, arg);
	port->modem_state = (port->modem_state & (~ALLOWED_STATES)) | (mstate & ALLOWED_STATES);

	spin_unlock_irqrestore(&port->port.lock, flags);

	pr_debug("%s %s port[%d] exit\n", module_name(THIS_MODULE), __func__, (int)(port - ports));

	return ret;
}

static long vtmx_ioctl(struct file * filp, unsigned int cmd, unsigned long arg)
{
	struct vtty_port *port = filp->private_data;

	pr_debug("%s %s %s on port %d\n", module_name(THIS_MODULE), __func__, (cmd == VTMX_GET_VTTY_NUM ? "VTMX_GET_VTTY_NUM" : (cmd == VTMX_SET_MODEM_LINES) ? "VTMX_SET_MODEM_LINES" : "(unknown)"), (int)(port - ports));

	switch(cmd) {
	case VTMX_GET_VTTY_NUM:
		return put_user((port - ports), (unsigned int __user *)arg);

	case VTMX_SET_MODEM_LINES:
		return vtty_modem_state_set(port, (unsigned int __user*)arg);
	}
	return -ENOIOCTLCMD;
}

static struct file_operations vtmx_fops = {
	.owner 		= THIS_MODULE,
	.llseek		= no_llseek,
	.read		= vtmx_read,
	.write		= vtmx_write,
	.poll		= vtmx_poll,
	.unlocked_ioctl	= vtmx_ioctl,
	.open		= vtmx_open,
	.release	= vtmx_release,

};

static struct miscdevice* vtmx_miscdev = NULL;

static int __init vtty_init(void)
{
	static struct miscdevice vtmx_miscdev_data;
	int ret = 0;
	unsigned long driver_flags = 0;

	vtmx_miscdev_data.minor = MISC_DYNAMIC_MINOR;
	vtmx_miscdev_data.name = mux_name;
	vtmx_miscdev_data.fops = &vtmx_fops;

	vtmx_miscdev = &vtmx_miscdev_data;

	ret = misc_register(vtmx_miscdev);

	if(ret)
		goto fail;

	driver_flags = TTY_DRIVER_RESET_TERMIOS |
			TTY_DRIVER_REAL_RAW |
			TTY_DRIVER_DYNAMIC_DEV;

	if (user_break_timing)
		driver_flags |= TTY_DRIVER_HARDWARE_BREAK;

	vtty_driver = tty_alloc_driver(VTTY_MAX, driver_flags);

	if(!vtty_driver) {
		ret = -ENOMEM;
		goto fail_deregister;
	}

	vtty_driver->driver_name = module_name(THIS_MODULE);
	vtty_driver->name = tty_name_template;
	vtty_driver->type = TTY_DRIVER_TYPE_SERIAL;
	vtty_driver->subtype = SERIAL_TYPE_NORMAL;
	vtty_driver->init_termios = tty_std_termios;

	tty_set_operations(vtty_driver, &vtty_ops);
	ret = tty_register_driver(vtty_driver);
	if(ret)
		goto fail_put;

	memset(ports, 0, sizeof(ports));

	mutex_init(&portlock);

	pr_info("%s initialized\n", vtty_driver->driver_name);
	pr_debug("%s mux device is %s, virtual tty template is %s\n", module_name(THIS_MODULE), mux_name, tty_name_template);

	return ret;

fail_put:
	tty_driver_kref_put(vtty_driver);

fail_deregister:
	misc_deregister(vtmx_miscdev);

fail:
	return ret;
}

static void __exit vtty_exit(void)
{
	pr_debug("%s removing\n", module_name(THIS_MODULE));

	mutex_destroy(&portlock);
	tty_unregister_driver(vtty_driver);
	tty_driver_kref_put(vtty_driver);
	misc_deregister(vtmx_miscdev);

	pr_info("%s removed\n", module_name(THIS_MODULE));
}

module_param(user_break_timing, bool, 0444);
MODULE_PARM_DESC(user_break_timing, " set N, if the userspace vtty provider/master cannot do break signal timing, defaults to Y");
module_param(tty_name_template, charp, 0444);
MODULE_PARM_DESC(tty_name_template, " the vtty slave name template for the vtty's, defaults to 'ttyV'");
module_param(mux_name, charp, 0444);
MODULE_PARM_DESC(mux_name, " the vtty master name, defaults to 'vtmx'");

module_init(vtty_init);
module_exit(vtty_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrzej Szombierski <qq@kuku.eu.org>");
MODULE_DESCRIPTION("Virtual serial port driver.");
