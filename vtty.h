// This file is released to the public domain.
// I doubt that that there is anything copyrightable here anyway...
#ifndef _VTTY_H
#define _VTTY_H

#define TAG_UART_RX 	(0)
#define TAG_SET_TERMIOS	(1)
#define TAG_SET_MODEM 	(2)
#define TAG_BREAK_CTL 	(3)

#include <asm/ioctl.h>

// vtmx-side ioctls
// can't be bothered to invent own ioctl numbers
#define VTMX_GET_VTTY_NUM (TIOCGPTN)
#define VTMX_SET_MODEM_LINES (TIOCMSET)

#endif
