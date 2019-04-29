#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/select.h>
#include <asm-generic/termbits.h>
#include <sys/select.h>

#include "vtty.h"

#define MASTER_PATH "/dev/vtmx"
#define SLAVE_PATH "/dev/ttyV%d"

struct termios2 termios_default = {
	.c_iflag = IGNPAR,
	.c_oflag = 0,
	.c_cflag = CS8 | CLOCAL | CREAD,
	.c_lflag = 0,
	.c_ispeed = B115200,
	.c_ospeed = B115200,
};

int configure_serial(int fd, struct termios2 *ref)
{
	// don't copy everything, the underlying serial port needs to stay RAW
	// even when the virtual port is configured for some processing
	struct termios2 t;
	if(ioctl(fd, TCGETS2, &t)) 
		return 1;

	t.c_cflag = CS8 | CLOCAL | CREAD | (ref->c_cflag & (PARENB|PARODD));
	t.c_iflag = IGNPAR;
	t.c_oflag = 0;
	t.c_lflag = 0;
  
	t.c_cc[VMIN] = 1;
	t.c_cc[VTIME] = 0;
	t.c_ispeed = ref->c_ispeed;
	t.c_ospeed = ref->c_ospeed;

	if(ioctl(fd, TCSETS2, &t)) {
		return 1;
	}

	return 0;
}

int main(int ac, char ** av)
{
	int serial, vtmx, ret, index;

	if(ac != 2) {
		fprintf(stderr, "Usage: %s serialport\n", av[0]);
		return 1;
	}

	serial = open(av[1], O_RDWR|O_NONBLOCK);
	if(serial < 0) {
		fprintf(stderr, "Can't open %s: %m\n", av[1]);
		return 1;
	}

	if(configure_serial(serial, &termios_default)) {
		fprintf(stderr, "Initial serial port configuration failed: %m\n");
		return 1;
	}
	
	vtmx = open(MASTER_PATH, O_RDWR|O_NONBLOCK);
	if(vtmx < 0) {
		fprintf(stderr, "Can't open %s: %m\n", MASTER_PATH);
		return 1;
	}
	
	ret = ioctl(vtmx, VTMX_GET_VTTY_NUM, &index);
	if(ret != 0) {
		fprintf(stderr, "VTMX_GET_VTTY_NUM failed: %m\n");
		return 1;
	}

	fprintf(stderr, "Virtual port ready at " SLAVE_PATH "\n", index);

	fd_set fds;
	int mbits = 0;
	ioctl(serial, TIOCMGET, &mbits);
	ioctl(vtmx, TIOCMSET, &mbits);
	fprintf(stderr, "Initial modem state: %x\n", mbits);

	for(;;) {
		struct {
			char make_space_for_padding_byte;
			struct {
				// ensure that this buffer is properly aligned
				char data[1024];
				struct termios2 termv;
				int intv;
			};
		} bufstruct;

		char *buf = bufstruct.data-1;
		int bufsize = sizeof(bufstruct.data)+1;

		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 1000000/100; // 10ms

		FD_ZERO(&fds);
		FD_SET(serial, &fds);
		FD_SET(vtmx, &fds);
		select(vtmx+1, &fds, NULL, NULL, &tv);

		// Linux doesn't provide a race-free way of polling for modem line changes :(
		int old_mbits = mbits;
		ioctl(serial, TIOCMGET, &mbits);
		if(mbits != old_mbits) {
			fprintf(stderr, "Modem state change: %x\n", mbits);
			ioctl(vtmx, TIOCMSET, &mbits);
		}

		if(FD_ISSET(serial, &fds)) {
			int ret = read(serial, buf, bufsize);
			if(ret > 0) {
				fprintf(stderr, "RX %d bytes\n", ret);
				write(vtmx, buf, ret);
			}
		}

		if(FD_ISSET(vtmx, &fds)) {
			int ret = read(vtmx, buf, bufsize);
			if(ret > 0) {
				if(buf[0] == TAG_UART_RX) {
					write(serial, buf+1, ret-1);
					fprintf(stderr, "TX %d bytes\n", ret-1);

				} else if(buf[0] == TAG_SET_TERMIOS && ret == 1 + sizeof(struct termios2)) {
					configure_serial(serial, &bufstruct.termv);
					fprintf(stderr, "Reconfigure serial port\n");

				} else if(buf[0] == TAG_SET_MODEM && ret == 1 + sizeof(int)) {
					fprintf(stderr, "Set modem lines to %x\n", bufstruct.intv);
					ioctl(serial, TIOCMSET, &bufstruct.intv);

				} else if(buf[0] == TAG_BREAK_CTL && ret == 1 + sizeof(int)) {
					int break_state = bufstruct.intv;
					fprintf(stderr, "Send break: %d\n", break_state);

					if(break_state == -1)
						ioctl(serial, TIOCSBRK, 0); // break on
					else if(break_state == 0)
						ioctl(serial, TIOCCBRK, 0); // break off
					else
						ioctl(serial, TCSBRKP, (break_state+99) / 100 /* deciseconds, round up */); // break pulse
				} else {
					fprintf(stderr, "Unknown message tag %d/%d\n", buf[0], ret);
				}
			}
		}
	}
}
