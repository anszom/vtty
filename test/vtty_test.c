// VTTY test suite
// This file is released to the public domain.
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <termios.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>

#include "vtty.h"

#ifdef TEST_ON_PTY
#define MASTER_PATH "/dev/vpts/ptmx"
#define SLAVE_PATH "/dev/vpts/0"
#else
#define MASTER_PATH "/dev/vtmx"
#define SLAVE_PATH "/dev/ttyV0"
#endif

#include <stdarg.h>
void t_begin(const char *str, ...) 
{
	va_list va;
	va_start(va, str);
	alarm(1);
	vprintf(str, va);
	printf("...");
	fflush(stdout);
	va_end(va);
}

#define t_assert(cond) t_check(cond, "%s:%d " #cond, __FILE__, __LINE__)
#define t_assert_eq(cond, val) do { int __rv = (cond); t_check(__rv == (val), "%s:%d " #cond ": %d != %d", __FILE__, __LINE__, __rv, (val)); } while(0)

void t_check(int cond, const char *str, ...)
{
	if(cond)
		return;

	va_list va;
	va_start(va, str);
	printf("\tFAILED: ");
	vprintf(str, va);
	printf(" (errno:%m)\n");
	va_end(va);
	abort();
}

void t_ok() 
{
	// wait for all junk to finish
	usleep(50000);
	printf("\tOK\n");
	alarm(0);
}

void t1_open_mux_create_slave()
{
	int fd;
	struct stat st;
	t_begin("Opening VTMX creates a VTTY");
	fd = open(MASTER_PATH, O_RDWR);
	t_assert(fd >= 0);

	t_assert(stat(SLAVE_PATH, &st) == 0);
	close(fd);
	t_assert(stat(SLAVE_PATH, &st) != 0);
	t_ok();
}

void t2_mux_return_index()
{
	int mx1, mx2;
	unsigned int rv = ~0;
	t_begin("VTMX_GET_VTTY_NUM returns VTTY index");
	mx1 = open(MASTER_PATH, O_RDWR);
	mx2 = open(MASTER_PATH, O_RDWR);
	t_assert(ioctl(mx1, VTMX_GET_VTTY_NUM, &rv) == 0 && rv == 0);
	t_assert(ioctl(mx2, VTMX_GET_VTTY_NUM, &rv) == 0 && rv == 1);
	close(mx1);
	mx1 = open(MASTER_PATH, O_RDWR);
	t_assert(ioctl(mx1, VTMX_GET_VTTY_NUM, &rv) == 0 && rv == 0);
	close(mx1);
	close(mx2);
	t_ok();
}

void tty_set_raw(int fd)
{
	struct termios t;
	tcgetattr(fd, &t);
	t.c_cflag = CS8 | CLOCAL | CREAD | B115200;
	t.c_iflag = IGNPAR;
	t.c_oflag = 0;
	t.c_lflag = 0;
  
	t.c_cc[VMIN] = 1;
	t.c_cc[VTIME] = 0;
	tcsetattr(fd, TCSANOW, &t);
}

void open_vtmx(int *mx)
{
	*mx = open(MASTER_PATH, O_RDWR);
#ifdef TEST_ON_PTY
	static int zero = 0;
	ioctl(*mx, TIOCSPTLCK, &zero);
#endif
	usleep(10000); // give udev some time
}

void open_vtty(int *tty)
{
	*tty = open(SLAVE_PATH, O_RDWR | O_CLOEXEC | O_NOCTTY);
	t_assert(*tty >= 0);
	tty_set_raw(*tty);
}

void open_pair(int *mx, int *tty)
{
	int rv;
	open_vtmx(mx);
	t_assert(ioctl(*mx, VTMX_GET_VTTY_NUM, &rv) == 0 && rv == 0);
	open_vtty(tty);
}

void t3_mux_write()
{
	int mx, tty;
	char ibuf[16]="0123456789abcdef";
	char obuf[16];
	t_begin("VTMX write -> VTTY read");
	open_pair(&mx, &tty);

	t_assert_eq(write(mx, ibuf, 16), 16);
	t_assert_eq(read(tty, obuf, 16), 16);
	t_assert(!memcmp(ibuf, obuf, 16));
	t_ok();
	close(mx);
	close(tty);
}

void t4_mux_write_noslave()
{
	int mx, tty;
	char ibuf[16]="0123456789abcdef";
	char obuf[16];
	t_begin("VTMX write -> unopened VTTY, data should be buffered");
	open_vtmx(&mx);
	t_assert_eq(write(mx, ibuf, 16), 16);
	open_vtty(&tty);

	t_assert_eq(read(tty, obuf, 16), 16);
	t_assert(!memcmp(ibuf, obuf, 16));
	t_ok();
	close(mx);
	close(tty);
}

int vtmx_read_uart(int mx, char *buf, int len)
{
#ifdef TEST_ON_PTY
	return read(mx, buf, len);
#else
	char _buf[128];
	int rv;
repeat:
	rv = read(mx, _buf, sizeof(_buf));
	if(rv <= 0)
		return rv;
	t_assert(rv != 1);
	if(_buf[0] != TAG_UART_RX)
		goto repeat;

	memcpy(buf, _buf+1, len);
	return rv-1;
#endif
}

void t5_slave_write() 
{
	int mx, tty;
	char ibuf[16]="0123456789abcdef";
	char obuf[16];
	t_begin("VTTY write -> VTMX read, tagged");
	open_pair(&mx, &tty);

	t_assert_eq(write(tty, ibuf, 16), 16);
	t_assert_eq(vtmx_read_uart(mx, obuf, 16), 16);
	t_assert(!memcmp(ibuf, obuf, 16));

	t_ok();
	close(mx);
	close(tty);
}

void nop(int sig) { (void)sig; }
void set_timeout(int ms)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = nop;
	sa.sa_flags = SA_RESETHAND;
	struct itimerval itv = { {0,0}, { 0, ms * 1000 } };
	setitimer(ITIMER_REAL, &itv, NULL);
	sigaction(SIGALRM, &sa, NULL);
}

typedef enum {
	S_BLOCKING,
	S_NONBLOCKING,
	S_POLLED
} syncmode_t;

int select_read(int fd, int timeout_ms)
{
	fd_set fds;
	struct timeval timeout = { .tv_sec=0, .tv_usec=timeout_ms * 1000 };
	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	return select(fd+1, &fds, NULL, NULL, &timeout);
}

int select_write(int fd, int timeout_ms)
{
	fd_set fds;
	struct timeval timeout = { .tv_sec=0, .tv_usec=timeout_ms * 1000 };
	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	return select(fd+1, NULL, &fds, NULL, &timeout);
}

int select_oob(int fd, int timeout_ms)
{
	fd_set fds;
	struct timeval timeout = { .tv_sec=0, .tv_usec=timeout_ms * 1000 };
	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	return select(fd+1, NULL, NULL, &fds, &timeout);
}


static const char *blocking_mode[] = {
	"blocking",
	"nonblocking",
	"polled"
};

static const char *blocking_behaviour[] = {
	"block (& return EINTR)",
	"return EAGAIN",
	"block (& timeout)",
};

void t6_slave_read_block(syncmode_t sync) 
{
	int mx, tty;
	char c;
	t_begin("VTTY %s read should %s when no data is available", blocking_mode[sync], blocking_behaviour[sync]);
	open_pair(&mx, &tty);

	switch(sync) {
	case S_BLOCKING:
		set_timeout(250);
		t_assert_eq(read(tty, &c, 1), -1);
		t_assert(errno == EINTR);
		break;

	case S_NONBLOCKING:
		fcntl(tty, F_SETFL, O_NONBLOCK);
		t_assert_eq(read(tty, &c, 1), -1);
		t_assert(errno == EAGAIN);
		break;

	case S_POLLED:
		t_assert_eq(select_read(tty, 250), 0);
		break;
	}

	t_ok();
	close(mx);
	close(tty);
}

void t7_slave_read_wakeup(syncmode_t sync)
{
	int mx, tty;
	char c = ' ';
	t_begin("VTTY %s read should wake up when data is available", blocking_mode[sync]);
	open_pair(&mx, &tty);

	if(fork()==0) {
		alarm(2);
		// child process
		usleep(100000);
		write(mx, &c, 1);
		_exit(0);
	}

	switch(sync) {
	case S_BLOCKING:
		t_assert_eq(read(tty, &c, 1), 1);
		break;

	case S_POLLED:
		t_assert_eq(select_read(tty, 250), 1);
		break;

	case S_NONBLOCKING:
		abort();
	};

	usleep(100000);
	t_ok();
	close(mx);
	close(tty);
}

void drain(int fd)
{
	int fl = fcntl(fd, F_GETFL);
	char buf[1024];
	fcntl(fd, F_SETFL, O_NONBLOCK);
	while(read(fd, buf, sizeof(buf)) > 0);
	fcntl(fd, F_SETFL, fl);
}

void t8_mux_read_block(syncmode_t sync)
{
	int mx, tty;
	char c;
	t_begin("VTMX %s read should %s when no data is available", blocking_mode[sync], blocking_behaviour[sync]);
	open_pair(&mx, &tty);
	drain(mx);

	switch(sync) {
	case S_BLOCKING:
		set_timeout(250);
		t_assert_eq(vtmx_read_uart(mx, &c, 1), -1);
		t_assert(errno == EINTR);
		break;

	case S_NONBLOCKING:
		fcntl(mx, F_SETFL, O_NONBLOCK);
		t_assert_eq(vtmx_read_uart(mx, &c, 1), -1);
		t_assert(errno == EAGAIN);
		break;

	case S_POLLED:
		t_assert_eq(select_read(mx, 250), 0);
		break;
	}

	t_ok();
	close(mx);
	close(tty);
}

void t9_mux_read_wakeup(syncmode_t sync)
{
	int mx, tty;
	char c;
	t_begin("VTMX %s read should wake up when data is available", blocking_mode[sync]);
	open_pair(&mx, &tty);
	drain(mx);

	if(fork()==0) {
		alarm(2);
		// child process
		usleep(100000);
		write(tty, &c, 1);
		_exit(0);
	}

	switch(sync) {
	case S_BLOCKING:
		t_assert_eq(vtmx_read_uart(mx, &c, 1), 1);
		break;

	case S_POLLED:
		t_assert_eq(select_read(mx, 250), 1);
		break;

	case S_NONBLOCKING:
		abort();
	};

	t_ok();
	usleep(100000);
	close(mx);
	close(tty);
}

void t10_slave_write_block(syncmode_t sync)
{
	int mx, tty;
	char buf[100];
	t_begin("VTTY %s write should %s when queue is full", blocking_mode[sync], blocking_behaviour[sync]);
	open_pair(&mx, &tty);

	switch(sync) {
	case S_BLOCKING:
		for(;;) {
			set_timeout(100);
			int rv = write(tty, buf, sizeof(buf));
			if(rv < 0 && errno == EINTR)
				break;

			if(rv < sizeof(buf)) 
				// short write
				break;

			t_assert_eq(rv, sizeof(buf));
		}
		break;

	case S_NONBLOCKING:
		fcntl(tty, F_SETFL, O_NONBLOCK);
		for(;;) {
			set_timeout(100);
			int rv = write(tty, buf, sizeof(buf));

			if(rv > 0 && rv < sizeof(buf)) {
				// short write, we should hit EAGAIN now
				rv = write(tty, buf, sizeof(buf));
			}

			if(rv < 0 && errno == EAGAIN)
				break;

			t_assert_eq(rv, sizeof(buf));
		}
		break;

	case S_POLLED:
		for(;;) {
			if(select_write(tty, 100) == 0) {
				// timeout => ok
				break;
			}

			set_timeout(100); // write should not fail now, but may be short (only once)
			int rv = write(tty, buf, sizeof(buf));
			t_assert(rv > 0);
			set_timeout(0);

			if(rv < sizeof(buf)) {
				// short write, this should be the last one
				t_assert_eq(select_write(tty, 0), 0);
				break;
			}
		}

#if 0
		// TTY layer is not consistent here
		// select() may return false earlier than the buffers are actually full and write() fails

		t_ok();

		t_begin("VTTY should not accept write when poll(write) returns false");
		// also ensure that writing is not accepted after select() returns false
		fcntl(tty, F_SETFL, O_NONBLOCK);
		t_assert(write(tty, buf, 1) < 0 && errno == EAGAIN);
		fcntl(tty, F_SETFL, 0);
#endif
		break;
	}

	t_ok();

	if(sync != S_NONBLOCKING) {
		t_begin("VTTY %s write should wake up when queue frees up", blocking_mode[sync]);
		int pid;
		if((pid=fork())==0) {
			alarm(2);
			// child process
			usleep(100000);
			while(read(mx, buf, sizeof(buf)) > 0);
			_exit(0);
		}

		if(sync == S_BLOCKING) {
			set_timeout(250);
			t_assert(write(tty, buf, sizeof(buf)) > 0);
		} else { // polled
			t_assert_eq(select_write(tty, 250), 1);
		}
		t_ok();
		kill(pid, SIGKILL);
		usleep(100000);
	}

	close(mx);
	close(tty);
}

void t11_mux_write_block(syncmode_t sync)
{
	int mx, tty;
	char buf[100];
	t_begin("VTMX %s write should %s when queue is full", blocking_mode[sync], blocking_behaviour[sync]);
	open_pair(&mx, &tty);

	switch(sync) {
	case S_BLOCKING:
		for(;;) {
			set_timeout(100);
			int rv = write(mx, buf, sizeof(buf));
			if(rv < 0 && errno == EINTR)
				break;

			if(rv < sizeof(buf)) 
				// short write
				break;

			t_assert_eq(rv, sizeof(buf));
		}
		break;

	case S_NONBLOCKING:
		fcntl(mx, F_SETFL, O_NONBLOCK);
		for(;;) {
			set_timeout(100);
			int rv = write(mx, buf, sizeof(buf));

			if(rv > 0 && rv < sizeof(buf)) {
				// short write, we should hit EAGAIN now
				rv = write(mx, buf, sizeof(buf));
			}

			if(rv < 0 && errno == EAGAIN)
				break;

			t_assert_eq(rv, sizeof(buf));
		}
		break;

	case S_POLLED:
		for(;;) {
			if(select_write(mx, 100) == 0) {
				// timeout => ok
				break;
			}

			set_timeout(100); // write should not fail now, but may be short (only once)
			int rv = write(mx, buf, sizeof(buf));
			t_assert(rv > 0);
			set_timeout(0);

			if(rv < sizeof(buf)) {
				// short write, this should be the last one
				t_assert_eq(select_write(mx, 0), 0);
				break;
			}
		}

#if 0 //ndef TEST_ON_PTY
		// TTY layer is not consistent here
		t_ok();

		t_begin("VTMX should not accept write when poll(write) returns false");
		// also ensure that writing is not accepted after select() returns false
		fcntl(mx, F_SETFL, O_NONBLOCK);
		t_assert(write(mx, buf, 1) < 0 && errno == EAGAIN);
		fcntl(mx, F_SETFL, 0);
#endif
		break;
	}

	t_ok();

	if(sync != S_NONBLOCKING) {
		t_begin("VTMX %s write should wake up when queue frees up", blocking_mode[sync]);
		int pid;
		if((pid=fork())==0) {
			alarm(2);
			// child process
			usleep(100000);
			while(read(tty, buf, sizeof(buf)) > 0);
			_exit(0);
		}

		if(sync == S_BLOCKING) {
			set_timeout(250);
			t_assert(write(mx, buf, sizeof(buf)) > 0);

		} else { // polled
			t_assert_eq(select_write(mx, 250), 1);
		}
		t_ok();
		kill(pid, SIGKILL);
		usleep(100000);
	}

	close(mx);
	close(tty);

}

void t12_close_mux()
{
	int mx, tty;
	char c;
	t_begin("VTTY read should return EOF when VTMX is closed");
	open_pair(&mx, &tty);

	close(mx);
	t_assert_eq(read(tty, &c, 1), 0);

	t_ok();
	close(tty);
}

void t13_close_mux_blocking()
{
	int mx, tty;
	char c;
	t_begin("VTTY read should return -EIO when VTMX is closed during a read");
	open_pair(&mx, &tty);

	if(fork()==0) {
		// child process
		usleep(100000);
		close(mx);
		_exit(0);
	}
	
	close(mx);

	set_timeout(250);
	t_assert_eq(read(tty, &c, 1), -1);
	t_assert(errno == EIO);

	t_ok();
	close(tty);
}

void t14_close_mux_polled()
{
	int mx, tty;
	t_begin("VTTY poll should return readable when VTMX is closed");
	open_pair(&mx, &tty);

	if(fork()==0) {
		// child process
		usleep(100000);
		close(mx);
		_exit(0);
	}
	
	close(mx);

	t_assert_eq(select_read(tty, 250), 1);

	t_ok();
	close(tty);
}

#ifndef TEST_ON_PTY

// this functionality is not present on PTY

void t15_vtty_tcsetattr_vtmx_oob()
{
	int mx, tty;
	struct termios ti;
	char buf[100];
	t_begin("VTTY calls to tcsetattr should be reported on VTMX side");
	open_pair(&mx, &tty);
	drain(mx); // tcsetattr will happen on open

	tcgetattr(tty, &ti);
	tcsetattr(tty, TCSANOW, &ti);

	// TODO: check the termios struct
	t_assert(read(mx, buf, sizeof(buf)) > 0);
	t_assert_eq(buf[0], TAG_SET_TERMIOS);

	t_ok();

	close(mx);
	close(tty);
}

void t16_vtty_mset_vtmx_oob()
{
	int mx, tty;
	char buf[100];
	unsigned int v, w;
	t_begin("VTTY calls to TIOCMSET & friends should be reported on VTMX side");
	open_pair(&mx, &tty);
	drain(mx); // tcsetattr will happen on open

	v = TIOCM_DTR;
	ioctl(tty, TIOCMSET, &v); // reset
	t_assert(read(mx, buf, sizeof(buf)) == 5);
	t_assert_eq(buf[0], TAG_SET_MODEM);
	memcpy(&w, buf+1, 4);
	t_assert_eq(w, TIOCM_DTR);

	v = TIOCM_RTS;
	ioctl(tty, TIOCMBIS, &v); // set
	t_assert(read(mx, buf, sizeof(buf)) == 5);
	t_assert_eq(buf[0], TAG_SET_MODEM);
	memcpy(&w, buf+1, 4);
	t_assert_eq(w, TIOCM_DTR|TIOCM_RTS);

	v = TIOCM_DTR;
	ioctl(tty, TIOCMBIC, &v); // clear
	t_assert(read(mx, buf, sizeof(buf)) == 5);
	t_assert_eq(buf[0], TAG_SET_MODEM);
	memcpy(&w, buf+1, 4);
	t_assert_eq(w, TIOCM_RTS);

	t_ok();

	close(mx);
	close(tty);
}

void t17_vtty_break_vtmx_oob()
{
	int mx, tty;
	char buf[100];
	int v;
	t_begin("VTTY calls to tcsendbreak should be reported on VTMX side");
	open_pair(&mx, &tty);
	drain(mx); // tcsetattr will happen on open

	tcsendbreak(tty, 0);

	t_assert(read(mx, buf, sizeof(buf)) == 5);
	t_assert_eq(buf[0], TAG_BREAK_CTL);
	memcpy(&v, buf+1, 4);
	t_assert(v > 0);

	t_ok();

	close(mx);
	close(tty);
}

void t18_vtmx_oob_not_lost()
{
	int mx, tty;
	char buf[100];
	t_begin("VTMX out-of-band data should not be lost");
	open_pair(&mx, &tty);
	drain(mx); // tcsetattr will happen on open

	// this will block on one side or the other, so we need to test with two processes
	if(fork() == 0) {
		struct termios ti;
		tcgetattr(tty, &ti);
		tcsetattr(tty, TCSANOW, &ti);
		tcsetattr(tty, TCSANOW, &ti);
		_exit(0);
	}

	usleep(100000); // force child process to wait

	t_assert(read(mx, buf, sizeof(buf)) > 0);
	t_assert_eq(buf[0], TAG_SET_TERMIOS);

	usleep(100000); // force child process to wait
	
	t_assert(read(mx, buf, sizeof(buf)) > 0);
	t_assert_eq(buf[0], TAG_SET_TERMIOS);

	usleep(100000);
	t_ok();

	close(mx);
	close(tty);
}

void t19_vtmx_read_wakeup_oob(syncmode_t sync)
{
	int mx, tty;
	char buf[100];
	t_begin("VTMX %s read should wake up when oob events happen on VTTY side", blocking_mode[sync]);
	open_pair(&mx, &tty);
	drain(mx);

	if(fork()==0) {
		alarm(2);
		// child process
		usleep(100000);
		struct termios ti;
		tcgetattr(tty, &ti);
		tcsetattr(tty, TCSANOW, &ti);
		_exit(0);
	}

	switch(sync) {
	case S_BLOCKING:
		t_assert(read(mx, buf, sizeof(buf)) > 0);
		break;

	case S_POLLED:
		t_assert_eq(select_oob(mx, 250), 1);
		break;

	case S_NONBLOCKING:
		abort();
	};

	t_ok();
	usleep(100000);
	close(mx);
	close(tty);
}

void t20_vtmx_mset()
{
	int mx, tty;
	unsigned int a;
	t_begin("VTMX_SET_MODEM_LINES -> VTTY");
	open_pair(&mx, &tty);
	drain(mx);

	a = TIOCM_DTR;
	ioctl(tty, TIOCMSET, &a);
	drain(mx);

	ioctl(tty, TIOCMGET, &a);
	t_assert_eq(a, TIOCM_DTR);

	a = TIOCM_RTS /* should be ignored */ | TIOCM_CTS;
	ioctl(mx, VTMX_SET_MODEM_LINES, &a);
	ioctl(tty, TIOCMGET, &a);

	t_assert_eq(a, TIOCM_DTR | TIOCM_CTS);
	t_ok();
	close(mx);
	close(tty);
}

#endif

int main()
{
	signal(SIGCHLD, SIG_IGN);
	printf("Test using %s\n", MASTER_PATH);
	
	t1_open_mux_create_slave();
	t2_mux_return_index();
	t3_mux_write();
	t4_mux_write_noslave();
	t5_slave_write();
	t6_slave_read_block(S_BLOCKING);
	t6_slave_read_block(S_NONBLOCKING);
	t6_slave_read_block(S_POLLED);
	t7_slave_read_wakeup(S_BLOCKING);
	t7_slave_read_wakeup(S_POLLED);
	t8_mux_read_block(S_BLOCKING);
	t8_mux_read_block(S_NONBLOCKING);
	t8_mux_read_block(S_POLLED);
	t9_mux_read_wakeup(S_BLOCKING);
	t9_mux_read_wakeup(S_POLLED);
	t10_slave_write_block(S_BLOCKING);
	t10_slave_write_block(S_NONBLOCKING);
	t10_slave_write_block(S_POLLED);
	t11_mux_write_block(S_BLOCKING);
	t11_mux_write_block(S_NONBLOCKING);
	t11_mux_write_block(S_POLLED);

	t12_close_mux();

	// there are other variants of this but they all are handled on the tty layer
	// it's more important to test the vtmx endpoint
	t13_close_mux_blocking();
	t14_close_mux_polled();

#ifndef TEST_ON_PTY
	t15_vtty_tcsetattr_vtmx_oob();
	t16_vtty_mset_vtmx_oob();
	t17_vtty_break_vtmx_oob();
	t18_vtmx_oob_not_lost();
	t19_vtmx_read_wakeup_oob(S_BLOCKING);
	t19_vtmx_read_wakeup_oob(S_POLLED);
	t20_vtmx_mset();
#endif
	return 0;
}
