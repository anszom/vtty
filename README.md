Virtual Serial Port driver for Linux
====================================

This kernel module allows userspace programs to create virtual serial ports under /dev/ttyV#.

This is somewhat similar to the regular pseudo-tty interface, but vtty also emulates characteristics
such as baud rate & modem line state. This allows users to create a fully-functional serial port
driver completely in userspace. 

Possible uses:
- forward a serial port over the network. There are several Linux implementations of a RFC2217 server.
  VTTY allows you to write a RFC2217 client exposing a native-looking serial port to other software.
- quickly prototype a driver for an USB-to-serial converter using VTTY & libusb
- split one physical serial port in two, allowing two apps to access it without conflict (for example
  gdb & minicom, or esptool & minicom)


Userspace interface
-------------------

The module creates a **/dev/vtmx** "master" device, which is used to create the virtual serial ports in a
manner similar to the pseudo-tty master device /dev/ptmx. Opening the **/dev/vtmx** device causes a
**/dev/ttyV#** device to be allocated. The index of the virtual port can be obtained by issuing a 
**VTMX_GET_VTTY_NUM** (equal to TIOCGPTN) ioctl on the vtmx file descriptor. 

Any writes on the vtmx file descriptor will appear as incoming data on the virtual TTY, subject to the
regular in-kernel processing (line disciplines, echoing, and so on). Reading from vtmx will return data
in a "packetized" format, inspired by the obscure pseudo-tty "packet" mode. On each successful read() call, 
the first byte returned will indicate the type of packet returned.

Currently supported packet formats:

- **TAG_UART_RX** (0), followed by the "serial port" data coming in from the virtual TTY (processed by the kernel as usual)
- **TAG_SET_TERMIOS** (1), followed by a 'struct termios2' structure representing the serial port configuration requested on the virtual TTY (TCSETS/TCSETS2)
- **TAG_SET_MODEM** (2),  followed by a 32-bit integer representing the modem line state requested on the virtual TTY (TIOCMSET/TIOCMBIC/TIOCMBIS)
- **TAG_BREAK_CTL** (3), followed by a 32-bit integer representing the requested "break" state. A "break" state is a special condition on the serial port, during which the "low" signal state is sent for a period longer than the byte duration. A positive number indicates the duration of the requested break state (in milliseconds). Negative numbers indicate a request to set the break state indefinitely. Zero terminates the break state.

The master side can also use the **VTMX_SET_MODEM_LINES** ioctl (equal to TIOCMSET) to manipulate the modem line state of the virtual serial port.
Only the "input" lines (such as CTS) can be changed this way. If the master process needs to change the "output" lines (such as RTS), it needs to
open the **ttyV#** device and issue the regular tty ioctls there.

The test/ directory contains testing/example apps demonstrating the use of the interface.


Comparison with PTY
-------------------

Most of the functionality of VTTY is inspired by and follows the PTY interfaces. Most notable differences
include:

- The "master" side of the pseudo-tty is a tty. I'm not really sure why and what would be the reason
  to (for example) configure the line discipline on the master side. After all, it's only used to read &
  write some bytes. In VTTY, the master side is a simple character device.

- PTY does not inform the master of the "termios" settings on the slave

- PTY does not support setting modem lines on the slave

- VTTY reads on the master side return the data prefixed with a "tag" byte. This is similar to the
  (rarely used) "packet" mode of the pseudo-ttys.

- PTY supports locking/unlocking access to the pseudo-tty using TIOCSPTLCK. This is not supported in VTTY


Build for user-mode linux
-------------------------

For debugging purposes, any kind of virtualization etc., it is possible to use this module also in user-mode linux.

Therefor you can "cross-compile" it like any other architecture, as a user mode module.

When you built your um-kernel in ``~/user-mode-linux/build_uml-$(uname -r)``, then you can build this module like this:

```
$ cd vtty
$ make KDIR=~/user-mode-linux/build_uml-$(uname -r) ARCH=um
```


Known bugs
----------

Any kinds of flow control were not tested. I assume that XON/XOFF will not work.

The module is mostly stable, but I wouldn't recommend running it on any "important" systems.
I wouldn't be surprised if there were some subtle locking bugs remaining (the linux tty layer is... complex).

Also see FIXME/TODO markers in the source code.

Some tty ioctls are not supported (notably TIOCMIWAIT & TIOCGICOUNT).

Similar projects
---------------

[tty0tty](https://github.com/freemed/tty0tty) emulates pairs of serial ports, connected in a null-modem fashion.
The modem status lines are properly emulated, but the "termios" settings are not.
