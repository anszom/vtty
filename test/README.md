VTTY test & example apps
========================

This directory contains several apps developed for testing the VTTY interface.

- **vtty_test** - a basic set of "unit" tests. Requires the vtty module to be loaded and not used by other software.
- **pty_test** - the same test suite as vtty_tests (built from the same source file), but executed against the regular PTY interface. This was used to
  ensure basic compatibility between VTTY & PTY. Requires a separate "instance" of the pseudo-tty filesystem to be mounted and not used by other software
  (mount devpts /dev/vpts -t devpts -o newinstance).
- **portmirror** - opens a regular serial port and clones it on a VTTY. The cloned port should behave identically as
  the regular one. Obviously, when portmirror is running, it will interfere with access to the regular serial port.
