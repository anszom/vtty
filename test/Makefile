all: vtty_test pty_test portmirror

%: %.c ../vtty.h
	gcc -o $@ $^ -I .. -Wall

pty_test: vtty_test.c ../vtty.h
	gcc -o $@ $^ -I .. -Wall -DTEST_ON_PTY

