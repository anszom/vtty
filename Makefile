obj-m := vtty.o
KVERSION := $(shell uname -r)

all: vtty.c
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
