KVERSION ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVERSION)/build

all: vtty.c
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
