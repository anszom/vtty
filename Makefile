KVERSION ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVERSION)/build

modules: vtty.c vtty.h
	$(MAKE) -C $(KDIR) M=$(PWD) modules

modules_install: modules
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	install -m 644 50-vtty.rules /usr/lib/udev/rules.d

all: modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
