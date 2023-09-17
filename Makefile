KVERSION ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVERSION)/build

modules: vtty.c vtty.h
	$(MAKE) -C $(KDIR) M=$(PWD) modules

modules_install: modules
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -A
	@if ! getent group dialout > /dev/null; then echo "Warning: group 'dialout' not found, not installing udev rules"; exit 1; fi
	install -m 644 50-vtty.rules /usr/lib/udev/rules.d

all: modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
