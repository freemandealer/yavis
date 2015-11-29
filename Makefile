ifneq ($(KERNELRELEASE),)
kbuild part of makefile
include Kbuild

else
	KDIR := /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=`pwd` modules

.PHONY: clean
clean:
	$(MAKE) -C $(KDIR) M=`pwd` clean

endif
