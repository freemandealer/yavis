ifneq ($(KERNELRELEASE),)
kbuild part of makefile
include Kbuild

else
#	KDIR := /lib/modules/`uname -r`/build
	KDIR := debug/linux-2.6.32.65

default:
	$(MAKE) -C $(KDIR) M=`pwd` modules
	scp yavis.ko freeman@192.168.61.132:/home/freeman

.PHONY: clean
clean:
	$(MAKE) -C $(KDIR) M=`pwd` clean

endif
