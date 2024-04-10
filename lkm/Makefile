KDIR ?= /lib/modules/$(shell uname -r)/build

FNAME_C := rdpci

PWD            := $(shell pwd)
obj-m          += ${FNAME_C}.o
#EXTRA_CFLAGS   += -DDEBUG

all:
	make -C $(KDIR) M=$(PWD) modules

install:
	make
	sudo make -C $(KDIR) M=$(PWD) modules_install
	sudo depmod

clean:
	make -C $(KDIR) M=$(PWD) clean

checkpatch:
	make clean
	$(KDIR)/scripts/checkpatch.pl --no-tree -f --max-line-length=95 *.[ch]

sa_sparse:
	make clean
	make C=2 CHECK="/usr/bin/sparse" -C $(KDIR) M=$(PWD) modules

sa_gcc:
	make clean
	make CFLAGS="-Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wshadow" -C $(KDIR) M=$(PWD) modules

sa_flawfinder:
	make clean
	flawfinder *.[ch]

sa_cppcheck:
	make clean
	cppcheck -v --force --enable=all --suppress=missingIncludeSystem .
