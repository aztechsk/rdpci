
# rdpci

**rdpci** is a Linux kernel PCI driver (lkm) that enables reading PCI memory areas (BAR's I/O port or I/O memory).

BAR stands for Base Address Register, which is used to define memory-mapped I/O regions).

**rdpci/lkm/rdpci.c** - kernel module.
**rdpci/rdpci/rdpci.c** - userspace application for reading data from /dev/rdpci device file

Example reads 2 bytes from device0 - BAR0 with align 8bit and offset 4.
	jr@dev:~/prj/rdpci/rdpci$ ./rdpci -d 0 -r 0 -s 2 -b 8 -o 4
	Options: BAR0 read_size=2 offset=4 read_align=B8 dev=/dev/rdpci0
	Vendor ID: 0x9710 Device ID: 0x9835 Status: 0x0280
	BAR0 - Size: 8 bytes - Type: I/O port
	hex dump 2 bytes: 0060
