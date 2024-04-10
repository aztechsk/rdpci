/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * rdpci_ioctl
 *
 * Copyright (c) 2024 Jan Rusnak <jan@rusnak.sk>
 */

#ifndef RDPCI_IOCTL_H
#define RDPCI_IOCTL_H

enum rdpci_read_align {
	RDPCI_READ_ALIGN_8,
	RDPCI_READ_ALIGN_16,
	RDPCI_READ_ALIGN_32,
};

struct rdpci_ioctl_bar {
	int bar;
	enum rdpci_read_align read_align;
	int bar_size; // ret
	unsigned long flags; // ret
};

#define IOCTL_RDPCI_MAGIC 0xB2
#define	IOCTL_RDPCI_MAXIOCTL 4

// Map BARn to kvm and return bar memory size
#define IOCTL_RDPCI_MAP_BAR _IOWR(IOCTL_RDPCI_MAGIC, 0, struct rdpci_ioctl_bar)
// PCI read config
#define IOCTL_RDPCI_CFG_BYTE _IOWR(IOCTL_RDPCI_MAGIC, 1, unsigned int)
#define IOCTL_RDPCI_CFG_WORD _IOWR(IOCTL_RDPCI_MAGIC, 2, unsigned int)
#define IOCTL_RDPCI_CFG_DWORD _IOWR(IOCTL_RDPCI_MAGIC, 3, unsigned int)

#endif
