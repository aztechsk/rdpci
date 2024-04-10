/*
 * rdpci.c
 *
 * Copyright (c) 2024 Jan Rusnak <jan@rusnak.sk>
 */

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdbool.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <signal.h>
#include "../lkm/rdpci_ioctl.h"
#include "pci_regs.h"

#define IORESOURCE_IO 0x00000100
#define IORESOURCE_MEM 0x00000200

static struct rdpci_ioctl_bar ioctl_bar;
static char *mem_buf;
static int dev_file = -1;
static char dev_path[13] = "/dev/rdpci";
static int read_size;
static int fpos;

static void dump_hex(const char buf[static 1], int size);
static void parse_options(int argc, char **argv);
static void on_exit_clean(int code, void *p);
static void logmsg(int prio, ...);

/**
 * main
 */
int main(int argc, char **argv)
{
	if (0 != on_exit(on_exit_clean, NULL)) {
		logmsg(LOG_ERR, "Register on_exit_clean() fail.\n");
		exit(EXIT_FAILURE);
	}
	if (setvbuf(stdout, NULL, _IOLBF, 0)) {
		logmsg(LOG_ERR, "setvbuf() fail.\n");
		exit(EXIT_FAILURE);
	}
	if (setvbuf(stderr, NULL, _IOLBF, 0)) {
		logmsg(LOG_ERR, "setvbuf() fail.\n");
		exit(EXIT_FAILURE);
	}
	parse_options(argc, argv);
	dev_file = open(dev_path, O_RDONLY);
	if (dev_file == -1) {
		logmsg(LOG_ERR, "Open file \"%s\" fail. %s.\n", dev_path, strerror(errno));
		exit(EXIT_FAILURE);
	}
	unsigned int vendor, device, status;
	vendor = PCI_VENDOR_ID;
	if (ioctl(dev_file, IOCTL_RDPCI_CFG_WORD, &vendor) < 0) {
		logmsg(LOG_ERR, "ioctl() on \"%s\" fail. %s.\n", dev_path, strerror(errno));
		exit(EXIT_FAILURE);
	}
	device = PCI_DEVICE_ID;
	if (ioctl(dev_file, IOCTL_RDPCI_CFG_WORD, &device) < 0) {
		logmsg(LOG_ERR, "ioctl() on \"%s\" fail. %s.\n", dev_path, strerror(errno));
		exit(EXIT_FAILURE);
	}
	status = PCI_STATUS;
	if (ioctl(dev_file, IOCTL_RDPCI_CFG_WORD, &status) < 0) {
		logmsg(LOG_ERR, "ioctl() on \"%s\" fail. %s.\n", dev_path, strerror(errno));
		exit(EXIT_FAILURE);
	}
	logmsg(LOG_INFO, "Vendor ID: 0x%04X Device ID: 0x%04X Status: 0x%04X\n", vendor, device, status);
	if (ioctl(dev_file, IOCTL_RDPCI_MAP_BAR, &ioctl_bar) < 0) {
		logmsg(LOG_ERR, "ioctl() on \"%s\" fail. %s.\n", dev_path, strerror(errno));
		exit(EXIT_FAILURE);
	}
	logmsg(LOG_INFO, "BAR%d - Size: %d bytes - Type: %s\n", ioctl_bar.bar, ioctl_bar.bar_size, (ioctl_bar.flags & IORESOURCE_IO) ? "I/O port" : "I/O memory");
	if (fpos) {
		off_t off = lseek(dev_file, fpos, SEEK_SET);
		if (off == -1) {
			logmsg(LOG_ERR, "lseek() on \"%s\" fail. %s.\n", dev_path, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	mem_buf = calloc(read_size, 1);
	int rcnt = read(dev_file, mem_buf, read_size);
	if (rcnt == -1) {
		logmsg(LOG_ERR, "read() on \"%s\" fail. %s.\n", dev_path, strerror(errno));
		exit(EXIT_FAILURE);
	}
	dump_hex(mem_buf, rcnt);
	exit(EXIT_SUCCESS);
}

/**
 * dump_hex
 */
static void dump_hex(const char buf[static 1], int size)
{
	printf("hex dump %d %s:\n", size, (size == 1) ? "byte" : "bytes");
	for (int i = 0, m = 0; i < size; ++i, ++m) {
		printf("%02X", buf[i]);
		if (i == size - 1) {
			break;
		}
		if (m % 2) {
			if (m == 15) {
				if (i != size - 1) {
					printf("\n");
				}
				m = -1;
			} else {
				if (m == 3 || m == 7 || m == 11) {
					printf(" ");
				} else {
					printf(":");
				}
			}
		}
	}
	printf("\n");
}

/**
 * parse_options
 */
static void parse_options(int argc, char **argv)
{
	int c;
	int devn;
	const char *d = NULL, *r = NULL, *s = NULL, *b = NULL, *o = NULL;

	opterr = 0;
	while ((c = getopt(argc, argv, ":d:r:s:b:o:")) != -1) {
		switch (c) {
		case 'd' :
			d = optarg;
			break;
		case 'r' :
			r = optarg;
			break;
		case 's' :
			s = optarg;
			break;
		case 'b' :
			b = optarg;
			break;
		case 'o' :
			o = optarg;
			break;
		case '?' :
			if (isprint(optopt)) {
				logmsg(LOG_ERR, "Unknown option -%c.\n", optopt);
			} else {
				logmsg(LOG_ERR, "Unknown option character \\x%x.\n");
			}
			exit(EXIT_FAILURE);
		case ':' :
			logmsg(LOG_ERR, "Option -%c requires argument.\n", optopt);
			exit(EXIT_FAILURE);
		}
	}
	if (!d) {
		logmsg(LOG_ERR, "Option -d required.\n");
		exit(EXIT_FAILURE);
	}
	if (!r) {
		logmsg(LOG_ERR, "Option -r required.\n");
		exit(EXIT_FAILURE);
	}
	if (!s) {
		logmsg(LOG_ERR, "Option -s required.\n");
		exit(EXIT_FAILURE);
	}
	if (!b) {
		logmsg(LOG_ERR, "Option -b required.\n");
		exit(EXIT_FAILURE);
	}
	errno = 0;
	char *tailptr = NULL;
	devn = strtoul(d, &tailptr, 0);
	if (errno || *tailptr != '\0' || devn < 0 || devn > 99) {
		logmsg(LOG_ERR, "Option -d bad format.\n");
		exit(EXIT_FAILURE);
	}
	errno = 0;
	tailptr = NULL;
	ioctl_bar.bar = strtoul(r, &tailptr, 0);
	if (errno || *tailptr != '\0' || ioctl_bar.bar < 0) {
		logmsg(LOG_ERR, "Option -r bad format.\n");
		exit(EXIT_FAILURE);
	}
	errno = 0;
	tailptr = NULL;
	read_size = strtoul(s, &tailptr, 0);
	if (errno || *tailptr != '\0' || read_size < 1) {
		logmsg(LOG_ERR, "Option -s bad format.\n");
		exit(EXIT_FAILURE);
	}
	errno = 0;
	tailptr = NULL;
	int align = strtol(b, &tailptr, 0);
	if (errno || *tailptr != '\0') {
		logmsg(LOG_ERR, "Option -b bad format.\n");
		exit(EXIT_FAILURE);
	}
	const char *bstr;
	if (align == 8) {
		bstr = "B8";
		ioctl_bar.read_align = RDPCI_READ_ALIGN_8;
	} else if (align == 16) {
		bstr = "B16";
		ioctl_bar.read_align = RDPCI_READ_ALIGN_16;
	} else if (align == 32) {
		bstr = "B32";
		ioctl_bar.read_align = RDPCI_READ_ALIGN_32;
	} else {
		logmsg(LOG_ERR, "Option -b bad format.\n");
		exit(EXIT_FAILURE);
	}
	if (o) {
		errno = 0;
		tailptr = NULL;
		fpos = strtoul(o, &tailptr, 0);
		if (errno || *tailptr != '\0' || fpos < 0) {
			logmsg(LOG_ERR, "Option -o bad format.\n");
			exit(EXIT_FAILURE);
		}
	}
	snprintf(dev_path + 10, 3, "%d", devn);
	logmsg(LOG_INFO, "Options: BAR%d read_size=%d offset=%d read_align=%s dev=%s\n", ioctl_bar.bar, read_size, fpos, bstr, dev_path);
}

/**
 * on_exit_clean
 */
static void on_exit_clean(int __attribute__((unused)) code, void __attribute__((unused)) *p)
{
	if (mem_buf) {
		free(mem_buf);
	}
	if (dev_file != -1) {
		close(dev_file);
	}
}

/**
 * logmsg
 */
static void logmsg(int prio, ...)
{
	va_list ap;
	FILE *file;
	const char *fmt;

	file = (prio <= LOG_ERR) ? stderr : stdout;
	va_start(ap, prio);
	fmt = va_arg(ap, const char *);
	if (prio <= LOG_ERR) {
		fprintf(stderr, "Error: ");
	}
	vfprintf(file, fmt, ap);
	va_end(ap);
}
