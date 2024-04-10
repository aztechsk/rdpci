/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * logmsg
 *
 * Copyright (c) 2024 Jan Rusnak <jan@rusnak.sk>
 */

#ifndef LOGMSG_H
#define LOGMSG_H

#define loginfo(fmt, ...) pr_warn("[%s] %s(): " fmt, KBUILD_MODNAME, __func__, ##__VA_ARGS__)
#define logerr(fmt, ...) pr_err("[%s] %s(): " fmt, KBUILD_MODNAME, __func__, ##__VA_ARGS__)

#endif
