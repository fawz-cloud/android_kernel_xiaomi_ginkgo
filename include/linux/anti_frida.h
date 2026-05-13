/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Anti-Frida kernel hook helpers.
 *
 * Provides string blacklists and tiny helpers used by /proc, /proc/net/tcp*,
 * and /proc/<pid>/maps to hide the presence of the Frida instrumentation
 * toolkit (frida-server, frida-agent, gum-js-loop, gmain, etc.) and the
 * default tcp listening ports it uses (27042/27043).
 *
 * The hider is intentionally lightweight: it performs case-insensitive
 * substring matches against a small, fixed blacklist. All comparisons happen
 * in kernel space using kernel headers only, with no allocations.
 */

#ifndef _LINUX_ANTI_FRIDA_H
#define _LINUX_ANTI_FRIDA_H

#include <linux/types.h>
#include <linux/sched.h>

#ifdef CONFIG_HIDE_FRIDA

/*
 * Returns true if the given NUL-terminated string contains any blacklisted
 * Frida-related substring (case-insensitive). Safe with NULL input.
 */
bool af_str_is_blacklisted(const char *s);

/*
 * Returns true if the given path / file name belongs to a known Frida
 * artifact (e.g. "re.frida.server", "frida-agent-*.so", "linjector").
 * Safe with NULL input.
 */
bool af_path_is_blacklisted(const char *path);

/*
 * Returns true if the given task is a Frida-related process or thread,
 * based on its comm field (or its leader's comm field).
 */
bool af_task_is_blacklisted(struct task_struct *task);

/*
 * Returns true if the given TCP port (host byte order) is one of the
 * default Frida listening ports.
 */
bool af_tcp_port_is_blacklisted(u16 port);

#else /* !CONFIG_HIDE_FRIDA */

static inline bool af_str_is_blacklisted(const char *s)		{ return false; }
static inline bool af_path_is_blacklisted(const char *path)	{ return false; }
static inline bool af_task_is_blacklisted(struct task_struct *t){ return false; }
static inline bool af_tcp_port_is_blacklisted(u16 port)		{ return false; }

#endif /* CONFIG_HIDE_FRIDA */

#endif /* _LINUX_ANTI_FRIDA_H */
