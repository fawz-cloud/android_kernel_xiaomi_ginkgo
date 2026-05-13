// SPDX-License-Identifier: GPL-2.0
/*
 * Anti-Frida kernel hider.
 *
 * Centralised string / port blacklists used by /proc, /proc/net/tcp* and
 * /proc/<pid>/maps to make Frida invisible to userspace probes.
 */

#include <linux/anti_frida.h>
#include <linux/ctype.h>
#include <linux/sched.h>
#include <linux/string.h>

/*
 * Substrings we hide from /proc/<pid>/comm, /proc/<pid>/cmdline,
 * /proc/<pid>/task/*\/comm, and /proc/<pid>/maps.
 *
 * Match is case-insensitive substring. Keep entries lowercase.
 */
static const char * const af_str_blacklist[] = {
	"frida",		/* frida-server, frida-agent, frida-helper */
	"gum-js-loop",		/* Frida's JavaScript thread */
	"gmain",		/* GLib main thread (used by frida) */
	"gdbus",		/* often spawned by frida-server */
	"linjector",		/* Frida injector helper */
	"re.frida.server",	/* default frida-server file name */
	NULL,
};

/*
 * Path/file-name fragments that should be hidden from /proc/<pid>/maps.
 * Same case-insensitive substring rules apply.
 */
static const char * const af_path_blacklist[] = {
	"frida",
	"re.frida.server",
	"linjector",
	NULL,
};

/*
 * Default Frida listening ports.
 */
static const u16 af_tcp_blacklist[] = {
	27042,
	27043,
	0,
};

/* Case-insensitive substring search. Empty needle never matches. */
static bool af_strcasestr(const char *hay, const char *needle)
{
	size_t nlen, hlen, i, j;

	if (!hay || !needle)
		return false;
	nlen = strlen(needle);
	if (nlen == 0)
		return false;
	hlen = strlen(hay);
	if (hlen < nlen)
		return false;

	for (i = 0; i + nlen <= hlen; i++) {
		for (j = 0; j < nlen; j++) {
			if (tolower(hay[i + j]) != tolower(needle[j]))
				break;
		}
		if (j == nlen)
			return true;
	}
	return false;
}

bool af_str_is_blacklisted(const char *s)
{
	const char * const *p;

	if (!s)
		return false;
	for (p = af_str_blacklist; *p; p++) {
		if (af_strcasestr(s, *p))
			return true;
	}
	return false;
}

bool af_path_is_blacklisted(const char *path)
{
	const char * const *p;

	if (!path)
		return false;
	for (p = af_path_blacklist; *p; p++) {
		if (af_strcasestr(path, *p))
			return true;
	}
	return false;
}

bool af_task_is_blacklisted(struct task_struct *task)
{
	char comm[TASK_COMM_LEN];

	if (!task)
		return false;

	/* Check this task's comm (covers both processes and threads). */
	get_task_comm(comm, task);
	if (af_str_is_blacklisted(comm))
		return true;

	/* Also check the thread group leader, so all threads of a Frida
	 * process get hidden together (including non-renamed worker threads).
	 */
	if (task->group_leader && task->group_leader != task) {
		get_task_comm(comm, task->group_leader);
		if (af_str_is_blacklisted(comm))
			return true;
	}
	return false;
}

bool af_tcp_port_is_blacklisted(u16 port)
{
	const u16 *p;

	for (p = af_tcp_blacklist; *p; p++) {
		if (*p == port)
			return true;
	}
	return false;
}
