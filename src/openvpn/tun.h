/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef TUN_H
#define TUN_H

#include "buffer.h"
#include "error.h"
#include "mtu.h"
#include "win32.h"
#include "event.h"
#include "proto.h"
#include "misc.h"

struct tun_engine_options_s;
typedef struct tun_engine_options_s *tun_engine_options_t;
struct tun_engine_private_data_s;
typedef struct tun_engine_private_data_s *tun_engine_private_data_t;
struct tun_engine_s;
typedef struct tun_engine_s *tun_engine_t;

/*
 * Define a TUN/TAP dev.
 */

struct tuntap
{
	tun_engine_t engine;
	tun_engine_private_data_t engine_data;

#define TUNNEL_TYPE(tt) ((tt) ? ((tt)->type) : DEV_TYPE_UNDEF)
	int type; /* DEV_TYPE_x as defined in proto.h */

#define TUNNEL_TOPOLOGY(tt) ((tt) ? ((tt)->topology) : TOP_UNDEF)
	int topology; /* one of the TOP_x values */

	bool did_opened;
	bool config_before_open;

	bool did_ifconfig_setup;
	bool did_ifconfig_ipv6_setup;
	bool did_ifconfig;

	bool ipv6;

	char *actual_name; /* actual name of TUN/TAP dev, usually including unit number */

	/* number of TX buffers */
	int txqueuelen;

	/* ifconfig parameters */
	in_addr_t local;
	in_addr_t remote_netmask;
	in_addr_t broadcast;

	struct in6_addr local_ipv6;
	struct in6_addr remote_ipv6;
	int netbits_ipv6;

#ifdef WIN32
	struct rw_handle rw_handle;
#else
	int fd;   /* file descriptor for TUN/TAP dev */
#endif

	/* used for printing status info only */
	unsigned int rwflags_debug;

	/* Some TUN/TAP drivers like to be ioctled for mtu
	after open */
	int post_open_mtu;
};

static inline bool
tun_defined (const struct tuntap *tt)
{
	return tt && tt->did_opened;
}

/*
 * Function prototypes
 */

struct tuntap *tun_init (
	const char *dev,       /* --dev option */
	const char *dev_type,  /* --dev-type option */
	int topology,          /* one of the TOP_x values */
	const char *ifconfig_local_parm,          /* --ifconfig parm 1 */
	const char *ifconfig_remote_netmask_parm, /* --ifconfig parm 2 */
	const char *ifconfig_ipv6_local_parm,     /* --ifconfig parm 1 / IPv6 */
	int ifconfig_ipv6_netbits_parm,           /* --ifconfig parm 1 / bits */
	const char *ifconfig_ipv6_remote_parm,    /* --ifconfig parm 2 / IPv6 */
	in_addr_t local_public,
	in_addr_t remote_public,
	const bool strict_warn,
	const bool ipv6,
	struct env_set *es
);

void tun_init_post (struct tuntap *tt,
	const struct frame *frame,
	const tun_engine_options_t options);

void tun_open (const char *dev, const char *dev_type, const char *dev_node,
	struct tuntap *tt);

void tun_close (struct tuntap *tt);

bool tun_stop (struct tuntap *tt, int status);

int tun_write (struct tuntap* tt, struct buffer *buf);

int tun_read (struct tuntap* tt, struct buffer *buf, int size, int maxsize);

int tun_write_queue (struct tuntap *tt, struct buffer *buf);

int tun_read_queue (struct tuntap *tt, int maxsize);

void tun_config (const char *dev, const char *dev_type, const char *dev_node,
	int persist_mode, const char *username,
	const char *groupname, const tun_engine_options_t options);

void tun_standby_init (struct tuntap *tt);

bool tun_standby (struct tuntap *tt);

const char *tun_device_guess (struct tuntap *tt, const char *dev,
	const char *dev_type, const char *dev_node, struct gc_arena *gc);

void tun_ifconfig (struct tuntap *tt,
	const char *actual,    /* actual device name */
	int tun_mtu, const struct env_set *es);

const char *tap_info (const struct tuntap *tt, struct gc_arena *gc);

void tun_debug_show (struct tuntap *tt);

const char *tun_status (const struct tuntap *tt, unsigned int rwflags, struct gc_arena *gc);


bool tun_is_dev_type (const char *dev, const char *dev_type, const char *match_type);
int tun_dev_type_enum (const char *dev, const char *dev_type);
const char *tun_dev_type_string (const char *dev, const char *dev_type);

const char *tun_ifconfig_options_string (const struct tuntap* tt, bool remote, bool disable, struct gc_arena *gc);

static inline bool
tun_config_before_open(const struct tuntap *tt) {
	return tt->config_before_open;
}

/*
 * TUN/TAP I/O wait functions
 */

static inline event_t
_tun_event_handle (const struct tuntap *tt)
{
#ifdef WIN32
	return &tt->rw_handle;
#else
	return tt->fd;
#endif
}

static inline unsigned int
tun_set (
	struct tuntap *tt,
	struct event_set *es,
	unsigned int rwflags,
	void *arg,
	unsigned int *persistent
) {
	if (tun_defined (tt)) {
		/*
		 * if persistent is defined, call event_ctl
		 * only if rwflags has changed since last call
		 */
		if (!persistent || *persistent != rwflags) {
			event_ctl (es, _tun_event_handle (tt), rwflags, arg);
			if (persistent)
				*persistent = rwflags;
		}
		if (rwflags & EVENT_READ)
			tun_read_queue (tt, 0);
		tt->rwflags_debug = rwflags;
	}
	return rwflags;
}

#endif /* TUN_H */
