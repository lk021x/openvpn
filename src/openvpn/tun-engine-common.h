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

#ifndef __TUN_ENGINE_COMMON_H
#define __TUN_ENGINE_COMMON_H

void
tun_engine_common_tun_open_null (struct tuntap *tt);

struct tuntap *
tun_engine_common_tun_init (
	tun_engine_t engine,
	const char *dev,       /* --dev option */
	const char *dev_type,  /* --dev-type option */
	int topology,          /* one of the TOP_x values */
	const char *ifconfig_local_parm,          /* --ifconfig parm 1 */
	const char *ifconfig_remote_netmask_parm, /* --ifconfig parm 2 */
	const char *ifconfig_ipv6_local_parm,     /* --ifconfig parm 1 IPv6 */
	int         ifconfig_ipv6_netbits_parm,
	const char *ifconfig_ipv6_remote_parm,    /* --ifconfig parm 2 IPv6 */
	in_addr_t local_public,
	in_addr_t remote_public,
	const bool strict_warn,
	const bool ipv6,
	struct env_set *es
);

void
tun_engine_common_tun_init_post (
	struct tuntap *tt,
	const struct frame *frame,
	const tun_engine_options_t options
);

void
tun_engine_common_tun_state_reset (struct tuntap *tt);

const char *
tun_engine_common_tun_status (const struct tuntap *tt, unsigned int rwflags, struct gc_arena *gc);

void
tun_engine_common_tun_open_generic (const char *dev, const char *dev_type, const char *dev_node,
	bool ipv6_explicitly_supported, bool dynamic,
	struct tuntap *tt);

void
tun_engine_common_tun_close_generic (struct tuntap *tt);

int
tun_engine_common_tun_write (struct tuntap* tt, uint8_t *buf, int len);

int
tun_engine_common_tun_read (struct tuntap* tt, uint8_t *buf, int len);

void
tun_engine_common_route_add_connected_v6_net(struct tuntap * tt, const struct env_set *es);

void
tun_engine_common_route_delete_connected_v6_net(struct tuntap * tt, const struct env_set *es);

bool
tun_engine_common_tun_is_p2p (const struct tuntap *tt);

#endif
