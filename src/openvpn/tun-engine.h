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

#ifndef __TUN_ENGINE_H
#define __TUN_ENGINE_H

struct tun_engine_s {
	struct tuntap *(*tun_init) (
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
	void (*tun_init_post) (
		struct tuntap *tt,
		const struct frame *frame,
		const tun_engine_options_t options
	);
	void (*tun_state_reset) (struct tuntap *tt);
	void (*tun_open) (
		const char *dev,
		const char *dev_type,
		const char *dev_node,
		struct tuntap *tt
	);
	void (*tun_close) (struct tuntap *tt);
	bool (*tun_stop) (struct tuntap *tt, int status);
	const char *(*tun_status) (const struct tuntap *tt, unsigned int rwflags, struct gc_arena *gc);
	int (*tun_write) (struct tuntap* tt, struct buffer *buf);
	int (*tun_read) (struct tuntap* tt, struct buffer *buf, int size, int maxsize);
	int (*tun_write_queue) (struct tuntap *tt, struct buffer *buf);
	int (*tun_read_queue) (struct tuntap *tt, int maxsize);
	const char *(*tun_info) (const struct tuntap *tt, struct gc_arena *gc);
	void (*tun_debug_show) (struct tuntap *tt);
	void (*tun_standby_init) (struct tuntap *tt);
	bool (*tun_standby) (struct tuntap *tt);
	void (*tun_config) (tun_engine_t engine, const char *dev, const char *dev_type, const char *dev_node, int persist_mode, const char *username, const char *groupname, const tun_engine_options_t options);
	const char *(*tun_device_guess) (
		struct tuntap *tt,
		const char *dev,
		const char *dev_type,
		const char *dev_node,
		struct gc_arena *gc
	);
	bool (*tun_device_open_dynamic) (struct tuntap* tt, const char *dev, char * dynamic_name, size_t dynamic_name_len);
	void (*tun_ifconfig) (
		struct tuntap *tt,
		const char *actual,
		int tun_mtu,
		const struct env_set *es,
		bool tun,
		const char *ifconfig_local,
		const char *ifconfig_remote_netmask,
		const char *ifconfig_broadcast,
		const char *ifconfig_ipv6_local,
		const char *ifconfig_ipv6_remote,
		bool do_ipv6
	);
	bool (*tun_is_p2p) (const struct tuntap *tt);
	void (*route_add_connected_v6_net) (struct tuntap * tt,	const struct env_set *es);
	void (*route_delete_connected_v6_net) (struct tuntap * tt, const struct env_set *es);
};

#endif
