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

/*
 * Support routines for configuring and accessing TUN/TAP
 * virtual network adapters.
 *
 * This file is based on the TUN/TAP driver interface routines
 * from VTun by Maxim Krasnyansky <max_mk@yahoo.com>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#ifdef TARGET_GENERIC

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "syshead.h"
#include "socket.h"
#include "fdmisc.h"
#include "tun.h"
#include "tun-engine.h"
#include "tun-engine-common.h"

static
void
tun_engine_generic_tun_ifconfig (
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
)
{
      msg (M_FATAL, "Sorry, but I don't know how to do 'ifconfig' commands on this operating system.  You should ifconfig your TUN/TAP device manually or use an --up script.");
}

static struct tun_engine_s _tun_engine = {
	tun_engine_common_tun_init,
	NULL, /* tun_init_post */
	tun_engine_common_tun_state_reset,
	tun_engine_common_tun_open_generic,
	tun_engine_common_tun_close_generic,
	NULL, /* tun_stop */
	tun_engine_common_tun_status,
	tun_engine_common_tun_write,
	tun_engine_common_tun_read,
	NULL, /* tun_write_queue */
	NULL, /* tun_read_queue */
	NULL, /* tun_info */
	NULL, /* tun_debug_show */
	NULL, /* tun_standby_init */
	NULL, /* tun_standby */
	NULL, /* tun_config */
	NULL, /* tun_device_guess */
	NULL, /* tun_device_open_dynamic */
	tun_engine_generic_tun_ifconfig,
	tun_engine_common_tun_is_p2p,
	NULL, /* route_add_connected_v6_net */
	NULL  /* route_delete_connected */
};
tun_engine_t tun_engine = &_tun_engine;

#endif
