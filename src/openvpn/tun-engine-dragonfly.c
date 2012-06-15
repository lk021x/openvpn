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

#ifdef TARGET_DRAGONFLY

#include "syshead.h"
#include "socket.h"
#include "fdmisc.h"
#include "route.h"
#include "tun.h"
#include "tun-engine.h"
#include "tun-engine-common.h"
#include "tun-engine-common-bsd.h"

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

#ifdef HAVE_NET_TUN_IF_TUN_H
#include <net/tun/if_tun.h>
#endif

#ifdef HAVE_NET_IF_TAP_H
#include <net/if_tap.h>
#endif

static
void
tun_engine_dragonfly_tun_open (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
	tun_engine_common_tun_open_generic (dev, dev_type, dev_node, true, true, tt);

	if (tt->fd >= 0) {
		int i = 0;

		/* Disable extended modes */
		ioctl (tt->fd, TUNSLMODE, &i);
		i = 1;
		ioctl (tt->fd, TUNSIFHEAD, &i);
	}
}

/* freebsd and dragonfly are the same */
static
void
tun_engine_dragonfly_tun_ifconfig (
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
	struct argv argv;

	argv_init (&argv);

	/* example: ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 netmask 255.255.255.255 up */
	if (tun)
		argv_printf (&argv,
			"%s %s %s %s mtu %d netmask 255.255.255.255 up",
			IFCONFIG_PATH,
			actual,
			ifconfig_local,
			ifconfig_remote_netmask,
			tun_mtu
		);
	else if ( tt->topology == TOP_SUBNET ) {
		argv_printf (&argv,
			"%s %s %s %s mtu %d netmask %s up",
			IFCONFIG_PATH,
			actual,
			ifconfig_local,
			ifconfig_local,
			tun_mtu,
			ifconfig_remote_netmask
		);
	}
	else
		argv_printf (&argv,
			"%s %s %s netmask %s mtu %d up",
			IFCONFIG_PATH,
			actual,
			ifconfig_local,
			ifconfig_remote_netmask,
			tun_mtu
		);

	argv_msg (M_INFO, &argv);
	openvpn_execve_check (&argv, es, S_FATAL, "FreeBSD ifconfig failed");
	tt->did_ifconfig = true;

	/* Add a network route for the local tun interface */
	if (!tun && tt->topology == TOP_SUBNET) {
		struct route r;
		CLEAR (r);
		r.flags = RT_DEFINED;
		r.network = tt->local & tt->remote_netmask;
		r.netmask = tt->remote_netmask;
		r.gateway = tt->local;
		add_route (&r, tt, 0, NULL, es);
	}

	if ( do_ipv6 ) {
		argv_printf (&argv,
			"%s %s inet6 %s/%d",
			IFCONFIG_PATH,
			actual,
			ifconfig_ipv6_local,
			tt->netbits_ipv6
		);
		argv_msg (M_INFO, &argv);
		openvpn_execve_check (&argv, es, S_FATAL, "FreeBSD ifconfig inet6 failed");
	}
	argv_reset (&argv);
}

static struct tun_engine_s_tun_engine = {
	tun_engine_common_tun_init,
	NULL, /* tun_init_post */
	tun_engine_common_tun_state_reset,
	tun_engine_dragonfly_tun_open,
	tun_engine_common_tun_close_generic,
	NULL, /* tun_stop */
	tun_engine_common_tun_status,
	tun_engine_common_bsd_tun_write,
	tun_engine_common_bsd_tun_read,
	NULL, /* tun_write_queue */
	NULL, /* tun_read_queue */
	NULL, /* tun_info */
	NULL, /* tun_debug_show */
	NULL, /* tun_standby_init */
	NULL, /* tun_standby */
	NULL, /* tun_config */
	NULL, /* tun_device_guess */
	NULL, /* tun_device_open_dynamic */
	tun_engine_dragonfly_tun_ifconfig,
	tun_engine_common_tun_is_p2p,
	NULL, /* route_add_connected_v6_net */
	NULL  /* route_delete_connected */
};
tun_engine_t tun_engine = &_tun_engine;

#endif
