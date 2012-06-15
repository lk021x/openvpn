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

#ifdef TARGET_DARWIN

#include "syshead.h"
#include "socket.h"
#include "fdmisc.h"
#include "route.h"
#include "tun.h"
#include "tun-engine.h"
#include "tun-engine-common.h"

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

/* Darwin (MacOS X) is mostly "just use the generic stuff", but there
 * is always one caveat...:
 *
 * If IPv6 is configured, and the tun device is closed, the IPv6 address
 * configured to the tun interface changes to a lingering /128 route
 * pointing to lo0.  Need to unconfigure...  (observed on 10.5)
 */

static
void
tun_engine_darwin_tun_close (struct tuntap* tt)
{
	if (tt) {
		struct gc_arena gc = gc_new ();
		struct argv argv;
		argv_init (&argv);

		if ( tt->ipv6 && tt->did_ifconfig_ipv6_setup ) {
			const char * ifconfig_ipv6_local =
				print_in6_addr (tt->local_ipv6, 0, &gc);

			argv_printf (&argv, "%s delete -inet6 %s",
			      ROUTE_PATH, ifconfig_ipv6_local );
			argv_msg (M_INFO, &argv);
			openvpn_execve_check (&argv, NULL, 0, "MacOS X 'remove inet6 route' failed (non-critical)");
		}

		tun_engine_common_tun_close_generic (tt);
		argv_reset (&argv);
		gc_free (&gc);
	}
}

static
void
tun_engine_darwin_tun_ifconfig (
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

	/*
	 * Darwin (i.e. Mac OS X) seems to exhibit similar behaviour to OpenBSD...
	 */

	argv_printf (&argv,
		"%s %s delete",
		IFCONFIG_PATH,
		actual);
	argv_msg (M_INFO, &argv);
	openvpn_execve_check (&argv, es, 0, NULL);
	msg (M_INFO, "NOTE: Tried to delete pre-existing tun/tap instance -- No Problem if failure");


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
	else {
		if (tt->topology == TOP_SUBNET)
			argv_printf (&argv,
				"%s %s %s %s netmask %s mtu %d up",
				IFCONFIG_PATH,
				actual,
				ifconfig_local,
				ifconfig_local,
				ifconfig_remote_netmask,
				tun_mtu
			);
		else
			argv_printf (&argv,
				"%s %s %s netmask %s mtu %d up",
				IFCONFIG_PATH,
				actual,
				ifconfig_local,
				ifconfig_remote_netmask,
				tun_mtu
			);
	}

	argv_msg (M_INFO, &argv);
	openvpn_execve_check (&argv, es, S_FATAL, "Mac OS X ifconfig failed");
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
		openvpn_execve_check (&argv, es, S_FATAL, "MacOS X ifconfig inet6 failed");

		/* and, hooray, we explicitely need to add a route... */
		tt->engine->route_add_connected_v6_net(tt, es);
	}

	argv_reset (&argv);
}

static struct tun_engine_s _tun_engine = {
	tun_engine_common_tun_init,
	NULL, /* tun_init_post */
	tun_engine_common_tun_state_reset,
	tun_engine_common_tun_open_generic,
	tun_engine_darwin_tun_close,
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
	tun_engine_darwin_tun_ifconfig,
	tun_engine_common_tun_is_p2p,
	tun_engine_common_route_add_connected_v6_net,
	tun_engine_common_route_delete_connected_v6_net
};
tun_engine_t tun_engine = &_tun_engine;

#endif
