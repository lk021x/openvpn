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

#ifdef TARGET_OPENBSD

#include "syshead.h"
#include "socket.h"
#include "fdmisc.h"
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

/*
 * OpenBSD has a slightly incompatible TUN device from
 * the rest of the world, in that it prepends a
 * uint32 to the beginning of the IP header
 * to designate the protocol (why not just
 * look at the version field in the IP header to
 * determine v4 or v6?).
 *
 * We strip off this field on reads and
 * put it back on writes.
 *
 * I have not tested TAP devices on OpenBSD,
 * but I have conditionalized the special
 * TUN handling code described above to
 * go away for TAP devices.
 */

static
void
tun_engine_openbsd_tun_open (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
	tun_engine_common_tun_open_generic (dev, dev_type, dev_node, true, true, tt);

	/* Enable multicast on the interface */
	if (tt->fd >= 0) {
		struct tuninfo info;

		if (ioctl (tt->fd, TUNGIFINFO, &info) < 0) {
			msg (M_WARN | M_ERRNO, "Can't get interface info: %s",
			strerror(errno));
		}

#ifdef IFF_MULTICAST /* openbsd 4.x doesn't have this */
		info.flags |= IFF_MULTICAST;
#endif

		if (ioctl (tt->fd, TUNSIFINFO, &info) < 0) {
			msg (M_WARN | M_ERRNO, "Can't set interface info: %s",
			strerror(errno));
		}
	}
}

/* tun(4): "If the device was created by opening /dev/tunN, it will be
 *          automatically destroyed.  Devices created via ifconfig(8) are
 *          only marked as not running and traffic will be dropped
 *          returning EHOSTDOWN."
 * --> no special handling should be needed - *but* OpenBSD is misbehaving
 * here: if the interface was put in tap mode ("ifconfig tunN link0"), it
 * *will* stay around, and needs to be cleaned up manually
 */

static
void
tun_engine_openbsd_tun_close (struct tuntap* tt)
{
	if (tt != NULL) {
		/* only *TAP* devices need destroying, tun devices auto-self-destruct
		 */
		if (tt->type == DEV_TYPE_TUN ) {
			tun_engine_common_tun_close_generic (tt);
		}
		else {
			struct gc_arena gc = gc_new ();
			struct argv argv;

			/* setup command, close tun dev (clears tt->actual_name!), run command
			 */

			argv_init (&argv);
			argv_printf (
				&argv,
				"%s %s destroy",
				IFCONFIG_PATH,
				tt->actual_name
			);

			tun_engine_common_tun_close_generic (tt);

			argv_msg (M_INFO, &argv);
			openvpn_execve_check (&argv, NULL, 0, "OpenBSD 'destroy tun interface' failed (non-critical)");
		}
	}
}

static
void
tun_engine_openbsd_tun_ifconfig (
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
	 * On OpenBSD, tun interfaces are persistant if created with
	 * "ifconfig tunX create", and auto-destroyed if created by
	 * opening "/dev/tunX" (so we just use the /dev/tunX)
	 */

	/* example: ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 netmask 255.255.255.255 up */
	if (tun)
		argv_printf (&argv,
			"%s %s %s %s mtu %d netmask 255.255.255.255 up -link0",
			IFCONFIG_PATH,
			actual,
			ifconfig_local,
			ifconfig_remote_netmask,
			tun_mtu
		);
	else
	if ( tt->topology == TOP_SUBNET ) {
		argv_printf (&argv,
			"%s %s %s %s mtu %d netmask %s up -link0",
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
			"%s %s %s netmask %s mtu %d broadcast %s link0",
			IFCONFIG_PATH,
			actual,
			ifconfig_local,
			ifconfig_remote_netmask,
			tun_mtu,
			ifconfig_broadcast
		);
	argv_msg (M_INFO, &argv);
	openvpn_execve_check (&argv, es, S_FATAL, "OpenBSD ifconfig failed");
	if ( do_ipv6 ) {
		argv_printf (&argv,
			"%s %s inet6 %s/%d",
			IFCONFIG_PATH,
			actual,
			ifconfig_ipv6_local,
			tt->netbits_ipv6
		);
		argv_msg (M_INFO, &argv);
		openvpn_execve_check (&argv, es, S_FATAL, "OpenBSD ifconfig inet6 failed");

		/* and, hooray, we explicitely need to add a route... */
		tt->engine->route_add_connected_v6_net(tt, es);
	}
	tt->did_ifconfig = true;

	argv_reset (&argv);
}

static struct tun_engine_s _tun_engine = {
	tun_engine_common_tun_init,
	NULL, /* tun_init_post */
	tun_engine_common_tun_state_reset,
	tun_engine_openbsd_tun_open,
	tun_engine_openbsd_tun_close,
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
	tun_engine_openbsd_tun_ifconfig,
	tun_engine_common_tun_is_p2p,
	tun_engine_common_route_add_connected_v6_net,
	tun_engine_common_route_delete_connected_v6_net
};
tun_engine_t tun_engine = &_tun_engine;

#endif
