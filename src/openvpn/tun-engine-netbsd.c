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

#ifdef TARGET_NETBSD

#include "syshead.h"
#include "socket.h"
#include "fdmisc.h"
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
/*
 * NetBSD before 4.0 does not support IPv6 on tun out of the box,
 * but there exists a patch (sys/net/if_tun.c, 1.79->1.80, see PR 32944).
 *
 * NetBSD 4.0 and up do, but we need to put the tun interface into
 * "multi_af" mode, which will prepend the address family to all packets
 * (same as OpenBSD and FreeBSD).  If this is not enabled, the kernel
 * silently drops all IPv6 packets on output and gets confused on input.
 *
 * On earlier versions, multi_af is not available at all, so we have
 * two different NetBSD code variants here :-(
 *
 */

static
void
tun_engine_netbsd_tun_open (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
#ifdef NETBSD_MULTI_AF
	tun_engine_common_tun_open_generic (dev, dev_type, dev_node, true, true, tt);
#else
	tun_engine_common_tun_open_generic (dev, dev_type, dev_node, false, true, tt);
#endif

	if (tt->fd >= 0) {
		int i = IFF_POINTOPOINT|IFF_MULTICAST;
		ioctl (tt->fd, TUNSIFMODE, &i);  /* multicast on */
		i = 0;
		ioctl (tt->fd, TUNSLMODE, &i);   /* link layer mode off */

#ifdef NETBSD_MULTI_AF
		if ( tt->type == DEV_TYPE_TUN ) {
			i = 1;
			if (ioctl (tt->fd, TUNSIFHEAD, &i) < 0) { 	/* multi-af mode on */
				msg (M_WARN | M_ERRNO, "ioctl(TUNSIFHEAD): %s", strerror(errno));
			}
	}
#endif
	}
}

/* the current way OpenVPN handles tun devices on NetBSD leads to
 * lingering tunX interfaces after close -> for a full cleanup, they
 * need to be explicitely destroyed
 */
static
void
tun_engine_netbsd_tun_close (struct tuntap *tt)
{
	if (tt != NULL) {
		/* only tun devices need destroying, tap devices auto-self-destruct
		 */
		if (tt->type != DEV_TYPE_TUN ) {
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
			openvpn_execve_check (&argv, NULL, 0, "NetBSD 'destroy tun interface' failed (non-critical)");
		}
	}
}

#ifdef NETBSD_MULTI_AF

static
int
tun_engine_netbsd_tun_write (struct tuntap* tt, struct buffer *buf)
{
	return tun_engine_common_bsd_tun_write(tt, buf);
}

static
int
tun_engine_netbsd_tun_read (struct tuntap* tt, struct buffer *buf, int size, int maxsize)
{
	return tun_engine_common_bsd_tun_read(tt, buf, size, maxsize);
}

#else	/* not NETBSD_MULTI_AF -> older code, IPv4 only */

static
int
tun_engine_netbsd_tun_write (struct tuntap* tt, struct buffer *buf)
{
	return tun_engine_common_tun_write(tt, buf);
}

static
int
tun_engine_netbsd_tun_read (struct tuntap* tt, struct buffer *buf, int size, int maxsize)
{
	return tun_engine_common_tun_read(tt, buf, size, maxsize);
}
#endif	/* NETBSD_MULTI_AF */

static
bool
tun_engine_netbsd_tun_device_open_dynamic (struct tuntap* tt, const char *dev, char * dynamic_name, size_t dynamic_name_len)
{
	/* on NetBSD, tap (but not tun) devices are opened by
	 * opening /dev/tap and then querying the system about the
	 * actual device name (tap0, tap1, ...) assigned
	 */
	if ( strcmp( dev, "tap" ) != 0 ) {
		return false;
	}
	else {
		struct ifreq ifr;
		if ((tt->fd = open ( "/dev/tap", O_RDWR)) < 0) {
			msg (M_FATAL, "Cannot allocate NetBSD TAP dev dynamically");
		}
		if ( ioctl( tt->fd, TAPGIFNAME, (void*)&ifr ) < 0 ) {
			msg (M_FATAL, "Cannot query NetBSD TAP device name");
		}
		CLEAR(dynamic_name);
		strncpy( dynamic_name, ifr.ifr_name, sizeof(dynamic_name)-1 );
		return true;
	}
}

static
void
tun_engine_netbsd_tun_ifconfig (
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
/* whether or not NetBSD can do IPv6 can be seen by the availability of
 * the TUNSIFHEAD ioctl() - see next TARGET_NETBSD block for more details
 */
#ifdef TUNSIFHEAD
# define NETBSD_MULTI_AF
#endif

	if (tun)
		argv_printf (&argv,
			"%s %s %s %s mtu %d netmask 255.255.255.255 up",
			IFCONFIG_PATH,
			actual,
			ifconfig_local,
			ifconfig_remote_netmask,
			tun_mtu
		);
	else
		if ( tt->topology == TOP_SUBNET ) {
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
		/*
		 * NetBSD has distinct tun and tap devices
		 * so we don't need the "link0" extra parameter to specify we want to do 
		 * tunneling at the ethernet level
		 */
		argv_printf (&argv,
			"%s %s %s netmask %s mtu %d broadcast %s",
			IFCONFIG_PATH,
			actual,
			ifconfig_local,
			ifconfig_remote_netmask,
			tun_mtu,
			ifconfig_broadcast
		);
	argv_msg (M_INFO, &argv);
	openvpn_execve_check (&argv, es, S_FATAL, "NetBSD ifconfig failed");

	if ( do_ipv6 ) {
#ifdef NETBSD_MULTI_AF
		argv_printf (&argv,
			"%s %s inet6 %s/%d",
			IFCONFIG_PATH,
			actual,
			ifconfig_ipv6_local,
			tt->netbits_ipv6
		);
		argv_msg (M_INFO, &argv);
		openvpn_execve_check (&argv, es, S_FATAL, "NetBSD ifconfig inet6 failed");

		/* and, hooray, we explicitely need to add a route... */
		tt->engine->route_add_connected_v6_net(tt, es);
#else
		msg( M_INFO, "no IPv6 support for tun interfaces on NetBSD before 4.0 (if your system is newer, recompile openvpn)" );
		tt->ipv6 = false;
#endif
	}
	tt->did_ifconfig = true;

	argv_reset (&argv);
}

static struct tun_engine_s _tun_engine = {
	tun_engine_common_tun_init,
	NULL, /* tun_init_post */
	tun_engine_common_tun_state_reset,
	tun_engine_netbsd_tun_open,
	tun_engine_netbsd_tun_close,
	NULL, /* tun_stop */
	tun_engine_common_tun_status,
	tun_engine_netbsd_tun_write,
	tun_engine_netbsd_tun_read,
	NULL, /* tun_write_queue */
	NULL, /* tun_read_queue */
	NULL, /* tun_info */
	NULL, /* tun_debug_show */
	NULL, /* tun_standby_init */
	NULL, /* tun_standby */
	NULL, /* tun_config */
	NULL, /* tun_device_guess */
	tun_device_open_dynamic,
	tun_engine_netbsd_tun_ifconfig,
	tun_engine_common_tun_is_p2p,
	tun_engine_common_route_add_connected_v6_net,
	tun_engine_common_route_delete_connected_v6_net
};
tun_engine_t tun_engine = &_tun_engine;

#endif
