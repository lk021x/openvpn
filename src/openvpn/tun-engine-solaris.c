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

#ifdef TARGET_SOLARIS

#include "syshead.h"
#include "socket.h"
#include "fdmisc.h"
#include "route.h"
#include "tun.h"
#include "tun-engine.h"
#include "tun-engine-common.h"

#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

#ifndef TUNNEWPPA
#error I need the symbol TUNNEWPPA from net/if_tun.h
#endif

#include <stropts.h>

struct tun_engine_private_data_s {
	int ip_fd;
};

static void
solaris_error_close (struct tuntap *tt, const struct env_set *es, 
                     const char *actual, bool unplumb_inet6 )
{
	struct argv argv;
	argv_init (&argv);

	if (unplumb_inet6) {
		argv_printf( &argv, "%s %s inet6 unplumb",
		IFCONFIG_PATH, actual );
		argv_msg (M_INFO, &argv);
		openvpn_execve_check (&argv, es, 0, "Solaris ifconfig inet6 unplumb failed");
	}

	argv_printf (&argv,
		"%s %s unplumb",
		IFCONFIG_PATH,
		actual);

	argv_msg (M_INFO, &argv);
	openvpn_execve_check (&argv, es, 0, "Solaris ifconfig unplumb failed");
	tt->engine->tun_close (tt);
	msg (M_FATAL, "Solaris ifconfig failed");
	argv_reset (&argv);
}

static
void
tun_engine_solaris_tun_state_reset (struct tuntap *tt)
{
	tun_engine_common_tun_state_reset(tt);
	if (tt->engine_data == NULL) {
		ALLOC_OBJ(tt->engine_data, struct tun_engine_private_data_s);
	}
	CLEAR(*tt->engine_data);
	tt->engine_data->ip_fd = -1;
}

static
void
tun_engine_solaris_tun_open (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
	int if_fd, ip_muxid, arp_muxid, arp_fd, ppa = -1;
	struct lifreq ifr;
	const char *ptr;
	const char *ip_node, *arp_node;
	const char *dev_tuntap_type;
	int link_type;
	bool is_tun;
	struct strioctl  strioc_if, strioc_ppa;

	/* improved generic TUN/TAP driver from
	 * http://www.whiteboard.ne.jp/~admin2/tuntap/
	 * has IPv6 support
	 */
	CLEAR(ifr);

	if (tt->type == DEV_TYPE_NULL) {
		tun_engine_common_tun_open_null (tt);
		return;
	}

	if (tt->type == DEV_TYPE_TUN) {
		ip_node = "/dev/udp";
		if (!dev_node)
			dev_node = "/dev/tun";
		dev_tuntap_type = "tun";
		link_type = I_PLINK;
		is_tun = true;
	}
	else if (tt->type == DEV_TYPE_TAP) {
		ip_node = "/dev/udp";
		if (!dev_node)
			dev_node = "/dev/tap";
		arp_node = dev_node;
		dev_tuntap_type = "tap";
		link_type = I_PLINK; /* was: I_LINK */
		is_tun = false;
	}
	else {
		msg (M_FATAL, "I don't recognize device %s as a tun or tap device",
			dev);
	}

	if ((tt->engine_data->ip_fd = open (ip_node, O_RDWR, 0)) < 0)
		msg (M_ERR, "Can't open %s", ip_node);

	if ((tt->fd = open (dev_node, O_RDWR, 0)) < 0)
		msg (M_ERR, "Can't open %s", dev_node);

	/* get unit number */
	if (*dev) {
		ptr = dev;
		while (*ptr && !isdigit ((int) *ptr))
			ptr++;
		ppa = atoi (ptr);
	}

	/* Assign a new PPA and get its unit number. */
	strioc_ppa.ic_cmd = TUNNEWPPA;
	strioc_ppa.ic_timout = 0;
	strioc_ppa.ic_len = sizeof(ppa);
	strioc_ppa.ic_dp = (char *)&ppa;

	if ( *ptr == '\0' ) {		/* no number given, try dynamic */
		bool found_one = false;
		while( ! found_one && ppa < 64 ) {
			int new_ppa = ioctl (tt->fd, I_STR, &strioc_ppa);
			if ( new_ppa >= 0 ) {
				msg( M_INFO, "open_tun: got dynamic interface '%s%d'", dev_tuntap_type, new_ppa );
				ppa = new_ppa;
				found_one = true;
				break;
			}
			if ( errno != EEXIST )
				msg (M_ERR, "open_tun: unexpected error trying to find free %s interface", dev_tuntap_type );
			ppa++;
		}
		if ( !found_one )
			msg (M_ERR, "open_tun: could not find free %s interface, give up.", dev_tuntap_type );
	}
	else {				/* try this particular one */
		if ((ppa = ioctl (tt->fd, I_STR, &strioc_ppa)) < 0)
		msg (M_ERR, "Can't assign PPA for new interface (%s%d)", dev_tuntap_type, ppa );
	}

	if ((if_fd = open (dev_node, O_RDWR, 0)) < 0)
		msg (M_ERR, "Can't open %s (2)", dev_node);

	if (ioctl (if_fd, I_PUSH, "ip") < 0)
		msg (M_ERR, "Can't push IP module");

	if (tt->type == DEV_TYPE_TUN) {
		/* Assign ppa according to the unit number returned by tun device */
		if (ioctl (if_fd, IF_UNITSEL, (char *) &ppa) < 0)
			msg (M_ERR, "Can't set PPA %d", ppa);
	}

	tt->actual_name = (char *) malloc (32);
	check_malloc_return (tt->actual_name);

	openvpn_snprintf (tt->actual_name, 32, "%s%d", dev_tuntap_type, ppa);

	if (tt->type == DEV_TYPE_TAP) {
		if (ioctl(if_fd, SIOCGLIFFLAGS, &ifr) < 0)
			msg (M_ERR, "Can't get flags\n");
		strncpynt (ifr.lifr_name, tt->actual_name, sizeof (ifr.lifr_name));
		ifr.lifr_ppa = ppa;
		/* Assign ppa according to the unit number returned by tun device */
		if (ioctl (if_fd, SIOCSLIFNAME, &ifr) < 0)
			msg (M_ERR, "Can't set PPA %d", ppa);
		if (ioctl(if_fd, SIOCGLIFFLAGS, &ifr) <0)
			msg (M_ERR, "Can't get flags\n");
		/* Push arp module to if_fd */
		if (ioctl (if_fd, I_PUSH, "arp") < 0)
			msg (M_ERR, "Can't push ARP module");

		/* Pop any modules on the stream */
		while (true) {
			if (ioctl (tt->engine_data->ip_fd, I_POP, NULL) < 0)
			break;
		}
		/* Push arp module to ip_fd */
		if (ioctl (tt->engine_data->ip_fd, I_PUSH, "arp") < 0)
			msg (M_ERR, "Can't push ARP module\n");

		/* Open arp_fd */
		if ((arp_fd = open (arp_node, O_RDWR, 0)) < 0)
			msg (M_ERR, "Can't open %s\n", arp_node);
		/* Push arp module to arp_fd */
		if (ioctl (arp_fd, I_PUSH, "arp") < 0)
			msg (M_ERR, "Can't push ARP module\n");

		/* Set ifname to arp */
		strioc_if.ic_cmd = SIOCSLIFNAME;
		strioc_if.ic_timout = 0;
		strioc_if.ic_len = sizeof(ifr);
		strioc_if.ic_dp = (char *)&ifr;
		if (ioctl(arp_fd, I_STR, &strioc_if) < 0) {
			msg (M_ERR, "Can't set ifname to arp\n");
		}
	}

	if ((ip_muxid = ioctl (tt->engine_data->ip_fd, link_type, if_fd)) < 0)
		msg (M_ERR, "Can't link %s device to IP", dev_tuntap_type);

	if (tt->type == DEV_TYPE_TAP) {
		if ((arp_muxid = ioctl (tt->engine_data->ip_fd, link_type, arp_fd)) < 0)
			msg (M_ERR, "Can't link %s device to ARP", dev_tuntap_type);
		close (arp_fd);
	}

	CLEAR (ifr);
	strncpynt (ifr.lifr_name, tt->actual_name, sizeof (ifr.lifr_name));
	ifr.lifr_ip_muxid  = ip_muxid;
	if (tt->type == DEV_TYPE_TAP) {
		ifr.lifr_arp_muxid = arp_muxid;
	}

	if (ioctl (tt->engine_data->ip_fd, SIOCSLIFMUXID, &ifr) < 0) {
		if (tt->type == DEV_TYPE_TAP) {
			ioctl (tt->engine_data->ip_fd, I_PUNLINK , arp_muxid);
		}
		ioctl (tt->engine_data->ip_fd, I_PUNLINK, ip_muxid);
		msg (M_ERR, "Can't set multiplexor id");
	}

	set_nonblock (tt->fd);
	set_cloexec (tt->fd);
	set_cloexec (tt->engine_data->ip_fd);

	msg (M_INFO, "TUN/TAP device %s opened", tt->actual_name);
	tt->did_opened = true;
}

/*
 * Close TUN device. 
 */
static
void
tun_engine_solaris_tun_close (struct tuntap *tt)
{
	if (tt) {
		/* IPv6 interfaces need to be 'manually' de-configured */
		if ( tt->ipv6 && tt->did_ifconfig_ipv6_setup ) {
			struct argv argv;
			argv_init (&argv);
			argv_printf( &argv, "%s %s inet6 unplumb",
			IFCONFIG_PATH, tt->actual_name );
			argv_msg (M_INFO, &argv);
			openvpn_execve_check (&argv, NULL, 0, "Solaris ifconfig inet6 unplumb failed");
			argv_reset (&argv);
		}

		if (tt->engine_data->ip_fd >= 0) {
			struct lifreq ifr;
			CLEAR (ifr);
			strncpynt (ifr.lifr_name, tt->actual_name, sizeof (ifr.lifr_name));

			if (ioctl (tt->engine_data->ip_fd, SIOCGLIFFLAGS, &ifr) < 0)
				msg (M_WARN | M_ERRNO, "Can't get iface flags");

			if (ioctl (tt->engine_data->ip_fd, SIOCGLIFMUXID, &ifr) < 0)
				msg (M_WARN | M_ERRNO, "Can't get multiplexor id");

			if (tt->type == DEV_TYPE_TAP) {
				if (ioctl (tt->engine_data->ip_fd, I_PUNLINK, ifr.lifr_arp_muxid) < 0)
				msg (M_WARN | M_ERRNO, "Can't unlink interface(arp)");
			}

			if (ioctl (tt->engine_data->ip_fd, I_PUNLINK, ifr.lifr_ip_muxid) < 0)
				msg (M_WARN | M_ERRNO, "Can't unlink interface(ip)");

			close (tt->engine_data->ip_fd);
			tt->engine_data->ip_fd = -1;
		}

		tun_engine_common_tun_close_generic(tt);
	}
}

static
int
tun_engine_solaris_tun_write (struct tuntap* tt, struct buffer *buf)
{
	struct strbuf sbuf;
	sbuf.len = BLEN(buf);
	sbuf.buf = (char *)BPTR(buf);
	return putmsg (tt->fd, NULL, &sbuf, 0) >= 0 ? sbuf.len : -1;
}

static
int
tun_engine_solaris_tun_read (struct tuntap* tt, struct buffer *buf, int size, int maxsize)
{
	struct strbuf sbuf;
	int f = 0;

	ASSERT (buf_init (buf, size));
	ASSERT (buf_safe (buf, maxsize));

	sbuf.maxlen = maxsize;
	sbuf.buf = (char *)BPTR(buf);
	buf->len = getmsg (tt->fd, NULL, &sbuf, &f) >= 0 ? sbuf.len : -1;
	return buf->len;
}

static
void
tun_engine_solaris_tun_ifconfig (
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

	/* Solaris 2.6 (and 7?) cannot set all parameters in one go...
	 * example:
	 *    ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 up
	 *    ifconfig tun2 netmask 255.255.255.255
	 */
	if (tun) {
		argv_printf (&argv,
			"%s %s %s %s mtu %d up",
			IFCONFIG_PATH,
			actual,
			ifconfig_local,
			ifconfig_remote_netmask,
			tun_mtu
		);

		argv_msg (M_INFO, &argv);
		if (!openvpn_execve_check (&argv, es, 0, "Solaris ifconfig phase-1 failed"))
			solaris_error_close (tt, es, actual, false);

		argv_printf (&argv,
			"%s %s netmask 255.255.255.255",
			IFCONFIG_PATH,
			actual
		);
	}
	else {
		if (tt->topology == TOP_SUBNET) {
			argv_printf (&argv,
				"%s %s %s %s netmask %s mtu %d up",
				IFCONFIG_PATH,
				actual,
				ifconfig_local,
				ifconfig_local,
				ifconfig_remote_netmask,
				tun_mtu
			);
		}
		else
			argv_printf (&argv,
				" %s %s %s netmask %s broadcast + up",
				IFCONFIG_PATH,
				actual,
				ifconfig_local,
				ifconfig_remote_netmask
			);
	}

	argv_msg (M_INFO, &argv);
	if (!openvpn_execve_check (&argv, es, 0, "Solaris ifconfig phase-2 failed"))
		solaris_error_close (tt, es, actual, false);

	if ( do_ipv6 ) {
		argv_printf (&argv, "%s %s inet6 unplumb",
		IFCONFIG_PATH, actual );
		argv_msg (M_INFO, &argv);
		openvpn_execve_check (&argv, es, 0, NULL);

		if ( tt->type == DEV_TYPE_TUN ) {
			argv_printf (&argv,
				"%s %s inet6 plumb %s/%d %s up",
				IFCONFIG_PATH,
				actual,
				ifconfig_ipv6_local,
				tt->netbits_ipv6,
				ifconfig_ipv6_remote
			);
		}
		else {	/* tap mode */
			/* base IPv6 tap interface needs to be brought up first
			 */
			argv_printf (&argv, "%s %s inet6 plumb up",
			IFCONFIG_PATH, actual );
			argv_msg (M_INFO, &argv);
			if (!openvpn_execve_check (&argv, es, 0, "Solaris ifconfig IPv6 (prepare) failed"))
				solaris_error_close (tt, es, actual, true);

			/* we might need to do "ifconfig %s inet6 auto-dhcp drop"
			 * after the system has noticed the interface and fired up
			 * the DHCPv6 client - but this takes quite a while, and the 
			 * server will ignore the DHCPv6 packets anyway.  So we don't.
			 */

			/* static IPv6 addresses need to go to a subinterface (tap0:1)
			 */
			argv_printf (&argv,
				"%s %s inet6 addif %s/%d up",
				IFCONFIG_PATH, actual,
				ifconfig_ipv6_local, tt->netbits_ipv6 );
		}
		argv_msg (M_INFO, &argv);
		if (!openvpn_execve_check (&argv, es, 0, "Solaris ifconfig IPv6 failed"))
			solaris_error_close (tt, es, actual, true);
	}

	if (!tun && tt->topology == TOP_SUBNET) {
		/* Add a network route for the local tun interface */
		struct route r;
		CLEAR (r);      
		r.flags = RT_DEFINED | RT_METRIC_DEFINED;
		r.network = tt->local & tt->remote_netmask;
		r.netmask = tt->remote_netmask;
		r.gateway = tt->local;  
		r.metric = 0;
		add_route (&r, tt, 0, NULL, es);
	}

	tt->did_ifconfig = true;

	argv_reset (&argv);
}

static struct tun_engine_s _tun_engine = {
	tun_engine_common_tun_init,
	NULL, /* tun_init_post */
	tun_engine_solaris_tun_state_reset,
	tun_engine_solaris_tun_open,
	tun_engine_solaris_tun_close,
	NULL, /* tun_stop */
	tun_engine_common_tun_status,
	tun_engine_solaris_tun_write,
	tun_engine_solaris_tun_read,
	NULL, /* tun_write_queue */
	NULL, /* tun_read_queue */
	NULL, /* tun_info */
	NULL, /* tun_debug_show */
	NULL, /* tun_standby_init */
	NULL, /* tun_standby */
	NULL, /* tun_config */
	NULL, /* tun_device_guess */
	NULL, /* tun_device_open_dynamic */
	tun_engine_solaris_tun_ifconfig,
	tun_engine_common_tun_is_p2p,
	NULL, /* route_add_connected_v6_net */
	NULL  /* route_delete_connected */
};
tun_engine_t tun_engine = &_tun_engine;

#endif
