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

#ifdef TARGET_LINUX

#include "syshead.h"
#include "socket.h"
#include "fdmisc.h"
#include "tun.h"
#include "tun-engine.h"
#include "tun-engine-common.h"
#include "tun-engine-linux-options.h"

#if defined(HAVE_NETINET_IF_ETHER_H)
#include <netinet/if_ether.h>
#endif

#ifdef HAVE_LINUX_IF_TUN_H
#include <linux/if_tun.h>
#endif

#ifdef HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif

#ifdef HAVE_LINUX_TYPES_H
#include <linux/types.h>
#endif

#ifdef HAVE_LINUX_ERRQUEUE_H
#include <linux/errqueue.h>
#endif

struct tun_engine_private_data_s {
	struct tun_engine_options_s options;
};

static
void
tun_engine_linux_tun_init_post (
	struct tuntap *tt,
	const struct frame *frame,
	const tun_engine_options_t options
)
{
	tt->engine_data->options = *options;
}

void
tun_engine_linux_tun_state_reset (struct tuntap *tt) {
	tun_engine_common_tun_state_reset(tt);
	if (tt->engine_data == NULL) {
		ALLOC_OBJ(tt->engine_data, struct tun_engine_private_data_s);
	}
	{
		struct tun_engine_options_s options = tt->engine_data->options;
		CLEAR(*tt->engine_data);
		tt->engine_data->options = options;
	}
}

#ifdef HAVE_LINUX_IF_TUN_H	/* New driver support */

#ifndef HAVE_LINUX_SOCKIOS_H
#error header file linux/sockios.h required
#endif

static
void
tun_engine_linux_tun_open (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
	struct ifreq ifr;

	/*
	 * We handle --dev null specially, we do not open /dev/null for this.
	 */
	if (tt->type == DEV_TYPE_NULL) {
		tun_engine_common_tun_open_null (tt);
	}
	else {
		/*
		 * Process --dev-node
		 */
		const char *node = dev_node;
		if (!node)
			node = "/dev/net/tun";

		/*
		 * Open the interface
		 */
		if ((tt->fd = open (node, O_RDWR)) < 0) {
			msg (M_ERR, "ERROR: Cannot open TUN/TAP dev %s", node);
		}

		/*
		 * Process --tun-ipv6
		 */
		CLEAR (ifr);
		if (!tt->ipv6)
			ifr.ifr_flags = IFF_NO_PI;

#if defined(IFF_ONE_QUEUE) && defined(SIOCSIFTXQLEN)
		ifr.ifr_flags |= IFF_ONE_QUEUE;
#endif

		/*
		 * Figure out if tun or tap device
		 */
		if (tt->type == DEV_TYPE_TUN) {
			ifr.ifr_flags |= IFF_TUN;
		}
		else if (tt->type == DEV_TYPE_TAP) {
			ifr.ifr_flags |= IFF_TAP;
		}
		else {
			msg (M_FATAL, "I don't recognize device %s as a tun or tap device",
				dev);
		}

		/*
		 * Set an explicit name, if --dev is not tun or tap
		 */
		if (strcmp(dev, "tun") && strcmp(dev, "tap"))
			strncpynt (ifr.ifr_name, dev, IFNAMSIZ);

		/*
		 * Use special ioctl that configures tun/tap device with the parms
		 * we set in ifr
		 */
		if (ioctl (tt->fd, TUNSETIFF, (void *) &ifr) < 0) {
			msg (M_ERR, "ERROR: Cannot ioctl TUNSETIFF %s", dev);
		}

		msg (M_INFO, "TUN/TAP device %s opened", ifr.ifr_name);
		tt->did_opened = true;

		/*
		 * Try making the TX send queue bigger
		 */
#if defined(IFF_ONE_QUEUE) && defined(SIOCSIFTXQLEN)
		if (tt->engine_data->options.txqueuelen) {
			struct ifreq netifr;
			int ctl_fd;

			if ((ctl_fd = socket (AF_INET, SOCK_DGRAM, 0)) >= 0) {
				CLEAR (netifr);
				strncpynt (netifr.ifr_name, ifr.ifr_name, IFNAMSIZ);
				netifr.ifr_qlen = tt->engine_data->options.txqueuelen;
				if (ioctl (ctl_fd, SIOCSIFTXQLEN, (void *) &netifr) >= 0)
					msg (D_OSBUF, "TUN/TAP TX queue length set to %d", tt->engine_data->options.txqueuelen);
				else
					msg (M_WARN | M_ERRNO, "Note: Cannot set tx queue length on %s", ifr.ifr_name);
				close (ctl_fd);
			}
			else {
				msg (M_WARN | M_ERRNO, "Note: Cannot open control socket on %s", ifr.ifr_name);
			}
		}
#endif

		set_nonblock (tt->fd);
		set_cloexec (tt->fd);
		tt->actual_name = string_alloc (ifr.ifr_name, NULL);
	}
}

#else

static
void
tun_engine_linux_tun_open (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
	tun_engine_common_tun_open_generic (dev, dev_type, dev_node, false, true, tt);
}

#endif /* HAVE_LINUX_IF_TUN_H */

#ifdef ENABLE_FEATURE_TUN_PERSIST

/*
 * This can be removed in future
 * when all systems will use newer
 * linux-headers
 */
#ifndef TUNSETOWNER
#define TUNSETOWNER	_IOW('T', 204, int)
#endif
#ifndef TUNSETGROUP
#define TUNSETGROUP	_IOW('T', 206, int)
#endif

static
void
tun_engine_linux_tun_config (tun_engine_t engine, const char *dev, const char *dev_type, const char *dev_node, int persist_mode, const char *username, const char *groupname, const tun_engine_options_t options)
{
	struct tuntap *tt;

	ALLOC_OBJ_CLEAR (tt, struct tuntap);
	engine->tun_state_reset (tt);
	tt->engine = engine;
	tt->type = tun_dev_type_enum (dev, dev_type);
	tun_open (dev, dev_type, dev_node, tt);
	if (ioctl (tt->fd, TUNSETPERSIST, persist_mode) < 0)
		msg (M_ERR, "Cannot ioctl TUNSETPERSIST(%d) %s", persist_mode, dev);
	if (username != NULL) {
		struct platform_state_user platform_state_user;

		if (!platform_user_get (username, &platform_state_user))
			msg (M_ERR, "Cannot get user entry for %s", username);
		else
			if (ioctl (tt->fd, TUNSETOWNER, platform_state_user.pw->pw_uid) < 0)
				msg (M_ERR, "Cannot ioctl TUNSETOWNER(%s) %s", username, dev);
	}
	if (groupname != NULL) {
		struct platform_state_group platform_state_group;

		if (!platform_group_get (groupname, &platform_state_group))
			msg (M_ERR, "Cannot get group entry for %s", groupname);
		else
			if (ioctl (tt->fd, TUNSETGROUP, platform_state_group.gr->gr_gid) < 0)
				msg (M_ERR, "Cannot ioctl TUNSETOWNER(%s) %s", groupname, dev);
	}
	tt->engine->tun_close (tt);
	msg (M_INFO, "Persist state set to: %s", (persist_mode ? "ON" : "OFF"));
}

#else

static
void
tun_engine_linux_tun_config (const char *dev, const char *dev_type, const char *dev_node, int persist_mode, const char *username, const char *groupname, const tun_engine_options_t options)
{
}

#endif /* ENABLE_FEATURE_TUN_PERSIST */

static
void
tun_engine_linux_tun_close (struct tuntap *tt)
{
	if (tt) {
		if (tt->type != DEV_TYPE_NULL && tt->did_ifconfig) {
			struct argv argv;
			struct gc_arena gc = gc_new ();
			argv_init (&argv);

#ifdef ENABLE_IPROUTE
			if (tun_engine_common_tun_is_p2p (tt)) {
				argv_printf (
					&argv,
					"%s addr del dev %s local %s peer %s",
					iproute_path,
					tt->actual_name,
					print_in_addr_t (tt->local, 0, &gc),
					print_in_addr_t (tt->remote_netmask, 0, &gc)
				);
			}
			else {
				argv_printf (
					&argv,
					"%s addr del dev %s %s/%d",
					iproute_path,
					tt->actual_name,
					print_in_addr_t (tt->local, 0, &gc),
					count_netmask_bits(print_in_addr_t (tt->remote_netmask, 0, &gc))
				);
			}
#else
			argv_printf (
				&argv,
				"%s %s 0.0.0.0",
				IFCONFIG_PATH,
				tt->actual_name
			);
#endif

			argv_msg (M_INFO, &argv);
			openvpn_execve_check (&argv, NULL, 0, "Linux ip addr del failed");

			argv_reset (&argv);
			gc_free (&gc);
		}
		tun_engine_common_tun_close_generic (tt);
	}
}

static
int
tun_engine_linux_tun_write (struct tuntap* tt, struct buffer *buf)
{
	if (tt->ipv6) {
		struct tun_pi pi;
		struct iphdr *iph;
		struct iovec vect[2];
		int ret;

		iph = (struct iphdr *)BPTR(buf);

		pi.flags = 0;

		if(iph->version == 6)
			pi.proto = htons(ETH_P_IPV6);
		else
			pi.proto = htons(ETH_P_IP);

		vect[0].iov_len = sizeof(pi);
		vect[0].iov_base = &pi;
		vect[1].iov_len = BLEN(buf);
		vect[1].iov_base = BPTR(buf);

		ret = writev(tt->fd, vect, 2);
		return(ret - sizeof(pi));
	}
	else
		return write (tt->fd, BPTR(buf), BLEN(buf));
}

static
int
tun_engine_linux_tun_read (struct tuntap* tt, struct buffer *buf, int size, int maxsize)
{
	ASSERT (buf_init (buf, size));
	ASSERT (buf_safe (buf, maxsize));

	if (tt->ipv6) {
		struct iovec vect[2];
		struct tun_pi pi;
		int ret;

		vect[0].iov_len = sizeof(pi);
		vect[0].iov_base = &pi;
		vect[1].iov_len = maxsize;
		vect[1].iov_base = BPTR(buf);

		ret = readv(tt->fd, vect, 2);
		buf->len = ret - sizeof(pi);
	}
	else
		buf->len = read (tt->fd, BPTR(buf), maxsize);
	
	return buf->len;
}

static
void
tun_engine_linux_tun_ifconfig (
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

#ifdef ENABLE_IPROUTE
	/*
	* Set the MTU for the device
	*/
	argv_printf (&argv,
		"%s link set dev %s up mtu %d",
		iproute_path,
		actual,
		tun_mtu
	);
	argv_msg (M_INFO, &argv);
	openvpn_execve_check (&argv, es, S_FATAL, "Linux ip link set failed");

	if (tun) {
		/*
		 * Set the address for the device
		 */
		argv_printf (&argv,
		"%s addr add dev %s local %s peer %s",
		iproute_path,
		actual,
		ifconfig_local,
		ifconfig_remote_netmask
		);
		argv_msg (M_INFO, &argv);
		openvpn_execve_check (&argv, es, S_FATAL, "Linux ip addr add failed");
	}
	else {
		argv_printf (&argv,
			"%s addr add dev %s %s/%d broadcast %s",
			iproute_path,
			actual,
			ifconfig_local,
			count_netmask_bits(ifconfig_remote_netmask),
			ifconfig_broadcast
		);
		argv_msg (M_INFO, &argv);
		openvpn_execve_check (&argv, es, S_FATAL, "Linux ip addr add failed");
	}
	if ( do_ipv6 ) {
		argv_printf( &argv,
			"%s -6 addr add %s/%d dev %s",
			iproute_path,
			ifconfig_ipv6_local,
			tt->netbits_ipv6,
			actual
		);
		argv_msg (M_INFO, &argv);
		openvpn_execve_check (&argv, es, S_FATAL, "Linux ip -6 addr add failed");
	}
	tt->did_ifconfig = true;
#else
	if (tun)
		argv_printf (&argv,
			"%s %s %s pointopoint %s mtu %d",
			IFCONFIG_PATH,
			actual,
			ifconfig_local,
			ifconfig_remote_netmask,
			tun_mtu
		);
	else
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
	openvpn_execve_check (&argv, es, S_FATAL, "Linux ifconfig failed");
	if ( do_ipv6 ) {
		argv_printf (&argv,
			"%s %s inet6 add %s/%d",
			IFCONFIG_PATH,
			actual,
			ifconfig_ipv6_local,
			tt->netbits_ipv6
		);
		argv_msg (M_INFO, &argv);
		openvpn_execve_check (&argv, es, S_FATAL, "Linux ifconfig inet6 failed");
	}
	tt->did_ifconfig = true;
#endif /*ENABLE_IPROUTE*/

	argv_reset (&argv);
}

static struct tun_engine_s _tun_engine = {
	tun_engine_common_tun_init,
	tun_engine_linux_tun_init_post,
	tun_engine_linux_tun_state_reset,
	tun_engine_linux_tun_open,
	tun_engine_linux_tun_close,
	NULL, /* tun_stop */
	tun_engine_common_tun_status,
	tun_engine_linux_tun_write,
	tun_engine_linux_tun_read,
	NULL, /* tun_write_queue */
	NULL, /* tun_read_queue */
	NULL, /* tun_info */
	NULL, /* tun_debug_show */
	NULL, /* tun_standby_init */
	NULL, /* tun_standby */
	tun_engine_linux_tun_config,
	NULL, /* tun_device_guess */
	NULL, /* tun_device_open_dynamic */
	tun_engine_linux_tun_ifconfig,
	tun_engine_common_tun_is_p2p,
	NULL, /* route_add_connected_v6_net */
	NULL  /* route_delete_connected_v6_net */
};
tun_engine_t tun_engine = &_tun_engine;

#endif
