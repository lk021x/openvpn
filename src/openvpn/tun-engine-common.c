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

#include "syshead.h"
#include "tun.h"
#include "tun-engine.h"
#include "route.h"
#include "socket.h"

/* --ifconfig-nowarn disables some options sanity checking */
static const char ifconfig_warn_how_to_silence[] = "(silence this warning with --ifconfig-nowarn)";

/*
 * Check that --local and --remote addresses do not
 * clash with ifconfig addresses or subnet.
 */
static void
check_addr_clash (
	const char *name,
	int type,
	in_addr_t public,
	in_addr_t local,
	in_addr_t remote_netmask
)
{
	struct gc_arena gc = gc_new ();
#if 0
	msg (M_INFO, "CHECK_ADDR_CLASH type=%d public=%s local=%s, remote_netmask=%s",
	type,
	print_in_addr_t (public, 0, &gc),
	print_in_addr_t (local, 0, &gc),
	print_in_addr_t (remote_netmask, 0, &gc));
#endif

	if (public) {
		if (type == DEV_TYPE_TUN) {
			const in_addr_t test_netmask = 0xFFFFFF00;
			const in_addr_t public_net = public & test_netmask;
			const in_addr_t local_net = local & test_netmask;
			const in_addr_t remote_net = remote_netmask & test_netmask;

			if (public == local || public == remote_netmask)
				msg (M_WARN,
					"WARNING: --%s address [%s] conflicts with --ifconfig address pair [%s, %s]. %s",
					name,
					print_in_addr_t (public, 0, &gc),
					print_in_addr_t (local, 0, &gc),
					print_in_addr_t (remote_netmask, 0, &gc),
					ifconfig_warn_how_to_silence);

			if (public_net == local_net || public_net == remote_net)
				msg (M_WARN,
					"WARNING: potential conflict between --%s address [%s] and --ifconfig address pair [%s, %s] -- this is a warning only that is triggered when local/remote addresses exist within the same /24 subnet as --ifconfig endpoints. %s",
					name,
					print_in_addr_t (public, 0, &gc),
					print_in_addr_t (local, 0, &gc),
					print_in_addr_t (remote_netmask, 0, &gc),
					ifconfig_warn_how_to_silence);
		}
		else if (type == DEV_TYPE_TAP) {
			const in_addr_t public_network = public & remote_netmask;
			const in_addr_t virtual_network = local & remote_netmask;
			if (public_network == virtual_network)
				msg (M_WARN,
					"WARNING: --%s address [%s] conflicts with --ifconfig subnet [%s, %s] -- local and remote addresses cannot be inside of the --ifconfig subnet. %s",
					name,
					print_in_addr_t (public, 0, &gc),
					print_in_addr_t (local, 0, &gc),
					print_in_addr_t (remote_netmask, 0, &gc),
					ifconfig_warn_how_to_silence);
		}
	}
	gc_free (&gc);
}

/*
 * If !tun, make sure ifconfig_remote_netmask looks
 *  like a netmask.
 *
 * If tun, make sure ifconfig_remote_netmask looks
 *  like an IPv4 address.
 */
static void
ifconfig_sanity_check (bool tun, in_addr_t addr, int topology)
{
	struct gc_arena gc = gc_new ();
	const bool looks_like_netmask = ((addr & 0xFF000000) == 0xFF000000);
	if (tun) {
		if (looks_like_netmask && (topology == TOP_NET30 || topology == TOP_P2P))
			msg (M_WARN, "WARNING: Since you are using --dev tun with a point-to-point topology, the second argument to --ifconfig must be an IP address.  You are using something (%s) that looks more like a netmask. %s",
				print_in_addr_t (addr, 0, &gc),
				ifconfig_warn_how_to_silence);
	}
	else { /* tap */
		if (!looks_like_netmask)
			msg (M_WARN, "WARNING: Since you are using --dev tap, the second argument to --ifconfig must be a netmask, for example something like 255.255.255.0. %s",
				ifconfig_warn_how_to_silence);
	}
	gc_free (&gc);
}

/*
 * For TAP-style devices, generate a broadcast address.
 */
static in_addr_t
generate_ifconfig_broadcast_addr (in_addr_t local, in_addr_t netmask)
{
	return local | ~netmask;
}

void
tun_engine_common_tun_open_null (struct tuntap *tt)
{
	tt->actual_name = string_alloc ("null", NULL);
}

/*
 * Init tun/tap object.
 *
 * Set up tuntap structure for ifconfig,
 * but don't execute yet.
 */
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
)
{
	struct gc_arena gc = gc_new ();
	struct tuntap *tt;

	ALLOC_OBJ_CLEAR (tt, struct tuntap);
	tt->engine = engine;
	tt->engine->tun_state_reset (tt);
	tt->type = tun_dev_type_enum (dev, dev_type);
	tt->topology = topology;

	if (ifconfig_local_parm && ifconfig_remote_netmask_parm) {
		bool tun = false;
		const char *ifconfig_local = NULL;
		const char *ifconfig_remote_netmask = NULL;
		const char *ifconfig_broadcast = NULL;

		/*
		 * We only handle TUN/TAP devices here, not --dev null devices.
		 */
		tun = tt->engine->tun_is_p2p (tt);

		/*
		 * Convert arguments to binary IPv4 addresses.
		 */

		tt->local = getaddr (
			GETADDR_RESOLVE
			| GETADDR_HOST_ORDER
			| GETADDR_FATAL_ON_SIGNAL
			| GETADDR_FATAL,
			ifconfig_local_parm,
			0,
			NULL,
			NULL
		);

		tt->remote_netmask = getaddr (
			(tun ? GETADDR_RESOLVE : 0)
			| GETADDR_HOST_ORDER
			| GETADDR_FATAL_ON_SIGNAL
			| GETADDR_FATAL,
			ifconfig_remote_netmask_parm,
			0,
			NULL,
			NULL
		);

		/*
		 * Look for common errors in --ifconfig parms
		 */
		if (strict_warn) {
			ifconfig_sanity_check (tt->type == DEV_TYPE_TUN, tt->remote_netmask, tt->topology);

			/*
			 * If local_public or remote_public addresses are defined,
			 * make sure they do not clash with our virtual subnet.
			 */

			check_addr_clash ("local",
				tt->type,
				local_public,
				tt->local,
				tt->remote_netmask
			);

			check_addr_clash ("remote",
				tt->type,
				remote_public,
				tt->local,
				tt->remote_netmask
			);
		}

		/*
		 * Set ifconfig parameters
		 */
		ifconfig_local = print_in_addr_t (tt->local, 0, &gc);
		ifconfig_remote_netmask = print_in_addr_t (tt->remote_netmask, 0, &gc);

		/*
		 * If TAP-style interface, generate broadcast address.
		 */
		if (!tun) {
			tt->broadcast = generate_ifconfig_broadcast_addr (tt->local, tt->remote_netmask);
			ifconfig_broadcast = print_in_addr_t (tt->broadcast, 0, &gc);
		}

		/*
		 * Set environmental variables with ifconfig parameters.
		 */
		if (es) {
			setenv_str (es, "ifconfig_local", ifconfig_local);
			if (tun) {
				setenv_str (es, "ifconfig_remote", ifconfig_remote_netmask);
			}
			else {
				setenv_str (es, "ifconfig_netmask", ifconfig_remote_netmask);
				setenv_str (es, "ifconfig_broadcast", ifconfig_broadcast);
			}
		}

		tt->did_ifconfig_setup = true;
	}

	if (ifconfig_ipv6_local_parm && ifconfig_ipv6_remote_parm) {
		const char *ifconfig_ipv6_local = NULL;
		const char *ifconfig_ipv6_remote = NULL;

		/*
		 * Convert arguments to binary IPv6 addresses.
		 */

		if ( inet_pton( AF_INET6, ifconfig_ipv6_local_parm, &tt->local_ipv6 ) != 1 ||
		inet_pton( AF_INET6, ifconfig_ipv6_remote_parm, &tt->remote_ipv6 ) != 1 ) {
			msg( M_FATAL, "init_tun: problem converting IPv6 ifconfig addresses %s and %s to binary", ifconfig_ipv6_local_parm, ifconfig_ipv6_remote_parm );
		}
		tt->netbits_ipv6 = ifconfig_ipv6_netbits_parm;

		/*
		 * Set ifconfig parameters
		 */
		ifconfig_ipv6_local = print_in6_addr (tt->local_ipv6, 0, &gc);
		ifconfig_ipv6_remote = print_in6_addr (tt->remote_ipv6, 0, &gc);

		/*
		 * Set environmental variables with ifconfig parameters.
		 */
		if (es) {
			setenv_str (es, "ifconfig_ipv6_local", ifconfig_ipv6_local);
			setenv_int (es, "ifconfig_ipv6_netbits", tt->netbits_ipv6);
			setenv_str (es, "ifconfig_ipv6_remote", ifconfig_ipv6_remote);
		}
		tt->did_ifconfig_ipv6_setup = true;
	}

	tt->ipv6 = ipv6;

	gc_free (&gc);
	return tt;
}

void
tun_engine_common_tun_state_reset (struct tuntap *tt)
{
	tun_engine_t engine = tt->engine;
	tun_engine_private_data_t engine_data = tt->engine_data;
	CLEAR (*tt);
	tt->engine = engine;
	tt->engine_data = engine_data;
#ifndef WIN32
	tt->fd = -1;
#endif
}

/*
 * Return a status string describing wait state.
 */
const char *
tun_engine_common_tun_status (const struct tuntap *tt, unsigned int rwflags, struct gc_arena *gc)
{
	struct buffer out = alloc_buf_gc (64, gc);
	if (rwflags & EVENT_READ) {
		buf_printf (&out, "T%s",
			(tt->rwflags_debug & EVENT_READ) ? "R" : "r");
	}
	if (rwflags & EVENT_WRITE) {
		buf_printf (&out, "T%s",
			(tt->rwflags_debug & EVENT_WRITE) ? "W" : "w");
	}
	return BSTR (&out);
}

/*
 * Return true for point-to-point topology, false for subnet topology
 */
bool
tun_engine_common_tun_is_p2p (const struct tuntap *tt)
{
	bool tun = false;

	if (tt->type == DEV_TYPE_TAP || (tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET))
		tun = false;
	else if (tt->type == DEV_TYPE_TUN)
		tun = true;
	else
		msg (M_FATAL, "Error: problem with tun vs. tap setting"); /* JYFIXME -- needs to be caught earlier, in init_tun? */

	return tun;
}

/* some of the platforms will auto-add a "network route" pointing
 * to the interface on "ifconfig tunX 2001:db8::1/64", others need
 * an extra call to "route add..."
 * -> helper function to simplify code below
 */
void
tun_engine_common_route_add_connected_v6_net(struct tuntap * tt,
	const struct env_set *es)
{
	struct route_ipv6 r6;

	r6.defined = true;
	r6.network = tt->local_ipv6;
	r6.netbits = tt->netbits_ipv6;
	r6.gateway = tt->local_ipv6;
	r6.metric  = 0;		/* connected route */
	r6.metric_defined = true;
	add_route_ipv6 (&r6, tt, 0, es);
}

void
tun_engine_common_route_delete_connected_v6_net(struct tuntap * tt,
	const struct env_set *es)
{
	struct route_ipv6 r6;

	r6.defined = true;
	r6.network = tt->local_ipv6;
	r6.netbits = tt->netbits_ipv6;
	r6.gateway = tt->local_ipv6;
	r6.metric  = 0;		/* connected route */
	r6.metric_defined = true;
	delete_route_ipv6 (&r6, tt, 0, es);
}

void
tun_engine_common_tun_close_generic (struct tuntap *tt)
{
	if (tt != NULL) {
#ifndef WIN32
		if (tt->fd >= 0) {
			close (tt->fd);
			tt->fd = -1;
		}
#endif
		if (tt->actual_name) {
			free (tt->actual_name);
			tt->actual_name = NULL;
		}
		tt->engine->tun_state_reset (tt);
		if (tt->engine_data != NULL) {
			free(tt->engine_data);
			tt->engine_data = NULL;
		}
		free(tt);
	}
}

#ifndef WIN32

void
tun_engine_common_tun_open_generic (const char *dev, const char *dev_type, const char *dev_node,
	bool ipv6_explicitly_supported, bool dynamic,
	struct tuntap *tt)
{
	char tunname[256];
	char dynamic_name[256];
	bool dynamic_opened = false;


	if ( tt->ipv6 && ! ipv6_explicitly_supported )
		msg (M_WARN, "NOTE: explicit support for IPv6 tun devices is not provided for this OS");

	if (tt->type == DEV_TYPE_NULL) {
		tun_engine_common_tun_open_null (tt);
	}
	else {
		/*
		 * --dev-node specified, so open an explicit device node
		 */
		if (dev_node) {
			openvpn_snprintf (tunname, sizeof (tunname), "%s", dev_node);
		}
		else {
			/*
			 * dynamic open is indicated by --dev specified without
			 * explicit unit number.  Try opening /dev/[dev]n
			 * where n = [0, 255].
			 */
			if (dynamic) {
				if (tt->engine->tun_device_open_dynamic != NULL) {
					if (tt->engine->tun_device_open_dynamic(
						tt, dev,
						dynamic_name, sizeof(dynamic_name)
					)) {
						dynamic_opened = true;
						openvpn_snprintf (tunname, sizeof (tunname), "/dev/%s", dynamic_name );
					}
				}

				if (!dynamic_opened && !has_digit((unsigned char *)dev)) {
					int i;
					for (i = 0; i < 256; ++i) {
						openvpn_snprintf (tunname, sizeof (tunname),
							"/dev/%s%d", dev, i);
							openvpn_snprintf (dynamic_name, sizeof (dynamic_name),
							"%s%d", dev, i);
						if ((tt->fd = open (tunname, O_RDWR)) > 0) {
							dynamic_opened = true;
							break;
						}
						msg (D_READ_WRITE | M_ERRNO, "Tried opening %s (failed)", tunname);
					}
					if (!dynamic_opened)
						msg (M_FATAL, "Cannot allocate TUN/TAP dev dynamically");
				}
			}

			/*
			 * explicit unit number specified
			 */
			if (!dynamic_opened) {
				openvpn_snprintf (tunname, sizeof (tunname), "/dev/%s", dev);
			}
		}

		if (!dynamic_opened) {
			if ((tt->fd = open (tunname, O_RDWR)) < 0)
				msg (M_ERR, "Cannot open TUN/TAP dev %s", tunname);
		}

		set_nonblock (tt->fd);
		set_cloexec (tt->fd); /* don't pass fd to scripts */
		msg (M_INFO, "TUN/TAP device %s opened", tunname);

		/* tt->actual_name is passed to up and down scripts and used as the ifconfig dev name */
		tt->actual_name = string_alloc (dynamic_opened ? dynamic_name : dev, NULL);

		tt->did_opened = true;
	}
}

int
tun_engine_common_tun_write (struct tuntap* tt, struct buffer *buf)
{
	return write (tt->fd, BPTR(buf), BLEN(buf));
}

int
tun_engine_common_tun_read (struct tuntap* tt, struct buffer *buf, int size, int maxsize)
{
	ASSERT (buf_init (buf, size));
	ASSERT (buf_safe (buf, maxsize));
	buf->len = read (tt->fd, BPTR(buf), maxsize);
	return buf->len;
}

#endif
