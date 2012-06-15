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
#include "fdmisc.h"
#include "common.h"
#include "misc.h"
#include "socket.h"
#include "manage.h"
#include "route.h"
#include "win32.h"

#include "memdbg.h"

extern tun_engine_t tun_engine;

bool
tun_is_dev_type (const char *dev, const char *dev_type, const char *match_type)
{
  ASSERT (match_type);
  if (!dev)
    return false;
  if (dev_type)
    return !strcmp (dev_type, match_type);
  else
    return !strncmp (dev, match_type, strlen (match_type));
}

int
tun_dev_type_enum (const char *dev, const char *dev_type)
{
  if (tun_is_dev_type (dev, dev_type, "tun"))
    return DEV_TYPE_TUN;
  else if (tun_is_dev_type (dev, dev_type, "tap"))
    return DEV_TYPE_TAP;
  else if (tun_is_dev_type (dev, dev_type, "null"))
    return DEV_TYPE_NULL;
  else
    return DEV_TYPE_UNDEF;
}

const char *
tun_dev_type_string (const char *dev, const char *dev_type)
{
  switch ( tun_dev_type_enum (dev, dev_type))
    {
    case DEV_TYPE_TUN:
      return "tun";
    case DEV_TYPE_TAP:
      return "tap";
    case DEV_TYPE_NULL:
      return "null";
    default:
      return "[unknown-dev-type]";
    }
}

/*
 * Return a string to be used for options compatibility check
 * between peers.
 */
const char *
tun_ifconfig_options_string (const struct tuntap* tt, bool remote, bool disable, struct gc_arena *gc)
{
  struct buffer out = alloc_buf_gc (256, gc);
  if (tt->did_ifconfig_setup && !disable)
    {
      if (tt->type == DEV_TYPE_TAP || (tt->type == DEV_TYPE_TUN && tt->topology == TOP_SUBNET))
	{
	  buf_printf (&out, "%s %s",
		      print_in_addr_t (tt->local & tt->remote_netmask, 0, gc),
		      print_in_addr_t (tt->remote_netmask, 0, gc));
	}
      else if (tt->type == DEV_TYPE_TUN)
	{
	  const char *l, *r;
	  if (remote)
	    {
	      r = print_in_addr_t (tt->local, 0, gc);
	      l = print_in_addr_t (tt->remote_netmask, 0, gc);
	    }
	  else
	    {
	      l = print_in_addr_t (tt->local, 0, gc);
	      r = print_in_addr_t (tt->remote_netmask, 0, gc);
	    }
	  buf_printf (&out, "%s %s", r, l);
	}
      else
	buf_printf (&out, "[undef]");
    }
  return BSTR (&out);
}

struct tuntap *
tun_init (
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
	tun_engine_t engine = tun_engine;
	if (engine->tun_init == NULL) {
		return NULL;
	}
	return engine->tun_init(
		engine,
		dev,
		dev_type,
		topology,
		ifconfig_local_parm,
		ifconfig_remote_netmask_parm,
		ifconfig_ipv6_local_parm,
		ifconfig_ipv6_netbits_parm,
		ifconfig_ipv6_remote_parm,
		local_public,
		remote_public,
		strict_warn,
		ipv6,
		es
	);
}

void
tun_init_post (
	struct tuntap *tt,
	const struct frame *frame,
	const tun_engine_options_t options
)
{
	tun_engine_t engine = tt->engine;
	if (engine->tun_init_post == NULL) {
		return;
	}
	engine->tun_init_post (tt, frame, options);
}

/* execute the ifconfig command through the shell */
void
tun_ifconfig (struct tuntap *tt,
	     const char *actual,    /* actual device name */
	     int tun_mtu,
	     const struct env_set *es)
{
  struct gc_arena gc = gc_new ();

  if (tt->did_ifconfig_setup)
    {
      bool tun = false;
      const char *ifconfig_local = NULL;
      const char *ifconfig_remote_netmask = NULL;
      const char *ifconfig_broadcast = NULL;
      const char *ifconfig_ipv6_local = NULL;
      const char *ifconfig_ipv6_remote = NULL;
      bool do_ipv6 = false;

      msg( M_INFO, "do_ifconfig, tt->ipv6=%d, tt->did_ifconfig_ipv6_setup=%d",
	           tt->ipv6, tt->did_ifconfig_ipv6_setup );

      /*
       * We only handle TUN/TAP devices here, not --dev null devices.
       */
      tun = tt->engine->tun_is_p2p (tt);

      /*
       * Set ifconfig parameters
       */
      ifconfig_local = print_in_addr_t (tt->local, 0, &gc);
      ifconfig_remote_netmask = print_in_addr_t (tt->remote_netmask, 0, &gc);

      if ( tt->ipv6 && tt->did_ifconfig_ipv6_setup )
        {
	  ifconfig_ipv6_local = print_in6_addr (tt->local_ipv6, 0, &gc);
	  ifconfig_ipv6_remote = print_in6_addr (tt->remote_ipv6, 0, &gc);
	  do_ipv6 = true;
	}

      /*
       * If TAP-style device, generate broadcast address.
       */
      if (!tun)
	ifconfig_broadcast = print_in_addr_t (tt->broadcast, 0, &gc);

#ifdef ENABLE_MANAGEMENT
  if (management)
    {
      management_set_state (management,
			    OPENVPN_STATE_ASSIGN_IP,
			    NULL,
			    tt->local,
			    0);
    }
#endif

    if (tt->engine->tun_ifconfig != NULL)
      {
    	tt->engine->tun_ifconfig(tt, actual, tun_mtu, es, tun, 
	      ifconfig_local, ifconfig_remote_netmask,
	      ifconfig_broadcast, ifconfig_ipv6_local,
	      ifconfig_ipv6_remote, do_ipv6 );
      }

    }
  gc_free (&gc);
}

void tun_open (
	const char *dev,
	const char *dev_type,
	const char *dev_node,
	struct tuntap *tt
)
{
	tun_engine_t engine = tt->engine;
	if (engine->tun_open == NULL) {
		return;
	}
	engine->tun_open(dev, dev_type, dev_node, tt);
}

void tun_close (struct tuntap *tt)
{
	tun_engine_t engine = tt->engine;
	if (engine->tun_close == NULL) {
		return;
	}
	engine->tun_close(tt);
}

bool
tun_stop (struct tuntap *tt, int status)
{
	tun_engine_t engine = tt->engine;
	if (engine->tun_stop == NULL) {
		return false;
	}

	return engine->tun_stop(tt, status);
}

const char *tun_status (const struct tuntap *tt, unsigned int rwflags, struct gc_arena *gc)
{
	if (tt == NULL) {
		return "T?";
	}
	else {
		tun_engine_t engine = tt->engine;
		if (engine->tun_status == NULL) {
			return "T?";
		}
		return engine->tun_status(tt, rwflags, gc);
	}
}

int tun_write (struct tuntap* tt, struct buffer *buf)
{
	tun_engine_t engine = tt->engine;
	if (engine->tun_write == NULL) {
		return -1;
	}
	return engine->tun_write(tt, buf);
}

int tun_read (struct tuntap* tt, struct buffer *buf, int size, int maxsize)
{
	tun_engine_t engine = tt->engine;
	if (engine->tun_read == NULL) {
		return -1;
	}
	return engine->tun_read(tt, buf, size, maxsize);
}

int tun_write_queue (struct tuntap *tt, struct buffer *buf)
{
	tun_engine_t engine = tt->engine;
	if (engine->tun_write_queue == NULL) {
		return -1;
	}
	return engine->tun_write_queue(tt, buf);
}

int tun_read_queue (struct tuntap *tt, int maxsize)
{
	tun_engine_t engine = tt->engine;
	if (engine->tun_read_queue == NULL) {
		return -1;
	}
	return engine->tun_read_queue(tt, maxsize);
}

const char *tap_info (const struct tuntap *tt, struct gc_arena *gc)
{
	tun_engine_t engine = tt->engine;
	if (engine->tun_debug_show == NULL) {
		return NULL;
	}
	return engine->tun_info(tt, gc);
}

void tun_debug_show (struct tuntap *tt)
{
	tun_engine_t engine = tt->engine;
	if (engine->tun_debug_show != NULL) {
		engine->tun_debug_show(tt);
	}
}

void tun_standby_init (struct tuntap *tt) {
	tun_engine_t engine = tt->engine;
	if (engine->tun_standby_init == NULL) {
		return;
	}
	engine->tun_standby_init(tt);
}

bool tun_standby (struct tuntap *tt)
{
	tun_engine_t engine = tt->engine;
	if (engine->tun_standby == NULL) {
		return true;
	}
	return engine->tun_standby(tt);
}

void
tun_config (const char *dev, const char *dev_type, const char *dev_node, int persist_mode, const char *username, const char *groupname, const tun_engine_options_t options)
{
	tun_engine_t engine = tun_engine;
	if (engine->tun_config == NULL) {
		return;
	}
	engine->tun_config(engine, dev, dev_type, dev_node, persist_mode, username, groupname, options);
}

/*
 * Try to predict the actual TUN/TAP device instance name,
 * before the device is actually opened.
 */
const char *
tun_device_guess (
	struct tuntap *tt,
	const char *dev,
	const char *dev_type,
	const char *dev_node,
	struct gc_arena *gc
)
{
	tun_engine_t engine = tt->engine;
	if (engine->tun_device_guess == NULL) {
		return dev;
	}
	return engine->tun_device_guess(
		tt,
		dev,
		dev_type,
		dev_node,
		gc
	);
}


