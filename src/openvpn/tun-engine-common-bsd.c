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

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#if \
	defined(TARGET_FREEBSD) || \
	defined(TARGET_NETBSD) || \
	defined(TARGET_DRAGONFLY) || \
	defined(TARGET_OPENBSD)

#include "syshead.h"
#include "tun.h"
#include "tun-engine.h"

#ifndef HAVE_STRUCT_IP
#define ip openvpn_iphdr
#endif

static inline int
bsd_modify_read_write_return (int len)
{
	if (len > 0)
		return len > sizeof (u_int32_t) ? len - sizeof (u_int32_t) : 0;
	else
		return len;
}

int
tun_engine_common_bsd_tun_write (struct tuntap* tt, struct buffer *buf)
{
	if (tt->type == DEV_TYPE_TUN) {
		u_int32_t type;
		struct iovec iv[2];
		struct ip *iph;

		iph = (struct ip *) BPTR(buf);

		if (tt->ipv6 && iph->ip_v == 6)
			type = htonl (AF_INET6);
		else 
			type = htonl (AF_INET);

		iv[0].iov_base = (char *)&type;
		iv[0].iov_len = sizeof (type);
		iv[1].iov_base = BPTR(buf);
		iv[1].iov_len = BLEN(buf);

		return bsd_modify_read_write_return (writev (tt->fd, iv, 2));
	}
	else
		return write (tt->fd, BPTR(buf), BLEN(buf));
}

int
tun_engine_common_bsd_tun_read (struct tuntap* tt, struct buffer *buf, int size, int maxsize)
{
	ASSERT (buf_init (buf, size));
	ASSERT (buf_safe (buf, maxsize));

	if (tt->type == DEV_TYPE_TUN) {
		u_int32_t type;
		struct iovec iv[2];

		iv[0].iov_base = (char *)&type;
		iv[0].iov_len = sizeof (type);
		iv[1].iov_base = BPTR(buf);
		iv[1].iov_len = maxsize;

		buf->len = bsd_modify_read_write_return (readv (tt->fd, iv, 2));
	}
	else
		buf->len = read (tt->fd, BPTR(buf), maxsize);
	
	return buf->len;
}

#endif
