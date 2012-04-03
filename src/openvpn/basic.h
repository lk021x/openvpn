/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

#ifndef BASIC_H
#define BASIC_H

#define BOOL_CAST(x) ((x) ? (true) : (false))

/* size of an array */
#define SIZE(x) (sizeof(x)/sizeof(x[0]))

/* clear an object */
#define CLEAR(x) memset(&(x), 0, sizeof(x))

#define IPV4_NETMASK_HOST 0xffffffffU

/* branch prediction hints */
#if defined(__GNUC__)
# define likely(x)       __builtin_expect((x),1)
# define unlikely(x)     __builtin_expect((x),0)
#else
# define likely(x)      (x)
# define unlikely(x)    (x)
#endif

/*
 * Lint mode is meant to accomplish lint-style program checking,
 * not to build a working executable.
 */
#ifdef ENABLE_LINT
# undef HAVE_CPP_VARARG_MACRO_GCC
# undef HAVE_CPP_VARARG_MACRO_ISO
# undef EMPTY_ARRAY_SIZE
# define EMPTY_ARRAY_SIZE 1
# ifdef inline
#  undef inline
# endif
#endif

/*
 * Our socket descriptor type.
 */
#ifdef WIN32
#define SOCKET_UNDEFINED (INVALID_SOCKET)
typedef SOCKET socket_descriptor_t;
#else
#define SOCKET_UNDEFINED (-1)
typedef int socket_descriptor_t;
#endif

static inline int
socket_defined (const socket_descriptor_t sd)
{
  return sd != SOCKET_UNDEFINED;
}

#endif
