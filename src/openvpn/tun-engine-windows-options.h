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

#ifndef __TUN_ENGINE_WINDOWS_OPTIONS_H
#define __TUN_ENGINE_WINDOWS_OPTIONS_H

#ifdef WIN32

#define tun_engine_options_s_defined
struct tun_engine_options_s {
  /* --ip-win32 options */
  bool ip_win32_defined;

# define IPW32_SET_MANUAL       0  /* "--ip-win32 manual" */
# define IPW32_SET_NETSH        1  /* "--ip-win32 netsh" */
# define IPW32_SET_IPAPI        2  /* "--ip-win32 ipapi" */
# define IPW32_SET_DHCP_MASQ    3  /* "--ip-win32 dynamic" */
# define IPW32_SET_ADAPTIVE     4  /* "--ip-win32 adaptive" */
# define IPW32_SET_N            5
  int ip_win32_type;

  /* --ip-win32 dynamic options */
  bool dhcp_masq_custom_offset;
  int dhcp_masq_offset;
  int dhcp_lease_time;

  /* --tap-sleep option */
  int tap_sleep;

  /* --dhcp-option options */

  bool dhcp_options;

  const char *domain;        /* DOMAIN (15) */

  const char *netbios_scope; /* NBS (47) */

  int netbios_node_type;     /* NBT 1,2,4,8 (46) */

#define N_DHCP_ADDR 4        /* Max # of addresses allowed for
			        DNS, WINS, etc. */

  /* DNS (6) */
  in_addr_t dns[N_DHCP_ADDR];
  int dns_len;

  /* WINS (44) */
  in_addr_t wins[N_DHCP_ADDR];
  int wins_len;

  /* NTP (42) */
  in_addr_t ntp[N_DHCP_ADDR];
  int ntp_len;

  /* NBDD (45) */
  in_addr_t nbdd[N_DHCP_ADDR];
  int nbdd_len;

  /* DISABLE_NBT (43, Vendor option 001) */
  bool disable_nbt;

  bool dhcp_renew;
  bool dhcp_pre_release;
  bool dhcp_release;

  bool register_dns;
};

#endif

#endif
