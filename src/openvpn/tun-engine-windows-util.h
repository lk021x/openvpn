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

#ifndef TUN_ENGINE_WINDOWS_UTIL_H
#define TUN_ENGINE_WINDOWS_UTIL_H

#ifdef WIN32

#define TUN_ADAPTER_INDEX_INVALID ((DWORD)-1)

/* time constants for --ip-win32 adaptive */
#define IPW32_SET_ADAPTIVE_DELAY_WINDOW 300
#define IPW32_SET_ADAPTIVE_TRY_NETSH    20

struct tap_reg
{
  const char *guid;
  struct tap_reg *next;
};

struct panel_reg
{
  const char *name;
  const char *guid;
  struct panel_reg *next;
};

int ascii2ipset (const char* name);
const char *ipset2ascii (int index);
const char *ipset2ascii_all (struct gc_arena *gc);

const IP_ADAPTER_INFO *get_adapter_info_list (struct gc_arena *gc);
const IP_ADAPTER_INFO *get_tun_adapter (const struct tuntap *tt, const IP_ADAPTER_INFO *list);

const IP_ADAPTER_INFO *get_adapter_info (DWORD index, struct gc_arena *gc);
const IP_PER_ADAPTER_INFO *get_per_adapter_info (const DWORD index, struct gc_arena *gc);
const IP_ADAPTER_INFO *get_adapter (const IP_ADAPTER_INFO *ai, DWORD index);

bool is_adapter_up (const struct tuntap *tt, const IP_ADAPTER_INFO *list);
bool is_ip_in_adapter_subnet (const IP_ADAPTER_INFO *ai, const in_addr_t ip, in_addr_t *highest_netmask);

DWORD adapter_index_of_ip (const IP_ADAPTER_INFO *list,
			   const in_addr_t ip,
			   int *count,
			   in_addr_t *netmask);

void show_tap_win_adapters (int msglev, int warnlev);
void show_adapters (int msglev);

void tap_allow_nonadmin_access (const char *dev_node);

void show_valid_win32_tun_subnets (void);

bool dhcp_release_by_adapter_index(const DWORD adapter_index);
bool dhcp_renew_by_adapter_index (const DWORD adapter_index);

void fork_register_dns_action (struct tuntap *tt);
void ipconfig_register_dns (const struct env_set *es);

#endif /* WIN32 */

#endif /* TUN_ENGINE_WINDOWS_UTIL_H */
