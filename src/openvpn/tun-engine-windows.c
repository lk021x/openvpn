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

#ifdef WIN32

#include "syshead.h"

#include <winioctl.h>
#include <tap-windows.h>

#include "fdmisc.h"
#include "socket.h"
#include "tun.h"
#include "tun-engine.h"
#include "tun-engine-common.h"
#include "tun-engine-windows-options.h"
#include "tun-engine-windows-util.h"

/* #define SIMULATE_DHCP_FAILED */       /* simulate bad DHCP negotiation */

#define NI_TEST_FIRST  (1<<0)
#define NI_IP_NETMASK  (1<<1)
#define NI_OPTIONS     (1<<2)

struct tun_engine_private_data_s {
	struct tun_engine_options_s options;

	HANDLE hand;

	struct overlapped_io reads;
	struct overlapped_io writes;

	/* used for setting interface address via IP Helper API
	or DHCP masquerade */
	bool ipapi_context_defined;
	ULONG ipapi_context;
	ULONG ipapi_instance;
	in_addr_t adapter_netmask;

	/* Windows adapter index for TAP-Windows adapter,
	~0 if undefined */
	DWORD adapter_index;

	int standby_iter;
};

/*
 * Convert --ip-win32 constants between index and ascii form.
 */

struct ipset_names {
	const char *short_form;
};

/* Indexed by IPW32_SET_x */
static const struct ipset_names ipset_names[] = {
	{"manual"},
	{"netsh"},
	{"ipapi"},
	{"dynamic"},
	{"adaptive"}
};

int
ascii2ipset (const char* name)
{
	int i;
	ASSERT (IPW32_SET_N == SIZE (ipset_names));
	for (i = 0; i < IPW32_SET_N; ++i)
		if (!strcmp (name, ipset_names[i].short_form))
			return i;
	return -1;
}

const char *
ipset2ascii (int index)
{
	ASSERT (IPW32_SET_N == SIZE (ipset_names));
	if (index < 0 || index >= IPW32_SET_N)
		return "[unknown --ip-win32 type]";
	else
		return ipset_names[index].short_form;
}

const char *
ipset2ascii_all (struct gc_arena *gc)
{
	struct buffer out = alloc_buf_gc (256, gc);
	int i;

	ASSERT (IPW32_SET_N == SIZE (ipset_names));
	for (i = 0; i < IPW32_SET_N; ++i) {
		if (i)
			buf_printf(&out, " ");
		buf_printf(&out, "[%s]", ipset2ascii(i));
	}
	return BSTR (&out);
}

const struct tap_reg *
get_tap_reg (struct gc_arena *gc)
{
	HKEY adapter_key;
	LONG status;
	DWORD len;
	struct tap_reg *first = NULL;
	struct tap_reg *last = NULL;
	int i = 0;

	status = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		ADAPTER_KEY,
		0,
		KEY_READ,
		&adapter_key
	);

	if (status != ERROR_SUCCESS)
		msg (M_FATAL, "Error opening registry key: %s", ADAPTER_KEY);

	while (true) {
		char enum_name[256];
		char unit_string[256];
		HKEY unit_key;
		char component_id_string[] = "ComponentId";
		char component_id[256];
		char net_cfg_instance_id_string[] = "NetCfgInstanceId";
		char net_cfg_instance_id[256];
		DWORD data_type;

		len = sizeof (enum_name);
			status = RegEnumKeyEx(
			adapter_key,
			i,
			enum_name,
			&len,
			NULL,
			NULL,
			NULL,
			NULL
		);
		if (status == ERROR_NO_MORE_ITEMS)
			break;
		else if (status != ERROR_SUCCESS)
			msg (M_FATAL, "Error enumerating registry subkeys of key: %s",
				ADAPTER_KEY);

		openvpn_snprintf (unit_string, sizeof(unit_string), "%s\\%s",
		ADAPTER_KEY, enum_name);

		status = RegOpenKeyEx(
			HKEY_LOCAL_MACHINE,
			unit_string,
			0,
			KEY_READ,
			&unit_key
		);

		if (status != ERROR_SUCCESS)
			dmsg (D_REGISTRY, "Error opening registry key: %s", unit_string);
		else {
			len = sizeof (component_id);
			status = RegQueryValueEx(
				unit_key,
				component_id_string,
				NULL,
				&data_type,
				component_id,
				&len
			);

			if (status != ERROR_SUCCESS || data_type != REG_SZ)
				dmsg (D_REGISTRY, "Error opening registry key: %s\\%s",
					unit_string, component_id_string);
			else {	      
				len = sizeof (net_cfg_instance_id);
				status = RegQueryValueEx(
					unit_key,
					net_cfg_instance_id_string,
					NULL,
					&data_type,
					net_cfg_instance_id,
					&len
				);

				if (status == ERROR_SUCCESS && data_type == REG_SZ) {
					if (!strcmp (component_id, TAP_WIN_COMPONENT_ID)) {
						struct tap_reg *reg;
						ALLOC_OBJ_CLEAR_GC (reg, struct tap_reg, gc);
						reg->guid = string_alloc (net_cfg_instance_id, gc);

						/* link into return list */
						if (!first)
							first = reg;
						if (last)
							last->next = reg;
						last = reg;
					}
				}
			}
			RegCloseKey (unit_key);
		}
		++i;
	}

	RegCloseKey (adapter_key);
	return first;
}

const struct panel_reg *
get_panel_reg (struct gc_arena *gc)
{
	LONG status;
	HKEY network_connections_key;
	DWORD len;
	struct panel_reg *first = NULL;
	struct panel_reg *last = NULL;
	int i = 0;

	status = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		NETWORK_CONNECTIONS_KEY,
		0,
		KEY_READ,
		&network_connections_key
	);

	if (status != ERROR_SUCCESS)
		msg (M_FATAL, "Error opening registry key: %s", NETWORK_CONNECTIONS_KEY);

	while (true) {
		char enum_name[256];
		char connection_string[256];
		HKEY connection_key;
		char name_data[256];
		DWORD name_type;
		const char name_string[] = "Name";

		len = sizeof (enum_name);
		status = RegEnumKeyEx(
			network_connections_key,
			i,
			enum_name,
			&len,
			NULL,
			NULL,
			NULL,
			NULL
		);
		if (status == ERROR_NO_MORE_ITEMS)
			break;
		else if (status != ERROR_SUCCESS)
			msg (M_FATAL, "Error enumerating registry subkeys of key: %s",
				NETWORK_CONNECTIONS_KEY);

		openvpn_snprintf (connection_string, sizeof(connection_string),
			"%s\\%s\\Connection",
			NETWORK_CONNECTIONS_KEY, enum_name);

		status = RegOpenKeyEx(
			HKEY_LOCAL_MACHINE,
			connection_string,
			0,
			KEY_READ,
			&connection_key
		);

		if (status != ERROR_SUCCESS)
			dmsg (D_REGISTRY, "Error opening registry key: %s", connection_string);
		else {
			len = sizeof (name_data);
			status = RegQueryValueEx(
				connection_key,
				name_string,
				NULL,
				&name_type,
				name_data,
				&len
			);

			if (status != ERROR_SUCCESS || name_type != REG_SZ)
				dmsg (D_REGISTRY, "Error opening registry key: %s\\%s\\%s",
					NETWORK_CONNECTIONS_KEY, connection_string, name_string);
			else {
				struct panel_reg *reg;

				ALLOC_OBJ_CLEAR_GC (reg, struct panel_reg, gc);
				reg->name = string_alloc (name_data, gc);
				reg->guid = string_alloc (enum_name, gc);

				/* link into return list */
				if (!first)
					first = reg;
				if (last)
					last->next = reg;
				last = reg;
			}
			RegCloseKey (connection_key);
		}
		++i;
	}

	RegCloseKey (network_connections_key);

	return first;
}

/*
 * Check that two addresses are part of the same 255.255.255.252 subnet.
 */
static
void
verify_255_255_255_252 (in_addr_t local, in_addr_t remote)
{
	struct gc_arena gc = gc_new ();
	const unsigned int mask = 3;
	const char *err = NULL;

	if (local == remote) {
		err = "must be different";
		goto error;
	}
	if ((local & (~mask)) != (remote & (~mask))) {
		err = "must exist within the same 255.255.255.252 subnet.  This is a limitation of --dev tun when used with the TAP-WIN32 driver";
		goto error;
	}
	if ((local & mask) == 0
		|| (local & mask) == 3
		|| (remote & mask) == 0
		|| (remote & mask) == 3) {
		err = "cannot use the first or last address within a given 255.255.255.252 subnet.  This is a limitation of --dev tun when used with the TAP-WIN32 driver";
		goto error;
	}

	gc_free (&gc);
	return;

error:
	msg (
		M_FATAL,
		"There is a problem in your selection of --ifconfig endpoints [local=%s, remote=%s].  The local and remote VPN endpoints %s.  Try '" PACKAGE " --show-valid-subnets' option for more info.",
		print_in_addr_t (local, 0, &gc),
		print_in_addr_t (remote, 0, &gc),
		err
	);
	gc_free (&gc);
}

void show_valid_win32_tun_subnets (void)
{
	int i;
	int col = 0;

	puts (
		"On Windows, point-to-point IP support (i.e. --dev tun)\n"
		"is emulated by the TAP-Windows driver.  The major limitation\n"
		"imposed by this approach is that the --ifconfig local and\n"
		"remote endpoints must be part of the same 255.255.255.252\n"
		"subnet.  The following list shows examples of endpoint\n"
		"pairs which satisfy this requirement.  Only the final\n"
		"component of the IP address pairs is at issue.\n\n"
		"As an example, the following option would be correct:\n"
		"    --ifconfig 10.7.0.5 10.7.0.6 (on host A)\n"
		"    --ifconfig 10.7.0.6 10.7.0.5 (on host B)\n"
		"because [5,6] is part of the below list.\n\n"
	);

	for (i = 0; i < 256; i += 4) {
		printf("[%3d,%3d] ", i+1, i+2);
		if (++col > 4) {
			col = 0;
			printf ("\n");
		}
	}
	if (col)
		printf ("\n");
}

void
show_tap_win_adapters (int msglev, int warnlev)
{
	struct gc_arena gc = gc_new ();

	bool warn_panel_null = false;
	bool warn_panel_dup = false;
	bool warn_tap_dup = false;

	int links;

	const struct tap_reg *tr;
	const struct tap_reg *tr1;
	const struct panel_reg *pr;

	const struct tap_reg *tap_reg = get_tap_reg (&gc);
	const struct panel_reg *panel_reg = get_panel_reg (&gc);

	msg (msglev, "Available TAP-WIN32 adapters [name, GUID]:");

	/* loop through each TAP-Windows adapter registry entry */
	for (tr = tap_reg; tr != NULL; tr = tr->next) {
		links = 0;

		/* loop through each network connections entry in the control panel */
		for (pr = panel_reg; pr != NULL; pr = pr->next) {
			if (!strcmp (tr->guid, pr->guid)) {
				msg (msglev, "'%s' %s", pr->name, tr->guid);
				++links;
			}
		}

		if (links > 1) {
			warn_panel_dup = true;
		}
		else if (links == 0) {
			/* a TAP adapter exists without a link from the network
			connections control panel */
			warn_panel_null = true;
			msg (msglev, "[NULL] %s", tr->guid);
		}
	}

	/* check for TAP-Windows adapter duplicated GUIDs */
	for (tr = tap_reg; tr != NULL; tr = tr->next) {
		for (tr1 = tap_reg; tr1 != NULL; tr1 = tr1->next) {
			if (tr != tr1 && !strcmp (tr->guid, tr1->guid))
				warn_tap_dup = true;
		}
	}

	/* warn on registry inconsistencies */
	if (warn_tap_dup)
		msg (warnlev, "WARNING: Some TAP-Windows adapters have duplicate GUIDs");

	if (warn_panel_dup)
		msg (warnlev, "WARNING: Some TAP-Windows adapters have duplicate links from the Network Connections control panel");

	if (warn_panel_null)
		msg (warnlev, "WARNING: Some TAP-Windows adapters have no link from the Network Connections control panel");

	gc_free (&gc);
}

/*
 * Confirm that GUID is a TAP-Windows adapter.
 */
static bool
is_tap_win (const char *guid, const struct tap_reg *tap_reg)
{
	const struct tap_reg *tr;

	for (tr = tap_reg; tr != NULL; tr = tr->next) {
		if (guid && !strcmp (tr->guid, guid))
			return true;
	}

	return false;
}

static const char *
guid_to_name (const char *guid, const struct panel_reg *panel_reg)
{
	const struct panel_reg *pr;

	for (pr = panel_reg; pr != NULL; pr = pr->next) {
		if (guid && !strcmp (pr->guid, guid))
			return pr->name;
	}

	return NULL;
}

static const char *
name_to_guid (const char *name, const struct tap_reg *tap_reg, const struct panel_reg *panel_reg)
{
	const struct panel_reg *pr;

	for (pr = panel_reg; pr != NULL; pr = pr->next) {
		if (name && !strcmp (pr->name, name) && is_tap_win (pr->guid, tap_reg))
			return pr->guid;
	}

	return NULL;
}

static void
at_least_one_tap_win (const struct tap_reg *tap_reg)
{
	if (!tap_reg)
		msg (M_FATAL, "There are no TAP-Windows adapters on this system.  You should be able to create a TAP-Windows adapter by going to Start -> All Programs -> " PACKAGE_NAME " -> Add a new TAP-Windows virtual ethernet adapter.");
}

/*
 * Get an adapter GUID and optional actual_name from the 
 * registry for the TAP device # = device_number.
 */
static const char *
get_unspecified_device_guid (
	const int device_number,
	char *actual_name,
	int actual_name_size,
	const struct tap_reg *tap_reg_src,
	const struct panel_reg *panel_reg_src,
	struct gc_arena *gc
)
{
	const struct tap_reg *tap_reg = tap_reg_src;
	struct buffer ret = clear_buf ();
	struct buffer actual = clear_buf ();
	int i;

	ASSERT (device_number >= 0);

	/* Make sure we have at least one TAP adapter */
	if (!tap_reg)
		return NULL;

	/* The actual_name output buffer may be NULL */
	if (actual_name) {
		ASSERT (actual_name_size > 0);
		buf_set_write (&actual, actual_name, actual_name_size);
	}

	/* Move on to specified device number */
	for (i = 0; i < device_number; i++) {
		tap_reg = tap_reg->next;
		if (!tap_reg)
			return NULL;
	}

	/* Save Network Panel name (if exists) in actual_name */
	if (actual_name) {
		const char *act = guid_to_name (tap_reg->guid, panel_reg_src);
		if (act)
			buf_printf (&actual, "%s", act);
		else
			buf_printf (&actual, "%s", tap_reg->guid);
	}

	/* Save GUID for return value */
	ret = alloc_buf_gc (256, gc);
	buf_printf (&ret, "%s", tap_reg->guid);
	return BSTR (&ret);
}

/*
 * Lookup a --dev-node adapter name in the registry
 * returning the GUID and optional actual_name.
 */
static const char *
get_device_guid (
	const char *name,
	char *actual_name,
	int actual_name_size,
	const struct tap_reg *tap_reg,
	const struct panel_reg *panel_reg,
	struct gc_arena *gc
)
{
	struct buffer ret = alloc_buf_gc (256, gc);
	struct buffer actual = clear_buf ();

	/* Make sure we have at least one TAP adapter */
	if (!tap_reg)
		return NULL;

	/* The actual_name output buffer may be NULL */
	if (actual_name) {
		ASSERT (actual_name_size > 0);
		buf_set_write (&actual, actual_name, actual_name_size);
	}

	/* Check if GUID was explicitly specified as --dev-node parameter */
	if (is_tap_win (name, tap_reg)) {
		const char *act = guid_to_name (name, panel_reg);
		buf_printf (&ret, "%s", name);
		if (act)
			buf_printf (&actual, "%s", act);
		else
			buf_printf (&actual, "%s", name);
		return BSTR (&ret);
	}

	/* Lookup TAP adapter in network connections list */
	{
		const char *guid = name_to_guid (name, tap_reg, panel_reg);
		if (guid) {
			buf_printf (&actual, "%s", name);
			buf_printf (&ret, "%s", guid);
			return BSTR (&ret);
		}
	}

	return NULL;
}

/*
 * Get adapter info list
 */
const IP_ADAPTER_INFO *
get_adapter_info_list (struct gc_arena *gc)
{
	ULONG size = 0;
	IP_ADAPTER_INFO *pi = NULL;
	DWORD status;

	if ((status = GetAdaptersInfo (NULL, &size)) != ERROR_BUFFER_OVERFLOW) {
		msg (M_INFO, "GetAdaptersInfo #1 failed (status=%u) : %s",
			(unsigned int)status,
			strerror_win32 (status, gc));
	}
	else {
		pi = (PIP_ADAPTER_INFO) gc_malloc (size, false, gc);
		if ((status = GetAdaptersInfo (pi, &size)) == NO_ERROR)
			return pi;
		else {
			msg (M_INFO, "GetAdaptersInfo #2 failed (status=%u) : %s",
				(unsigned int)status,
				strerror_win32 (status, gc));
		}
	}
	return pi;
}

const IP_PER_ADAPTER_INFO *
get_per_adapter_info (const DWORD index, struct gc_arena *gc)
{
	ULONG size = 0;
	IP_PER_ADAPTER_INFO *pi = NULL;
	DWORD status;

	if (index != TUN_ADAPTER_INDEX_INVALID) {
		if ((status = GetPerAdapterInfo (index, NULL, &size)) != ERROR_BUFFER_OVERFLOW) {
			msg (M_INFO, "GetPerAdapterInfo #1 failed (status=%u) : %s",
				(unsigned int)status,
				strerror_win32 (status, gc));
		}
		else {
			pi = (PIP_PER_ADAPTER_INFO) gc_malloc (size, false, gc);
			if ((status = GetPerAdapterInfo ((ULONG)index, pi, &size)) == ERROR_SUCCESS)
				return pi;
			else {
				msg (M_INFO, "GetPerAdapterInfo #2 failed (status=%u) : %s",
					(unsigned int)status,
					strerror_win32 (status, gc));
			}
		}
	}
	return pi;
}

static const IP_INTERFACE_INFO *
get_interface_info_list (struct gc_arena *gc)
{
	ULONG size = 0;
	IP_INTERFACE_INFO *ii = NULL;
	DWORD status;

	if ((status = GetInterfaceInfo (NULL, &size)) != ERROR_INSUFFICIENT_BUFFER) {
		msg (M_INFO, "GetInterfaceInfo #1 failed (status=%u) : %s",
			(unsigned int)status,
			strerror_win32 (status, gc));
	}
	else {
		ii = (PIP_INTERFACE_INFO) gc_malloc (size, false, gc);
		if ((status = GetInterfaceInfo (ii, &size)) == NO_ERROR)
			return ii;
		else {
			msg (M_INFO, "GetInterfaceInfo #2 failed (status=%u) : %s",
				(unsigned int)status,
				strerror_win32 (status, gc));
		}
	}
	return ii;
}

static const IP_ADAPTER_INDEX_MAP *
get_interface_info (DWORD index, struct gc_arena *gc)
{
	const IP_INTERFACE_INFO *list = get_interface_info_list (gc);
	if (list) {
		int i;
		for (i = 0; i < list->NumAdapters; ++i) {
			const IP_ADAPTER_INDEX_MAP *inter = &list->Adapter[i];
			if (index == inter->Index)
				return inter;
		}
	}
	return NULL;
}

/*
 * Given an adapter index, return a pointer to the
 * IP_ADAPTER_INFO structure for that adapter.
 */

const IP_ADAPTER_INFO *
get_adapter (const IP_ADAPTER_INFO *ai, DWORD index)
{
	if (ai && index != TUN_ADAPTER_INDEX_INVALID) {
		const IP_ADAPTER_INFO *a;

		/* find index in the linked list */
		for (a = ai; a != NULL; a = a->Next) {
			if (a->Index == index)
				return a;
		}
	}
	return NULL;
}

const IP_ADAPTER_INFO *
get_adapter_info (DWORD index, struct gc_arena *gc)
{
	return get_adapter (get_adapter_info_list (gc), index);
}

static int
get_adapter_n_ip_netmask (const IP_ADAPTER_INFO *ai)
{
	if (ai) {
		int n = 0;
		const IP_ADDR_STRING *ip = &ai->IpAddressList;

		while (ip) {
			++n;
			ip = ip->Next;
		}
		return n;
	}
	else
		return 0;
}

static bool
get_adapter_ip_netmask (const IP_ADAPTER_INFO *ai, const int n, in_addr_t *ip, in_addr_t *netmask)
{
	bool ret = false;
	*ip = 0;
	*netmask = 0;

	if (ai) {
		const IP_ADDR_STRING *iplist = &ai->IpAddressList;
		int i = 0;

		while (iplist) {
			if (i == n)
				break;
			++i;
			iplist = iplist->Next;
		}

		if (iplist) {
			const unsigned int getaddr_flags = GETADDR_HOST_ORDER;
			const char *ip_str = iplist->IpAddress.String;
			const char *netmask_str = iplist->IpMask.String;
			bool succeed1 = false;
			bool succeed2 = false;

			if (ip_str && netmask_str && strlen (ip_str) && strlen (netmask_str)) {
				*ip = getaddr (getaddr_flags, ip_str, 0, &succeed1, NULL);
				*netmask = getaddr (getaddr_flags, netmask_str, 0, &succeed2, NULL);
				ret = (succeed1 == true && succeed2 == true);
			}
		}
	}

	return ret;
}

static bool
test_adapter_ip_netmask (const IP_ADAPTER_INFO *ai, const in_addr_t ip, const in_addr_t netmask)
{
	if (ai) {
		in_addr_t ip_adapter = 0;
		in_addr_t netmask_adapter = 0;
		const bool status = get_adapter_ip_netmask (ai, 0, &ip_adapter, &netmask_adapter);
		return (status && ip_adapter == ip && netmask_adapter == netmask);
	}
	else
		return false;
}

const IP_ADAPTER_INFO *
get_tun_adapter (const struct tuntap *tt, const IP_ADAPTER_INFO *list)
{
	if (list && tt)
		return get_adapter (list, tt->engine_data->adapter_index);
	else
		return NULL;
}

bool
is_adapter_up (const struct tuntap *tt, const IP_ADAPTER_INFO *list)
{
	int i;
	bool ret = false;

	const IP_ADAPTER_INFO *ai = get_tun_adapter (tt, list);

	if (ai) {
		const int n = get_adapter_n_ip_netmask (ai);

		/* loop once for every IP/netmask assigned to adapter */
		for (i = 0; i < n; ++i) {
			in_addr_t ip, netmask;
			if (get_adapter_ip_netmask (ai, i, &ip, &netmask)) {
				if (tt->local && tt->engine_data->adapter_netmask) {
					/* wait for our --ifconfig parms to match the actual adapter parms */
					if (tt->local == ip && tt->engine_data->adapter_netmask == netmask)
						ret = true;
				}
				else {
					/* --ifconfig was not defined, maybe using a real DHCP server */
					if (ip && netmask)
					ret = true;
				}
			}
		}
	}
	else
		ret = true; /* this can occur when TAP adapter is bridged */

	return ret;
}

bool
is_ip_in_adapter_subnet (const IP_ADAPTER_INFO *ai, const in_addr_t ip, in_addr_t *highest_netmask)
{
	int i;
	bool ret = false;

	if (highest_netmask)
		*highest_netmask = 0;

	if (ai) {
		const int n = get_adapter_n_ip_netmask (ai);
		for (i = 0; i < n; ++i) {
			in_addr_t adapter_ip, adapter_netmask;
			if (get_adapter_ip_netmask (ai, i, &adapter_ip, &adapter_netmask)) {
				if (adapter_ip && adapter_netmask && (ip & adapter_netmask) == (adapter_ip & adapter_netmask)) {
					if (highest_netmask && adapter_netmask > *highest_netmask)
						*highest_netmask = adapter_netmask;
					ret = true;
				}
			}
		}
	}
	return ret;
}

DWORD
adapter_index_of_ip (
	const IP_ADAPTER_INFO *list,
	const in_addr_t ip,
	int *count,
	in_addr_t *netmask
)
{
	struct gc_arena gc = gc_new ();
	DWORD ret = TUN_ADAPTER_INDEX_INVALID;
	in_addr_t highest_netmask = 0;
	bool first = true;

	if (count)
		*count = 0;

	while (list) {
		in_addr_t hn;

		if (is_ip_in_adapter_subnet (list, ip, &hn)) {
			if (first || hn > highest_netmask) {
				highest_netmask = hn;
				if (count)
					*count = 1;
				ret = list->Index;
				first = false;
			}
			else if (hn == highest_netmask) {
				if (count)
					++*count;
			}
		}
		list = list->Next;
	}

	dmsg (D_ROUTE_DEBUG, "DEBUG: IP Locate: ip=%s nm=%s index=%d count=%d",
		print_in_addr_t (ip, 0, &gc),
		print_in_addr_t (highest_netmask, 0, &gc),
		(int)ret,
		count ? *count : -1);

	if (ret == TUN_ADAPTER_INDEX_INVALID && count)
		*count = 0;

	if (netmask)
		*netmask = highest_netmask;

	gc_free (&gc);
	return ret;
}

/*
 * Given an adapter index, return true if the adapter
 * is DHCP disabled.
 */

#define DHCP_STATUS_UNDEF     0
#define DHCP_STATUS_ENABLED   1
#define DHCP_STATUS_DISABLED  2

static int
dhcp_status (DWORD index)
{
	struct gc_arena gc = gc_new ();
	int ret = DHCP_STATUS_UNDEF;
	if (index != TUN_ADAPTER_INDEX_INVALID) {
		const IP_ADAPTER_INFO *ai = get_adapter_info (index, &gc);

		if (ai) {
			if (ai->DhcpEnabled)
				ret = DHCP_STATUS_ENABLED;
			else
				ret = DHCP_STATUS_DISABLED;
		}
	}
	gc_free (&gc);
	return ret;
}

/*
 * Delete all temporary address/netmask pairs which were added
 * to adapter (given by index) by previous calls to AddIPAddress.
 */
static void
delete_temp_addresses (DWORD index)
{
	struct gc_arena gc = gc_new ();
	const IP_ADAPTER_INFO *a = get_adapter_info (index, &gc);

	if (a) {
		const IP_ADDR_STRING *ip = &a->IpAddressList;
		while (ip) {
			DWORD status;
			const DWORD context = ip->Context;

			if ((status = DeleteIPAddress ((ULONG) context)) == NO_ERROR) {
				msg (M_INFO, "Successfully deleted previously set dynamic IP/netmask: %s/%s",
				ip->IpAddress.String,
				ip->IpMask.String);
			}
			else {
				const char *empty = "0.0.0.0";
				if (strcmp (ip->IpAddress.String, empty)
					|| strcmp (ip->IpMask.String, empty)) {

					msg (M_INFO, "NOTE: could not delete previously set dynamic IP/netmask: %s/%s (status=%u)",
						ip->IpAddress.String,
						ip->IpMask.String,
						(unsigned int)status);
				}
			}
			ip = ip->Next;
		}
	}
	gc_free (&gc);
}

/*
 * Get interface index for use with IP Helper API functions.
 */
static DWORD
get_adapter_index_method_1 (const char *guid)
{
	DWORD index;
	ULONG aindex;
	wchar_t wbuf[256];
	_snwprintf (wbuf, SIZE (wbuf), L"\\DEVICE\\TCPIP_%S", guid);
	wbuf [SIZE(wbuf) - 1] = 0;
	if (GetAdapterIndex (wbuf, &aindex) != NO_ERROR)
		index = TUN_ADAPTER_INDEX_INVALID;
	else
		index = (DWORD)aindex;
	return index;
}

static DWORD
get_adapter_index_method_2 (const char *guid)
{
	struct gc_arena gc = gc_new ();
	DWORD index = TUN_ADAPTER_INDEX_INVALID;

	const IP_ADAPTER_INFO *list = get_adapter_info_list (&gc);

	while (list) {
		if (!strcmp (guid, list->AdapterName)) {
			index = list->Index;
			break;
		}
		list = list->Next;
	}

	gc_free (&gc);
	return index;
}

static DWORD
get_adapter_index (const char *guid)
{
	DWORD index;
	index = get_adapter_index_method_1 (guid);
	if (index == TUN_ADAPTER_INDEX_INVALID)
		index = get_adapter_index_method_2 (guid);
	if (index == TUN_ADAPTER_INDEX_INVALID)
		msg (M_INFO, "NOTE: could not get adapter index for %s", guid);
	return index;
}

static DWORD
get_adapter_index_flexible (const char *name) /* actual name or GUID */
{
	struct gc_arena gc = gc_new ();
	DWORD index;
	index = get_adapter_index_method_1 (name);
	if (index == TUN_ADAPTER_INDEX_INVALID)
		index = get_adapter_index_method_2 (name);
	if (index == TUN_ADAPTER_INDEX_INVALID) {
		const struct tap_reg *tap_reg = get_tap_reg (&gc);
		const struct panel_reg *panel_reg = get_panel_reg (&gc);
		const char *guid = name_to_guid (name, tap_reg, panel_reg);
		index = get_adapter_index_method_1 (guid);
		if (index == TUN_ADAPTER_INDEX_INVALID)
		index = get_adapter_index_method_2 (guid);
	}
	if (index == TUN_ADAPTER_INDEX_INVALID)
		msg (M_INFO, "NOTE: could not get adapter index for name/GUID '%s'", name);
	gc_free (&gc);
	return index;
}

/*
 * Return a string representing a PIP_ADDR_STRING
 */
static const char *
format_ip_addr_string (const IP_ADDR_STRING *ip, struct gc_arena *gc)
{
	struct buffer out = alloc_buf_gc (256, gc);
	while (ip) {
		buf_printf (&out, "%s", ip->IpAddress.String);
		if (strlen (ip->IpMask.String)) {
			buf_printf (&out, "/");
			buf_printf (&out, "%s", ip->IpMask.String);
		}
		buf_printf (&out, " ");
		ip = ip->Next;
	}
	return BSTR (&out);
}

/*
 * Show info for a single adapter
 */
static void
show_adapter (int msglev, const IP_ADAPTER_INFO *a, struct gc_arena *gc)
{
	msg (msglev, "%s", a->Description);
	msg (msglev, "  Index = %d", (int)a->Index);
	msg (msglev, "  GUID = %s", a->AdapterName);
	msg (msglev, "  IP = %s", format_ip_addr_string (&a->IpAddressList, gc));
	msg (msglev, "  MAC = %s", format_hex_ex (a->Address, a->AddressLength, 0, 1, ":", gc));
	msg (msglev, "  GATEWAY = %s", format_ip_addr_string (&a->GatewayList, gc));
	if (a->DhcpEnabled) {
		msg (msglev, "  DHCP SERV = %s", format_ip_addr_string (&a->DhcpServer, gc));
		msg (msglev, "  DHCP LEASE OBTAINED = %s", time_string (a->LeaseObtained, 0, false, gc));
		msg (msglev, "  DHCP LEASE EXPIRES  = %s", time_string (a->LeaseExpires, 0, false, gc));
	}
	if (a->HaveWins) {
		msg (msglev, "  PRI WINS = %s", format_ip_addr_string (&a->PrimaryWinsServer, gc));
		msg (msglev, "  SEC WINS = %s", format_ip_addr_string (&a->SecondaryWinsServer, gc));
	}

	{
		const IP_PER_ADAPTER_INFO *pai = get_per_adapter_info (a->Index, gc);
		if (pai) {
			msg (msglev, "  DNS SERV = %s", format_ip_addr_string (&pai->DnsServerList, gc));
		}
	}
}

/*
 * Show current adapter list
 */
void
show_adapters (int msglev)
{
	struct gc_arena gc = gc_new ();
	const IP_ADAPTER_INFO *ai = get_adapter_info_list (&gc);

	msg (msglev, "SYSTEM ADAPTER LIST");
	if (ai) {
		const IP_ADAPTER_INFO *a;

		/* find index in the linked list */
		for (a = ai; a != NULL; a = a->Next) {
			show_adapter (msglev, a, &gc);
		}
	}
	gc_free (&gc);
}

/*
 * Set a particular TAP-Windows adapter (or all of them if
 * adapter_name == NULL) to allow it to be opened from
 * a non-admin account.  This setting will only persist
 * for the lifetime of the device object.
 */

static void
tap_allow_nonadmin_access_handle (const char *device_path, HANDLE hand)
{
	struct security_attributes sa;
	BOOL status;

	if (!init_security_attributes_allow_all (&sa))
		msg (M_ERR, "Error: init SA failed");

	status = SetKernelObjectSecurity (hand, DACL_SECURITY_INFORMATION, &sa.sd);
	if (!status) {
		msg (M_ERRNO, "Error: SetKernelObjectSecurity failed on %s", device_path);
	}
	else {
		msg (M_INFO|M_NOPREFIX, "TAP-Windows device: %s [Non-admin access allowed]", device_path);
	}
}

void
tap_allow_nonadmin_access (const char *dev_node)
{
	struct gc_arena gc = gc_new ();
	const struct tap_reg *tap_reg = get_tap_reg (&gc);
	const struct panel_reg *panel_reg = get_panel_reg (&gc);
	const char *device_guid = NULL;
	HANDLE hand;
	char actual_buffer[256];
	char device_path[256];

	at_least_one_tap_win (tap_reg);

	if (dev_node) {
		/* Get the device GUID for the device specified with --dev-node. */
		device_guid = get_device_guid (dev_node, actual_buffer, sizeof (actual_buffer), tap_reg, panel_reg, &gc);

		if (!device_guid)
			msg (M_FATAL, "TAP-Windows adapter '%s' not found", dev_node);

		/* Open Windows TAP-Windows adapter */
		openvpn_snprintf (device_path, sizeof(device_path), "%s%s%s",
			USERMODEDEVICEDIR,
			device_guid,
			TAP_WIN_SUFFIX);

		hand = CreateFile (
			device_path,
			MAXIMUM_ALLOWED,
			0, /* was: FILE_SHARE_READ */
			0,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
			0
		);

		if (hand == INVALID_HANDLE_VALUE)
			msg (M_ERR, "CreateFile failed on TAP device: %s", device_path);

		tap_allow_nonadmin_access_handle (device_path, hand);
		CloseHandle (hand);
	}
	else {
		int device_number = 0;

		/* Try opening all TAP devices */
		while (true) {
			device_guid = get_unspecified_device_guid (
				device_number, 
				actual_buffer, 
				sizeof (actual_buffer),
				tap_reg,
				panel_reg,
				&gc
			);

			if (!device_guid)
				break;

			/* Open Windows TAP-Windows adapter */
			openvpn_snprintf (
				device_path, sizeof(device_path), "%s%s%s",
				USERMODEDEVICEDIR,
				device_guid,
				TAP_WIN_SUFFIX);

			hand = CreateFile (
				device_path,
				MAXIMUM_ALLOWED,
				0, /* was: FILE_SHARE_READ */
				0,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
				0
			);

			if (hand == INVALID_HANDLE_VALUE)
				msg (M_WARN, "CreateFile failed on TAP device: %s", device_path);
			else {
				tap_allow_nonadmin_access_handle (device_path, hand);
				CloseHandle (hand);
			}

			device_number++;
		}
	}
	gc_free (&gc);
}

/*
 * DHCP release/renewal
 */
bool
dhcp_release_by_adapter_index(const DWORD adapter_index)
{
	struct gc_arena gc = gc_new ();
	bool ret = false;
	const IP_ADAPTER_INDEX_MAP *inter = get_interface_info (adapter_index, &gc);

	if (inter) {
		DWORD status = IpReleaseAddress ((IP_ADAPTER_INDEX_MAP *)inter);
		if (status == NO_ERROR) {
			msg (D_TUNTAP_INFO, "TAP: DHCP address released");
			ret = true;
		}
		else
			msg (M_WARN, "NOTE: Release of DHCP-assigned IP address lease on TAP-Windows adapter failed: %s (code=%u)",
				strerror_win32 (status, &gc),
				(unsigned int)status);
	}

	gc_free (&gc);
	return ret;
}

static bool
dhcp_release (const struct tuntap *tt)
{
	if (tt && tt->engine_data->options.ip_win32_type == IPW32_SET_DHCP_MASQ && tt->engine_data->adapter_index != TUN_ADAPTER_INDEX_INVALID)
		return dhcp_release_by_adapter_index (tt->engine_data->adapter_index);
	else
		return false;
}

bool
dhcp_renew_by_adapter_index (const DWORD adapter_index)
{
	struct gc_arena gc = gc_new ();
	bool ret = false;
	const IP_ADAPTER_INDEX_MAP *inter = get_interface_info (adapter_index, &gc);

	if (inter) {
		DWORD status = IpRenewAddress ((IP_ADAPTER_INDEX_MAP *)inter);
		if (status == NO_ERROR) {
			msg (D_TUNTAP_INFO, "TAP: DHCP address renewal succeeded");
			ret = true;
		}
		else
			msg (M_WARN, "WARNING: Failed to renew DHCP IP address lease on TAP-Windows adapter: %s (code=%u)",
				strerror_win32 (status, &gc),
				(unsigned int)status);
	}
	gc_free (&gc);
	return ret;
}

static bool
dhcp_renew (const struct tuntap *tt)
{
	if (tt && tt->engine_data->options.ip_win32_type == IPW32_SET_DHCP_MASQ && tt->engine_data->adapter_index != TUN_ADAPTER_INDEX_INVALID)
		return dhcp_renew_by_adapter_index (tt->engine_data->adapter_index);
	else
		return false;
}

/*
 * netsh functions
 */

void /* @ALON: static! */
netsh_command (const struct argv *a, int n)
{
	int i;
	for (i = 0; i < n; ++i) {
		bool status;
		openvpn_sleep (1);
		netcmd_semaphore_lock ();
		argv_msg_prefix (M_INFO, a, "NETSH");
		status = openvpn_execve_check (a, NULL, 0, "ERROR: netsh command failed");
		netcmd_semaphore_release ();
		if (status)
			return;
		openvpn_sleep (4);
	}
	msg (M_FATAL, "NETSH: command failed");
}

void
ipconfig_register_dns (const struct env_set *es)
{
	struct argv argv;
	bool status;
	const char err[] = "ERROR: Windows ipconfig command failed";

	msg (D_TUNTAP_INFO, "Start net commands...");
	netcmd_semaphore_lock ();

	argv_init (&argv);

	argv_printf (&argv, "%s%sc stop dnscache",
		get_win_sys_path(),
		WIN_NET_PATH_SUFFIX);
		argv_msg (D_TUNTAP_INFO, &argv);
	status = openvpn_execve_check (&argv, es, 0, err);
	argv_reset(&argv);

	argv_printf (&argv, "%s%sc start dnscache",
		get_win_sys_path(),
		WIN_NET_PATH_SUFFIX);
		argv_msg (D_TUNTAP_INFO, &argv);
	status = openvpn_execve_check (&argv, es, 0, err);
	argv_reset(&argv);

	argv_printf (&argv, "%s%sc /flushdns",
		get_win_sys_path(),
		WIN_IPCONFIG_PATH_SUFFIX);
		argv_msg (D_TUNTAP_INFO, &argv);
	status = openvpn_execve_check (&argv, es, 0, err);
	argv_reset(&argv);

	argv_printf (&argv, "%s%sc /registerdns",
		get_win_sys_path(),
		WIN_IPCONFIG_PATH_SUFFIX);
	argv_msg (D_TUNTAP_INFO, &argv);
	status = openvpn_execve_check (&argv, es, 0, err);
	argv_reset(&argv);

	netcmd_semaphore_release ();
	msg (D_TUNTAP_INFO, "End net commands...");
}

void
ip_addr_string_to_array (in_addr_t *dest, int *dest_len, const IP_ADDR_STRING *src)
{
	int i = 0;
	while (src) {
		const unsigned int getaddr_flags = GETADDR_HOST_ORDER;
		const char *ip_str = src->IpAddress.String;
		in_addr_t ip = 0;
		bool succeed = false;

		if (i >= *dest_len)
			break;
		if (!ip_str || !strlen (ip_str))
			break;

		ip = getaddr (getaddr_flags, ip_str, 0, &succeed, NULL);
		if (!succeed)
			break;
		dest[i++] = ip;

		src = src->Next;
	}
	*dest_len = i;

	#if 0
	{
		struct gc_arena gc = gc_new ();
		msg (M_INFO, "ip_addr_string_to_array [%d]", *dest_len);
		for (i = 0; i < *dest_len; ++i) {
			msg (M_INFO, "%s", print_in_addr_t (dest[i], 0, &gc));
		}
		gc_free (&gc);
	}
	#endif
}

static bool
ip_addr_one_to_one (const in_addr_t *a1, const int a1len, const IP_ADDR_STRING *ias)
{
	in_addr_t a2[8];
	int a2len = SIZE(a2);
	int i;

	ip_addr_string_to_array (a2, &a2len, ias);
	/*msg (M_INFO, "a1len=%d a2len=%d", a1len, a2len);*/
	if (a1len != a2len)
		return false;

	for (i = 0; i < a1len; ++i) {
		if (a1[i] != a2[i])
			return false;
	}
	return true;
}

static bool
ip_addr_member_of (const in_addr_t addr, const IP_ADDR_STRING *ias)
{
	in_addr_t aa[8];
	int len = SIZE(aa);
	int i;

	ip_addr_string_to_array (aa, &len, ias);
	for (i = 0; i < len; ++i) {
		if (addr == aa[i])
			return true;
	}
	return false;
}

static void
netsh_ifconfig_options (
	const char *type,
	const in_addr_t *addr_list,
	const int addr_len,
	const IP_ADDR_STRING *current,
	const char *flex_name,
	const bool test_first
)
{
	struct gc_arena gc = gc_new ();
	struct argv argv = argv_new ();
	bool delete_first = false;

	/* first check if we should delete existing DNS/WINS settings from TAP interface */
	if (test_first) {
		if (!ip_addr_one_to_one (addr_list, addr_len, current))
			delete_first = true;
	}
	else
		delete_first = true;

	/* delete existing DNS/WINS settings from TAP interface */
	if (delete_first) {
		argv_printf (&argv, "%s%sc interface ip delete %s %s all",
			get_win_sys_path(),
			NETSH_PATH_SUFFIX,
			type,
			flex_name);
		netsh_command (&argv, 2);
	}

	/* add new DNS/WINS settings to TAP interface */
	{
		int count = 0;
		int i;
		for (i = 0; i < addr_len; ++i) {
			if (delete_first || !test_first || !ip_addr_member_of (addr_list[i], current)) {
				const char *fmt = count ?
					"%s%sc interface ip add %s %s %s"
					: "%s%sc interface ip set %s %s static %s";

				argv_printf (&argv, fmt,
					get_win_sys_path(),
					NETSH_PATH_SUFFIX,
					type,
					flex_name,
					print_in_addr_t (addr_list[i], 0, &gc));
				netsh_command (&argv, 2);

				++count;
			}
			else {
				msg (M_INFO, "NETSH: \"%s\" %s %s [already set]",
				flex_name,
				type,
				print_in_addr_t (addr_list[i], 0, &gc));
			}
		}
	}

	argv_reset (&argv);
	gc_free (&gc);
}

static void
init_ip_addr_string2 (IP_ADDR_STRING *dest, const IP_ADDR_STRING *src1, const IP_ADDR_STRING *src2)
{
	CLEAR (dest[0]);
	CLEAR (dest[1]);
	if (src1) {
		dest[0] = *src1;
		dest[0].Next = NULL;
	}
	if (src2) {
		dest[1] = *src2;
		dest[0].Next = &dest[1];
		dest[1].Next = NULL;
	}
}

void /* @ALON: static! */
netsh_ifconfig (
	const tun_engine_options_t to,
	const char *flex_name,
	const in_addr_t ip,
	const in_addr_t netmask,
	const unsigned int flags
)
{
	struct gc_arena gc = gc_new ();
	struct argv argv = argv_new ();
	const IP_ADAPTER_INFO *ai = NULL;
	const IP_PER_ADAPTER_INFO *pai = NULL;

	if (flags & NI_TEST_FIRST) {
		const IP_ADAPTER_INFO *list = get_adapter_info_list (&gc);
		const int index = get_adapter_index_flexible (flex_name);
		ai = get_adapter (list, index);
		pai = get_per_adapter_info (index, &gc);
	}

	if (flags & NI_IP_NETMASK) {
		if (test_adapter_ip_netmask (ai, ip, netmask)) {
			msg (M_INFO, "NETSH: \"%s\" %s/%s [already set]",
				flex_name,
				print_in_addr_t (ip, 0, &gc),
				print_in_addr_t (netmask, 0, &gc));
		}
		else {
			/* example: netsh interface ip set address my-tap static 10.3.0.1 255.255.255.0 */
			argv_printf (&argv, "%s%sc interface ip set address %s static %s %s",
				get_win_sys_path(),
				NETSH_PATH_SUFFIX,
				flex_name,
				print_in_addr_t (ip, 0, &gc),
				print_in_addr_t (netmask, 0, &gc));

			netsh_command (&argv, 4);
		}
	}

	/* set WINS/DNS options */
	if (flags & NI_OPTIONS) {
		IP_ADDR_STRING wins[2];
		CLEAR (wins[0]);
		CLEAR (wins[1]);

		netsh_ifconfig_options ("dns",
			to->dns,
			to->dns_len,
			pai ? &pai->DnsServerList : NULL,
			flex_name,
			BOOL_CAST (flags & NI_TEST_FIRST));
		if (ai && ai->HaveWins)
			init_ip_addr_string2 (wins, &ai->PrimaryWinsServer, &ai->SecondaryWinsServer);

		netsh_ifconfig_options ("wins",
			to->wins,
			to->wins_len,
			ai ? wins : NULL,
			flex_name,
			BOOL_CAST (flags & NI_TEST_FIRST));
	}

	argv_reset (&argv);
	gc_free (&gc);
}

static void
netsh_enable_dhcp (const tun_engine_options_t to,
		   const char *actual_name)
{
	struct argv argv;
	argv_init (&argv);

	/* example: netsh interface ip set address my-tap dhcp */
	argv_printf (&argv,
		"%s%sc interface ip set address %s dhcp",
		get_win_sys_path(),
		NETSH_PATH_SUFFIX,
		actual_name);

	netsh_command (&argv, 4);

	argv_reset (&argv);
}

/*
 * Return a TAP name for netsh commands.
 */
const char * /* @ALON: static! */
netsh_get_id (const char *dev_node, struct gc_arena *gc)
{
	const struct tap_reg *tap_reg = get_tap_reg (gc);
	const struct panel_reg *panel_reg = get_panel_reg (gc);
	struct buffer actual = alloc_buf_gc (256, gc);
	const char *guid;

	at_least_one_tap_win (tap_reg);

	if (dev_node) {
		guid = get_device_guid (dev_node, BPTR (&actual), BCAP (&actual), tap_reg, panel_reg, gc);
	}
	else {
		guid = get_unspecified_device_guid (0, BPTR (&actual), BCAP (&actual), tap_reg, panel_reg, gc);

		if (get_unspecified_device_guid (1, NULL, 0, tap_reg, panel_reg, gc)) /* ambiguous if more than one TAP-Windows adapter */
			guid = NULL;
	}

	if (!guid)
		return "NULL";         /* not found */
	else if (strcmp (BPTR (&actual), "NULL"))
		return BPTR (&actual); /* control panel name */
	else
		return guid;           /* no control panel name, return GUID instead */
}

/*
 * Called iteratively on TAP-Windows wait-for-initialization polling loop
 */
static
void
tun_engine_windows_tun_standby_init (struct tuntap *tt)
{
	tt->engine_data->standby_iter = 0;
}

static
bool
tun_engine_windows_tun_standby (struct tuntap *tt)
{
	bool ret = true;
	++tt->engine_data->standby_iter;
	if (tt->engine_data->options.ip_win32_type == IPW32_SET_ADAPTIVE) {
		if (tt->engine_data->standby_iter == IPW32_SET_ADAPTIVE_TRY_NETSH) {
			msg (M_INFO, "NOTE: now trying netsh (this may take some time)");
				netsh_ifconfig (&tt->engine_data->options,
				tt->actual_name,
				tt->local,
				tt->engine_data->adapter_netmask,
				NI_TEST_FIRST|NI_IP_NETMASK|NI_OPTIONS);
		}
		else if (tt->engine_data->standby_iter >= IPW32_SET_ADAPTIVE_TRY_NETSH*2) {
			ret = false;
		}
	}
	return ret;
}

/*
 * Convert DHCP options from the command line / config file
 * into a raw DHCP-format options string.
 */

static void
write_dhcp_u8 (struct buffer *buf, const int type, const int data, bool *error)
{
	if (!buf_safe (buf, 3)) {
		*error = true;
		msg (M_WARN, "write_dhcp_u8: buffer overflow building DHCP options");
		return;
	}
	buf_write_u8 (buf, type);
	buf_write_u8 (buf, 1);
	buf_write_u8 (buf, data);
}

static void
write_dhcp_u32_array (struct buffer *buf, const int type, const uint32_t *data, const unsigned int len, bool *error)
{
	if (len > 0) {
		int i;
		const int size = len * sizeof (uint32_t);

		if (!buf_safe (buf, 2 + size)) {
			*error = true;
			msg (M_WARN, "write_dhcp_u32_array: buffer overflow building DHCP options");
			return;
		}
		if (size < 1 || size > 255) {
			*error = true;
			msg (M_WARN, "write_dhcp_u32_array: size (%d) must be > 0 and <= 255", size);
			return;
		}
		buf_write_u8 (buf, type);
		buf_write_u8 (buf, size);
		for (i = 0; i < len; ++i)
			buf_write_u32 (buf, data[i]);
	}
}

static void
write_dhcp_str (struct buffer *buf, const int type, const char *str, bool *error)
{
	const int len = strlen (str);
	if (!buf_safe (buf, 2 + len)) {
		*error = true;
		msg (M_WARN, "write_dhcp_str: buffer overflow building DHCP options");
		return;
	}
	if (len < 1 || len > 255) {
		*error = true;
		msg (M_WARN, "write_dhcp_str: string '%s' must be > 0 bytes and <= 255 bytes", str);
		return;
	}
	buf_write_u8 (buf, type);
	buf_write_u8 (buf, len);
	buf_write (buf, str, len);
}

static bool
build_dhcp_options_string (struct buffer *buf, tun_engine_options_t o)
{
	bool error = false;
	if (o->domain)
		write_dhcp_str (buf, 15, o->domain, &error);

	if (o->netbios_scope)
		write_dhcp_str (buf, 47, o->netbios_scope, &error);

	if (o->netbios_node_type)
		write_dhcp_u8 (buf, 46, o->netbios_node_type, &error);

	write_dhcp_u32_array (buf, 6, (uint32_t*)o->dns, o->dns_len, &error);
	write_dhcp_u32_array (buf, 44, (uint32_t*)o->wins, o->wins_len, &error);
	write_dhcp_u32_array (buf, 42, (uint32_t*)o->ntp, o->ntp_len, &error);
	write_dhcp_u32_array (buf, 45, (uint32_t*)o->nbdd, o->nbdd_len, &error);

	/* the MS DHCP server option 'Disable Netbios-over-TCP/IP
	is implemented as vendor option 001, value 002.
	A value of 001 means 'leave NBT alone' which is the default */
	if (o->disable_nbt) {
		if (!buf_safe (buf, 8)) {
			msg (M_WARN, "build_dhcp_options_string: buffer overflow building DHCP options");
			return false;
		}
		buf_write_u8 (buf,  43);
		buf_write_u8 (buf,  6);  /* total length field */
		buf_write_u8 (buf,  0x001);
		buf_write_u8 (buf,  4);  /* length of the vendor specified field */
		buf_write_u32 (buf, 0x002);
	}
	return !error;
}

static void
fork_dhcp_action (struct tuntap *tt)
{
	if (tt->engine_data->options.dhcp_pre_release || tt->engine_data->options.dhcp_renew) {
		struct gc_arena gc = gc_new ();
		struct buffer cmd = alloc_buf_gc (256, &gc);
		const int verb = 3;
		const int pre_sleep = 1;

		buf_printf (&cmd, "openvpn --verb %d --tap-sleep %d", verb, pre_sleep);
		if (tt->engine_data->options.dhcp_pre_release)
			buf_printf (&cmd, " --dhcp-pre-release");
		if (tt->engine_data->options.dhcp_renew)
			buf_printf (&cmd, " --dhcp-renew");
		buf_printf (&cmd, " --dhcp-internal %u", (unsigned int)tt->engine_data->adapter_index);

		fork_to_self (BSTR (&cmd));
		gc_free (&gc);
	}
}

void
fork_register_dns_action (struct tuntap *tt)
{
	if (tt && tt->engine_data->options.register_dns) {
		struct gc_arena gc = gc_new ();
		struct buffer cmd = alloc_buf_gc (256, &gc);
		const int verb = 3;

		buf_printf (&cmd, "openvpn --verb %d --register-dns --rdns-internal", verb);
		fork_to_self (BSTR (&cmd));
		gc_free (&gc);
	}
}

static uint32_t
dhcp_masq_addr (const in_addr_t local, const in_addr_t netmask, const int offset)
{
	struct gc_arena gc = gc_new ();
	in_addr_t dsa; /* DHCP server addr */

	if (offset < 0)
		dsa = (local | (~netmask)) + offset;
	else
		dsa = (local & netmask) + offset;

	if (dsa == local)
		msg (M_FATAL, "ERROR: There is a clash between the --ifconfig local address and the internal DHCP server address -- both are set to %s -- please use the --ip-win32 dynamic option to choose a different free address from the --ifconfig subnet for the internal DHCP server", print_in_addr_t (dsa, 0, &gc));

	if ((local & netmask) != (dsa & netmask))
		msg (M_FATAL, "ERROR: --ip-win32 dynamic [offset] : offset is outside of --ifconfig subnet");

	gc_free (&gc);
	return htonl(dsa);
}

static
int
tun_finalize (
	HANDLE h,
	struct overlapped_io *io,
	struct buffer *buf)
{
	int ret = -1;
	BOOL status;

	switch (io->iostate) {
		case IOSTATE_QUEUED:
			status = GetOverlappedResult(
				h,
				&io->overlapped,
				&io->size,
				FALSE
			);
			if (status) {
				/* successful return for a queued operation */
				if (buf)
				*buf = io->buf;
				ret = io->size;
				io->iostate = IOSTATE_INITIAL;
				ASSERT (ResetEvent (io->overlapped.hEvent));
				dmsg (D_WIN32_IO, "WIN32 I/O: TAP Completion success [%d]", ret);
			}
			else {
				/* error during a queued operation */
				ret = -1;
				if (GetLastError() != ERROR_IO_INCOMPLETE) {
					/* if no error (i.e. just not finished yet),
					then DON'T execute this code */
					io->iostate = IOSTATE_INITIAL;
					ASSERT (ResetEvent (io->overlapped.hEvent));
					msg (D_WIN32_IO | M_ERRNO, "WIN32 I/O: TAP Completion error");
				}
			}
			break;

		case IOSTATE_IMMEDIATE_RETURN:
			io->iostate = IOSTATE_INITIAL;
			ASSERT (ResetEvent (io->overlapped.hEvent));
			if (io->status) {
				/* error return for a non-queued operation */
				SetLastError (io->status);
				ret = -1;
				msg (D_WIN32_IO | M_ERRNO, "WIN32 I/O: TAP Completion non-queued error");
			}
			else {
				/* successful return for a non-queued operation */
				if (buf)
					*buf = io->buf;
				ret = io->size;
				dmsg (D_WIN32_IO, "WIN32 I/O: TAP Completion non-queued success [%d]", ret);
			}
			break;

		case IOSTATE_INITIAL: /* were we called without proper queueing? */
			SetLastError (ERROR_INVALID_FUNCTION);
			ret = -1;
			dmsg (D_WIN32_IO, "WIN32 I/O: TAP Completion BAD STATE");
			break;

		default:
			ASSERT (0);
	}

	if (buf)
		buf->len = ret;
	return ret;
}

static
void
tun_engine_windows_tun_init_post (
	struct tuntap *tt,
	const struct frame *frame,
	const tun_engine_options_t options
)
{
	tt->engine_data->options = *options;
	overlapped_io_init (&tt->engine_data->reads, frame, FALSE, true);
	overlapped_io_init (&tt->engine_data->writes, frame, TRUE, true);
	tt->rw_handle.read = tt->engine_data->reads.overlapped.hEvent;
	tt->rw_handle.write = tt->engine_data->writes.overlapped.hEvent;
	tt->engine_data->adapter_index = TUN_ADAPTER_INDEX_INVALID;
}

void
tun_engine_windows_tun_state_reset (struct tuntap *tt) {
	tun_engine_common_tun_state_reset(tt);
	if (tt->engine_data == NULL) {
		ALLOC_OBJ(tt->engine_data, struct tun_engine_private_data_s);
	}
	{
		struct tun_engine_options_s options = tt->engine_data->options;
		CLEAR(*tt->engine_data);
		tt->engine_data->options = options;
	}
	tt->config_before_open = true;
}

static
void
tun_engine_windows_tun_open (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt)
{
	struct gc_arena gc = gc_new ();
	char device_path[256];
	const char *device_guid = NULL;
	DWORD len;
	bool dhcp_masq = false;
	bool dhcp_masq_post = false;

	/*netcmd_semaphore_lock ();*/

	msg( M_INFO, "open_tun, tt->ipv6=%d", tt->ipv6 );

	if (tt->type == DEV_TYPE_NULL) {
		tun_engine_common_tun_open_null (tt);
		gc_free (&gc);
		return;
	}
	else if (tt->type == DEV_TYPE_TAP || tt->type == DEV_TYPE_TUN) {
		;
	}
	else {
		msg (M_FATAL|M_NOPREFIX, "Unknown virtual device type: '%s'", dev);
	}

	/*
	 * Lookup the device name in the registry, using the --dev-node high level name.
	 */
	{
		const struct tap_reg *tap_reg = get_tap_reg (&gc);
		const struct panel_reg *panel_reg = get_panel_reg (&gc);
		char actual_buffer[256];

		at_least_one_tap_win (tap_reg);

		if (dev_node) {
			/* Get the device GUID for the device specified with --dev-node. */
			device_guid = get_device_guid (dev_node, actual_buffer, sizeof (actual_buffer), tap_reg, panel_reg, &gc);

			if (!device_guid)
				msg (M_FATAL, "TAP-Windows adapter '%s' not found", dev_node);

			/* Open Windows TAP-Windows adapter */
			openvpn_snprintf (device_path, sizeof(device_path), "%s%s%s",
				USERMODEDEVICEDIR,
				device_guid,
				TAP_WIN_SUFFIX);

			tt->engine_data->hand = CreateFile (
				device_path,
				GENERIC_READ | GENERIC_WRITE,
				0, /* was: FILE_SHARE_READ */
				0,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
				0
			);

			if (tt->engine_data->hand == INVALID_HANDLE_VALUE)
			msg (M_ERR, "CreateFile failed on TAP device: %s", device_path);
		}
		else  {
			int device_number = 0;

			/* Try opening all TAP devices until we find one available */
			while (true) {
				device_guid = get_unspecified_device_guid (device_number, 
					actual_buffer, 
					sizeof (actual_buffer),
					tap_reg,
					panel_reg,
					&gc
				);

				if (!device_guid)
					msg (M_FATAL, "All TAP-Windows adapters on this system are currently in use.");

				/* Open Windows TAP-Windows adapter */
				openvpn_snprintf (device_path, sizeof(device_path), "%s%s%s",
					USERMODEDEVICEDIR,
					device_guid,
					TAP_WIN_SUFFIX);

				tt->engine_data->hand = CreateFile (
					device_path,
					GENERIC_READ | GENERIC_WRITE,
					0, /* was: FILE_SHARE_READ */
					0,
					OPEN_EXISTING,
					FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
					0
				);

				if (tt->engine_data->hand == INVALID_HANDLE_VALUE)
					msg (D_TUNTAP_INFO, "CreateFile failed on TAP device: %s", device_path);
				else
					break;

				device_number++;
			}
		}

		/* translate high-level device name into a device instance
		GUID using the registry */
		tt->actual_name = string_alloc (actual_buffer, NULL);
	}

	msg (M_INFO, "TAP-WIN32 device [%s] opened: %s", tt->actual_name, device_path);
		tt->engine_data->adapter_index = get_adapter_index (device_guid);
	tt->did_opened = true;

	/* get driver version info */
	{
		ULONG info[3];
		CLEAR (info);
		if (DeviceIoControl (tt->engine_data->hand, TAP_WIN_IOCTL_GET_VERSION,
			&info, sizeof (info),
			&info, sizeof (info), &len, NULL)) {
			msg (D_TUNTAP_INFO, "TAP-Windows Driver Version %d.%d %s",
			(int) info[0],
			(int) info[1],
			(info[2] ? "(DEBUG)" : ""));

		}
		if (!(info[0] == TAP_WIN_MIN_MAJOR && info[1] >= TAP_WIN_MIN_MINOR))
			msg (M_FATAL, "ERROR:  This version of " PACKAGE_NAME " requires a TAP-Windows driver that is at least version %d.%d -- If you recently upgraded your " PACKAGE_NAME " distribution, a reboot is probably required at this point to get Windows to see the new driver.",
			TAP_WIN_MIN_MAJOR,
			TAP_WIN_MIN_MINOR);

		/* usage of numeric constants is ugly, but this is really tied to
		 * *this* version of the driver
		 */
		if ( tt->ipv6 && tt->type == DEV_TYPE_TUN &&
			info[0] == 9 && info[1] < 8) {
			msg( M_INFO, "WARNING:  Tap-Win32 driver version %d.%d does not support IPv6 in TUN mode.  IPv6 will be disabled.  Upgrade to Tap-Win32 9.8 (2.2-beta3 release or later) or use TAP mode to get IPv6", (int) info[0], (int) info[1] );
			tt->ipv6 = false;
		}

		/* tap driver 9.8 (2.2.0 and 2.2.1 release) is buggy
		 */
		if ( tt->type == DEV_TYPE_TUN &&
			info[0] == 9 && info[1] == 8) {
			msg( M_FATAL, "ERROR:  Tap-Win32 driver version %d.%d is buggy regarding small IPv4 packets in TUN mode.  Upgrade to Tap-Win32 9.9 (2.2.2 release or later) or use TAP mode", (int) info[0], (int) info[1] );
		}
	}

	/* get driver MTU */
	{
		ULONG mtu;
		if (DeviceIoControl (tt->engine_data->hand, TAP_WIN_IOCTL_GET_MTU,
			&mtu, sizeof (mtu),
			&mtu, sizeof (mtu), &len, NULL)) {
			tt->post_open_mtu = (int) mtu;
			msg (D_MTU_INFO, "TAP-Windows MTU=%d", (int) mtu);
		}
	}

	/*
	 * Preliminaries for setting TAP-Windows adapter TCP/IP
	 * properties via --ip-win32 dynamic or --ip-win32 adaptive.
	*/
	if (tt->did_ifconfig_setup) {
		if (tt->engine_data->options.ip_win32_type == IPW32_SET_DHCP_MASQ) {
			/*
			 * If adapter is set to non-DHCP, set to DHCP mode.
			 */
			if (dhcp_status (tt->engine_data->adapter_index) == DHCP_STATUS_DISABLED)
				netsh_enable_dhcp (&tt->engine_data->options, tt->actual_name);
			dhcp_masq = true;
			dhcp_masq_post = true;
		}
		else if (tt->engine_data->options.ip_win32_type == IPW32_SET_ADAPTIVE) {
			/*
			 * If adapter is set to non-DHCP, use netsh right away.
			 */
			if (dhcp_status (tt->engine_data->adapter_index) != DHCP_STATUS_ENABLED) {
				netsh_ifconfig (&tt->engine_data->options,
				tt->actual_name,
				tt->local,
				tt->engine_data->adapter_netmask,
				NI_TEST_FIRST|NI_IP_NETMASK|NI_OPTIONS);
			}
			else {
				dhcp_masq = true;
			}
		}
	}

	/* set point-to-point mode if TUN device */

	if (tt->type == DEV_TYPE_TUN) {
		if (!tt->did_ifconfig_setup) {
			msg (M_FATAL, "ERROR: --dev tun also requires --ifconfig");
		}

		if (tt->topology == TOP_SUBNET) {
			in_addr_t ep[3];
			BOOL status;

			ep[0] = htonl (tt->local);
			ep[1] = htonl (tt->local & tt->remote_netmask);
			ep[2] = htonl (tt->remote_netmask);

			status = DeviceIoControl (tt->engine_data->hand, TAP_WIN_IOCTL_CONFIG_TUN,
				ep, sizeof (ep),
				ep, sizeof (ep), &len, NULL);

			msg (status ? M_INFO : M_FATAL, "Set TAP-Windows TUN subnet mode network/local/netmask = %s/%s/%s [%s]",
			print_in_addr_t (ep[1], IA_NET_ORDER, &gc),
			print_in_addr_t (ep[0], IA_NET_ORDER, &gc),
			print_in_addr_t (ep[2], IA_NET_ORDER, &gc),
			status ? "SUCCEEDED" : "FAILED");
		}
		else {
			in_addr_t ep[2];
			ep[0] = htonl (tt->local);
			ep[1] = htonl (tt->remote_netmask);

			if (!DeviceIoControl (tt->engine_data->hand, TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT,
				ep, sizeof (ep),
				ep, sizeof (ep), &len, NULL)) {
				msg (M_FATAL, "ERROR: The TAP-Windows driver rejected a DeviceIoControl call to set Point-to-Point mode, which is required for --dev tun");
			}
		}
	}

	/* should we tell the TAP-Windows driver to masquerade as a DHCP server as a means
	of setting the adapter address? */
	if (dhcp_masq) {
		uint32_t ep[4];

		/* We will answer DHCP requests with a reply to set IP/subnet to these values */
		ep[0] = htonl (tt->local);
		ep[1] = htonl (tt->engine_data->adapter_netmask);

		/* At what IP address should the DHCP server masquerade at? */
		if (tt->type == DEV_TYPE_TUN) {
			if (tt->topology == TOP_SUBNET) {
				if (tt->engine_data->options.dhcp_masq_custom_offset)
					ep[2] = dhcp_masq_addr (tt->local, tt->remote_netmask, tt->engine_data->options.dhcp_masq_offset);
				else
					ep[2] = dhcp_masq_addr (tt->local, tt->remote_netmask, -1);
			}
			else
				ep[2] = htonl (tt->remote_netmask);
		}
		else {
			ASSERT (tt->type == DEV_TYPE_TAP);
			ep[2] = dhcp_masq_addr (tt->local, tt->engine_data->adapter_netmask, tt->engine_data->options.dhcp_masq_custom_offset ? tt->engine_data->options.dhcp_masq_offset : 0);
		}

		/* lease time in seconds */
		ep[3] = (uint32_t) tt->engine_data->options.dhcp_lease_time;

		ASSERT (ep[3] > 0);

#ifndef SIMULATE_DHCP_FAILED /* this code is disabled to simulate bad DHCP negotiation */
		if (!DeviceIoControl (tt->engine_data->hand, TAP_WIN_IOCTL_CONFIG_DHCP_MASQ,
			ep, sizeof (ep),
			ep, sizeof (ep), &len, NULL)) {
			msg (M_FATAL, "ERROR: The TAP-Windows driver rejected a DeviceIoControl call to set TAP_WIN_IOCTL_CONFIG_DHCP_MASQ mode");
		}

		msg (M_INFO, "Notified TAP-Windows driver to set a DHCP IP/netmask of %s/%s on interface %s [DHCP-serv: %s, lease-time: %d]",
			print_in_addr_t (tt->local, 0, &gc),
			print_in_addr_t (tt->engine_data->adapter_netmask, 0, &gc),
			device_guid,
			print_in_addr_t (ep[2], IA_NET_ORDER, &gc),
			ep[3]
		);

		/* user-supplied DHCP options capability */
		if (tt->engine_data->options.dhcp_options) {
			struct buffer buf = alloc_buf (256);
			if (build_dhcp_options_string (&buf, &tt->engine_data->options)) {
				msg (D_DHCP_OPT, "DHCP option string: %s", format_hex (BPTR (&buf), BLEN (&buf), 0, &gc));
				if (!DeviceIoControl (tt->engine_data->hand, TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT,
					BPTR (&buf), BLEN (&buf),
					BPTR (&buf), BLEN (&buf), &len, NULL)) {
					msg (M_FATAL, "ERROR: The TAP-Windows driver rejected a TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT DeviceIoControl call");
				}
			}
			else
			msg (M_WARN, "DHCP option string not set due to error");
			free_buf (&buf);
		}
#endif
	}

	/* set driver media status to 'connected' */
	{
		ULONG status = TRUE;
		if (!DeviceIoControl (tt->engine_data->hand, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
		&status, sizeof (status),
		&status, sizeof (status), &len, NULL))
		msg (M_WARN, "WARNING: The TAP-Windows driver rejected a TAP_WIN_IOCTL_SET_MEDIA_STATUS DeviceIoControl call.");
	}

	/* possible wait for adapter to come up */
	{
		int s = tt->engine_data->options.tap_sleep;
		if (s > 0) {
			msg (M_INFO, "Sleeping for %d seconds...", s);
			openvpn_sleep (s);
		}
	}

	/* possibly use IP Helper API to set IP address on adapter */
	{
		const DWORD index = tt->engine_data->adapter_index;

		/* flush arp cache */
		if (index != TUN_ADAPTER_INDEX_INVALID) {
			DWORD status;

			if ((status = FlushIpNetTable (index)) == NO_ERROR)
				msg (M_INFO, "Successful ARP Flush on interface [%u] %s",
				(unsigned int)index,
				device_guid);
			else
				msg (D_TUNTAP_INFO, "NOTE: FlushIpNetTable failed on interface [%u] %s (status=%u) : %s",
					(unsigned int)index,
					device_guid,
					(unsigned int)status,
					strerror_win32 (status, &gc));
		}

		/*
		 * If the TAP-Windows driver is masquerading as a DHCP server
		 * make sure the TCP/IP properties for the adapter are
		 * set correctly.
		 */
		if (dhcp_masq_post) {
			/* check dhcp enable status */
			if (dhcp_status (index) == DHCP_STATUS_DISABLED)
				msg (M_WARN, "WARNING: You have selected '--ip-win32 dynamic', which will not work unless the TAP-Windows TCP/IP properties are set to 'Obtain an IP address automatically'");

			/* force an explicit DHCP lease renewal on TAP adapter? */
			if (tt->engine_data->options.dhcp_pre_release)
				dhcp_release (tt);
			if (tt->engine_data->options.dhcp_renew)
				dhcp_renew (tt);
		}
		else
			fork_dhcp_action (tt);

		if (tt->did_ifconfig_setup && tt->engine_data->options.ip_win32_type == IPW32_SET_IPAPI) {
			DWORD status;
			const char *error_suffix = "I am having trouble using the Windows 'IP helper API' to automatically set the IP address -- consider using other --ip-win32 methods (not 'ipapi')";

			/* couldn't get adapter index */
			if (index == TUN_ADAPTER_INDEX_INVALID) {
				msg (M_FATAL, "ERROR: unable to get adapter index for interface %s -- %s",
					device_guid,
					error_suffix);
			}

			/* check dhcp enable status */
			if (dhcp_status (index) == DHCP_STATUS_DISABLED)
				msg (M_WARN, "NOTE: You have selected (explicitly or by default) '--ip-win32 ipapi', which has a better chance of working correctly if the TAP-Windows TCP/IP properties are set to 'Obtain an IP address automatically'");

			/* delete previously added IP addresses which were not
			correctly deleted */
			delete_temp_addresses (index);

			/* add a new IP address */
			if ((status = AddIPAddress (htonl(tt->local),
				htonl(tt->engine_data->adapter_netmask),
				index,
				&tt->engine_data->ipapi_context,
				&tt->engine_data->ipapi_instance)) == NO_ERROR) {
				msg (M_INFO, "Succeeded in adding a temporary IP/netmask of %s/%s to interface %s using the Win32 IP Helper API",
					print_in_addr_t (tt->local, 0, &gc),
					print_in_addr_t (tt->engine_data->adapter_netmask, 0, &gc),
					device_guid
				);
			}
			else {
				msg (M_FATAL, "ERROR: AddIPAddress %s/%s failed on interface %s, index=%d, status=%u (windows error: '%s') -- %s",
					print_in_addr_t (tt->local, 0, &gc),
					print_in_addr_t (tt->engine_data->adapter_netmask, 0, &gc),
					device_guid,
					(int)index,
					(unsigned int)status,
					strerror_win32 (status, &gc),
					error_suffix);
			}
			tt->engine_data->ipapi_context_defined = true;
		}
	}
	/*netcmd_semaphore_release ();*/
	gc_free (&gc);
}

static
void
tun_engine_windows_tun_close (struct tuntap *tt)
{
	struct gc_arena gc = gc_new ();

	if (tt) {
		if ( tt->ipv6 && tt->did_ifconfig_ipv6_setup ) {
			const char *ifconfig_ipv6_local;
			struct argv argv;
			argv_init (&argv);

			/* remove route pointing to interface */
			tt->engine->route_delete_connected_v6_net(tt, NULL);

			/* netsh interface ipv6 delete address \"%s\" %s */
			ifconfig_ipv6_local = print_in6_addr (tt->local_ipv6, 0,  &gc);
			argv_printf (&argv,
			"%s%sc interface ipv6 delete address %s %s",
			get_win_sys_path(),
			NETSH_PATH_SUFFIX,
			tt->actual_name,
			ifconfig_ipv6_local );

			netsh_command (&argv, 1);
			argv_reset (&argv);
		}
#if 1
		if (tt->engine_data->ipapi_context_defined) {
			DWORD status;
			if ((status = DeleteIPAddress (tt->engine_data->ipapi_context)) != NO_ERROR) {
				msg (M_WARN, "Warning: DeleteIPAddress[%u] failed on TAP-Windows adapter, status=%u : %s",
					(unsigned int)tt->engine_data->ipapi_context,
					(unsigned int)status,
					strerror_win32 (status, &gc));
			}
		}
#endif

		if (tt->engine_data->options.dhcp_release)
			dhcp_release (tt);

		if (tt->engine_data->hand != NULL) {
			dmsg (D_WIN32_IO_LOW, "Attempting CancelIO on TAP-Windows adapter");
			if (!CancelIo (tt->engine_data->hand))
				msg (M_WARN | M_ERRNO, "Warning: CancelIO failed on TAP-Windows adapter");
		}

		dmsg (D_WIN32_IO_LOW, "Attempting close of overlapped read event on TAP-Windows adapter");
		overlapped_io_close (&tt->engine_data->reads);

		dmsg (D_WIN32_IO_LOW, "Attempting close of overlapped write event on TAP-Windows adapter");
		overlapped_io_close (&tt->engine_data->writes);

		if (tt->engine_data->hand != NULL) {
			dmsg (D_WIN32_IO_LOW, "Attempting CloseHandle on TAP-Windows adapter");
			if (!CloseHandle (tt->engine_data->hand))
				msg (M_WARN | M_ERRNO, "Warning: CloseHandle failed on TAP-Windows adapter");
		}

		tun_engine_common_tun_close_generic(tt);
	}

	gc_free (&gc);
}

static
int
tun_engine_windows_tun_write (struct tuntap *tt, struct buffer *buf)
{
	int err = 0;
	int status = 0;
	if (overlapped_io_active (&tt->engine_data->writes)) {
		status = tun_finalize (tt->engine_data->hand, &tt->engine_data->writes, NULL);
		if (status < 0)
			err = GetLastError ();
	}
	tt->engine->tun_write_queue (tt, buf);
	if (status < 0) {
		SetLastError (err);
		return status;
	}
	else
		return BLEN (buf);
}

static
int
tun_engine_windows_tun_read (struct tuntap *tt, struct buffer *buf, int size, int maxsize)
{
	return tun_finalize (tt->engine_data->hand, &tt->engine_data->reads, buf);
}

static
int
tun_engine_windows_tun_read_queue (struct tuntap *tt, int maxsize)
{
	if (tt->engine_data->reads.iostate == IOSTATE_INITIAL) {
		DWORD len;
		BOOL status;
		int err;

		/* reset buf to its initial state */
		tt->engine_data->reads.buf = tt->engine_data->reads.buf_init;

		len = maxsize ? maxsize : BLEN (&tt->engine_data->reads.buf);
		ASSERT (len <= BLEN (&tt->engine_data->reads.buf));

		/* the overlapped read will signal this event on I/O completion */
		ASSERT (ResetEvent (tt->engine_data->reads.overlapped.hEvent));

		status = ReadFile(
			tt->engine_data->hand,
			BPTR (&tt->engine_data->reads.buf),
			len,
			&tt->engine_data->reads.size,
			&tt->engine_data->reads.overlapped
		);

		if (status) { /* operation completed immediately? */
			/* since we got an immediate return, we must signal the event object ourselves */
			ASSERT (SetEvent (tt->engine_data->reads.overlapped.hEvent));

			tt->engine_data->reads.iostate = IOSTATE_IMMEDIATE_RETURN;
			tt->engine_data->reads.status = 0;

			dmsg (D_WIN32_IO, "WIN32 I/O: TAP Read immediate return [%d,%d]",
				(int) len,
				(int) tt->engine_data->reads.size);	       
		}
		else {
			err = GetLastError (); 
			if (err == ERROR_IO_PENDING) { /* operation queued? */
				tt->engine_data->reads.iostate = IOSTATE_QUEUED;
				tt->engine_data->reads.status = err;
				dmsg (D_WIN32_IO, "WIN32 I/O: TAP Read queued [%d]",
				(int) len);
			}
			else { /* error occurred */
				struct gc_arena gc = gc_new ();
				ASSERT (SetEvent (tt->engine_data->reads.overlapped.hEvent));
				tt->engine_data->reads.iostate = IOSTATE_IMMEDIATE_RETURN;
				tt->engine_data->reads.status = err;
				dmsg (D_WIN32_IO, "WIN32 I/O: TAP Read error [%d] : %s",
					(int) len,
					strerror_win32 (status, &gc));
					gc_free (&gc);
			}
		}
	}
	return tt->engine_data->reads.iostate;
}

static
int
tun_engine_windows_tun_write_queue (struct tuntap *tt, struct buffer *buf)
{
	if (tt->engine_data->writes.iostate == IOSTATE_INITIAL) {
		BOOL status;
		int err;

		/* make a private copy of buf */
		tt->engine_data->writes.buf = tt->engine_data->writes.buf_init;
		tt->engine_data->writes.buf.len = 0;
		ASSERT (buf_copy (&tt->engine_data->writes.buf, buf));

		/* the overlapped write will signal this event on I/O completion */
		ASSERT (ResetEvent (tt->engine_data->writes.overlapped.hEvent));

		status = WriteFile(
			tt->engine_data->hand,
			BPTR (&tt->engine_data->writes.buf),
			BLEN (&tt->engine_data->writes.buf),
			&tt->engine_data->writes.size,
			&tt->engine_data->writes.overlapped
		);

		if (status) { /* operation completed immediately? */
			tt->engine_data->writes.iostate = IOSTATE_IMMEDIATE_RETURN;

			/* since we got an immediate return, we must signal the event object ourselves */
			ASSERT (SetEvent (tt->engine_data->writes.overlapped.hEvent));

			tt->engine_data->writes.status = 0;

			dmsg (D_WIN32_IO, "WIN32 I/O: TAP Write immediate return [%d,%d]",
				BLEN (&tt->engine_data->writes.buf),
				(int) tt->engine_data->writes.size);	       
		}
		else {
			err = GetLastError (); 
			if (err == ERROR_IO_PENDING) { /* operation queued? */
				tt->engine_data->writes.iostate = IOSTATE_QUEUED;
				tt->engine_data->writes.status = err;
				dmsg (D_WIN32_IO, "WIN32 I/O: TAP Write queued [%d]",
					BLEN (&tt->engine_data->writes.buf));
			}
			else { /* error occurred */
				struct gc_arena gc = gc_new ();
				ASSERT (SetEvent (tt->engine_data->writes.overlapped.hEvent));
				tt->engine_data->writes.iostate = IOSTATE_IMMEDIATE_RETURN;
				tt->engine_data->writes.status = err;
				dmsg (D_WIN32_IO, "WIN32 I/O: TAP Write error [%d] : %s",
					BLEN (&tt->engine_data->writes.buf),
					strerror_win32 (err, &gc));
				gc_free (&gc);
			}
		}
	}
	return tt->engine_data->writes.iostate;
}

static
bool
tun_engine_windows_tun_stop (int status)
{
	/*
	 * This corresponds to the STATUS_NO_SUCH_DEVICE
	 * error in tapdrvr.c.
	 */
	if (status < 0) {
		return openvpn_errno () == ERROR_FILE_NOT_FOUND;
	}
	else {
		return false;
	}
}

const char *
tun_engine_windows_tun_status (const struct tuntap *tt, unsigned int rwflags, struct gc_arena *gc)
{
	struct buffer out = alloc_buf_gc (64, gc);
	if (rwflags & EVENT_READ) {
		buf_printf (&out, "T%s%s",
			(tt->rwflags_debug & EVENT_READ) ? "R" : "r",
			overlapped_io_state_ascii (&tt->engine_data->reads));
	}
	if (rwflags & EVENT_WRITE) {
		buf_printf (&out, "T%s%s",
			(tt->rwflags_debug & EVENT_WRITE) ? "W" : "w",
			overlapped_io_state_ascii (&tt->engine_data->writes));
	}
	return BSTR (&out);
}

static
const char *
tun_engine_windows_tun_info (const struct tuntap *tt, struct gc_arena *gc)
{
	if (tt && tt->engine_data->hand != NULL) {
		struct buffer out = alloc_buf_gc (256, gc);
		DWORD len;
		if (DeviceIoControl (tt->engine_data->hand, TAP_WIN_IOCTL_GET_INFO,
			BSTR (&out), BCAP (&out),
			BSTR (&out), BCAP (&out),
			&len, NULL)
		) {
			return BSTR (&out);
		}
	}
	return NULL;
}

static
void
tun_engine_windows_tun_debug_show (struct tuntap *tt)
{
	if (tt && tt->engine_data->hand != NULL) {
		struct buffer out = alloc_buf (1024);
		DWORD len;
		while (
			DeviceIoControl (
				tt->engine_data->hand,
				TAP_WIN_IOCTL_GET_LOG_LINE,
				BSTR (&out), BCAP (&out),
				BSTR (&out), BCAP (&out),
				&len, NULL
			)
		) {
			msg (D_TAP_WIN_DEBUG, "TAP-Windows: %s", BSTR (&out));
		}
		free_buf (&out);
	}
}

static
const char *
tun_engine_windows_tun_device_guess (
	struct tuntap *tt,
	const char *dev,
	const char *dev_type,
	const char *dev_node,
	struct gc_arena *gc
) {
	const int dt = tun_dev_type_enum (dev, dev_type);
	if (dt == DEV_TYPE_TUN || dt == DEV_TYPE_TAP) {
		return netsh_get_id (dev_node, gc);
	}
	else {
		return dev;
	}
}

static
void
tun_engine_windows_tun_ifconfig (
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
	struct gc_arena gc = gc_new ();
	struct argv argv;

	argv_init (&argv);

	/*
	* Make sure that both ifconfig addresses are part of the
	* same .252 subnet.
	*/
	if (tun) {
		verify_255_255_255_252 (tt->local, tt->remote_netmask);
		tt->engine_data->adapter_netmask = ~3;
	}
	else {
		tt->engine_data->adapter_netmask = tt->remote_netmask;
	}

	switch (tt->engine_data->options.ip_win32_type) {
		case IPW32_SET_MANUAL:
			msg (M_INFO, "******** NOTE:  Please manually set the IP/netmask of '%s' to %s/%s (if it is not already set)",
				actual,
				ifconfig_local,
				print_in_addr_t (tt->engine_data->adapter_netmask, 0, &gc));
			break;
		case IPW32_SET_NETSH:
			if (!strcmp (actual, "NULL"))
				msg (M_FATAL, "Error: When using --ip-win32 netsh, if you have more than one TAP-Windows adapter, you must also specify --dev-node");

			netsh_ifconfig (&tt->engine_data->options,
				actual,
				tt->local,
				tt->engine_data->adapter_netmask,
				NI_IP_NETMASK|NI_OPTIONS);

			break;
	}
	tt->did_ifconfig = true;

	/* IPv6 always uses "netsh" interface */
	if ( do_ipv6 ) {
		char * saved_actual;

		if (!strcmp (actual, "NULL"))
			msg (M_FATAL, "Error: When using --tun-ipv6, if you have more than one TAP-Windows adapter, you must also specify --dev-node");

		/* example: netsh interface ipv6 set address MyTap 2001:608:8003::d store=active */
		argv_printf (&argv,
			"%s%sc interface ipv6 set address %s %s store=active",
			get_win_sys_path(),
			NETSH_PATH_SUFFIX,
			actual,
			ifconfig_ipv6_local );

		netsh_command (&argv, 4);

		/* explicit route needed */
		/* on windows, OpenVPN does ifconfig first, open_tun later, so
		* tt->actual_name might not yet be initialized, but routing code
		* needs to know interface name - point to "actual", restore later
		*/
		saved_actual = tt->actual_name;
		tt->actual_name = (char*) actual;
		tt->engine->route_add_connected_v6_net(tt, es);
		tt->actual_name = saved_actual;
	}
	argv_reset (&argv);
	gc_free (&gc);
}

static struct tun_engine_s _tun_engine = {
	tun_engine_common_tun_init,
	tun_engine_windows_tun_init_post,
	tun_engine_windows_tun_state_reset,
	tun_engine_windows_tun_open,
	tun_engine_windows_tun_close,
	tun_engine_windows_tun_stop,
	tun_engine_windows_tun_status,
	tun_engine_windows_tun_write,
	tun_engine_windows_tun_read,
	tun_engine_windows_tun_write_queue,
	tun_engine_windows_tun_read_queue,
	tun_engine_windows_tun_info,
	tun_engine_windows_tun_debug_show,
	tun_engine_windows_tun_standby_init,
	tun_engine_windows_tun_standby,
	NULL, /* tun_config */
	tun_engine_windows_tun_device_guess,
	NULL, /* tun_device_open_dynamic */
	tun_engine_windows_tun_ifconfig,
	tun_engine_common_tun_is_p2p,
	tun_engine_common_route_add_connected_v6_net,
	tun_engine_common_route_delete_connected_v6_net
};
tun_engine_t tun_engine = &_tun_engine;

#endif
