/* TiVoBridge - TiVo/mDNS packet repeater daemon
   Copyright (C) 2006-2007  Brian Smith

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
*/

#ifndef _CFGFILE_H_INCLUDED_
#define _CFGFILE_H_INCLUDED_

typedef struct IPListEntry
{
	u_int32_t nIP, nMask;

	struct IPListEntry *pNext;
} IPListEntry;

typedef struct TunnelListEntry
{
	int nType;
	IPListEntry *pFromList;
	IPListEntry *pNotFromList;
	IPListEntry *pOrigin;
	IPListEntry *pFwdList;

	struct TunnelListEntry *pNext;
} TunnelListEntry;

// Tunnel types
#define TUNNEL_TIVO	1	// TiVo discovery beacon
#define TUNNEL_MDNS	2	// Multicast DNS

void cleanup_config();
const TunnelListEntry* get_tunnel_list();
const IPListEntry *get_interface_list();

#endif
