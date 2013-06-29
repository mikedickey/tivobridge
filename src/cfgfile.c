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

#include "common.h"

#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#include "logger.h"
#include "cfgfile.h"

static TunnelListEntry *s_pTunnels = NULL;
static TunnelListEntry *s_pCurrent;
static IPListEntry *s_pInterfaces;
static int s_bBadSection, s_bOptionSection;

static void delete_ip_list(IPListEntry *pList)
{
	while (pList)
	{
		IPListEntry *pNext = pList->pNext;
		free(pList);
		pList = pNext;
	}
}

static void delete_tunnel_list(TunnelListEntry *pItem)
{
	while (pItem)
	{
		TunnelListEntry *pNext = pItem->pNext;
		delete_ip_list(pItem->pFromList);
		delete_ip_list(pItem->pNotFromList);
		delete_ip_list(pItem->pOrigin);
		delete_ip_list(pItem->pFwdList);
		free(pItem);

		pItem = pNext;
	}
}

void cleanup_config()
{
	delete_tunnel_list(s_pTunnels);
	s_pTunnels = NULL;

	delete_ip_list(s_pInterfaces);
	s_pInterfaces = NULL;
}

const TunnelListEntry* get_tunnel_list()
{
	return s_pTunnels;
}

const IPListEntry* get_interface_list()
{
	return s_pInterfaces;
}

static void make_lower(char *szLine)
{
	while (*szLine)
	{
		char ch = *szLine;
		if (ch >= 'A' && ch <= 'Z')
			*szLine = ch - 'A' + 'a';

		szLine++;
	}
}

static void trim_line(char *szLine)
{
	int i;
	char *pTmp;

	pTmp = strchr(szLine, '#');
	if (pTmp)
		*pTmp = 0;

	while (*szLine && strchr(" \r\n\t", *szLine))
		strcpy(szLine, szLine+1);

	i = strlen(szLine);
	while (i--)
	{
		if (strchr(" \r\n\t", szLine[i]))
			szLine[i] = 0;
	}
}

static void validate_current_tunnel()
{
	if (!s_pCurrent)
		return;

	if (s_pCurrent->pFwdList && !s_bBadSection)
	{
		s_pCurrent->pNext = s_pTunnels;
		s_pTunnels = s_pCurrent; 
	}
	else
		delete_tunnel_list(s_pCurrent);

	s_pCurrent = NULL;
}

static void process_section_line(char *szLine)
{
	int nType = 0;

	validate_current_tunnel();
	s_bOptionSection = 0;

	if (szLine[strlen(szLine)-1] != ']')
	{
		log_message(LOG_WARNING, "Broken config section line - %s",
			szLine);
		return;
	}

	strcpy(szLine, szLine + 1);
	szLine[strlen(szLine)-1] = 0;

	make_lower(szLine);
	if (!strcmp(szLine, "options"))
	{
		s_bOptionSection = 1;
		s_bBadSection = 0;
		return;
	}
	else if (!strcmp(szLine, "tivo"))
		nType = TUNNEL_TIVO;
#ifdef ENABLE_MDNS
	else if (!strcmp(szLine, "mdns"))
		nType = TUNNEL_MDNS;
#endif
	else
	{
		log_message(LOG_WARNING, "Invalid config section type - %s",
			szLine);
		return;
	}

	s_pCurrent = (TunnelListEntry*)malloc(sizeof(TunnelListEntry));
	s_pCurrent->nType = nType;
	s_pCurrent->pFromList = s_pCurrent->pNotFromList =
		s_pCurrent->pOrigin = s_pCurrent->pFwdList = NULL;

	s_bBadSection = 0;
}

static void parse_ip_property(IPListEntry **ppList, char *szIP, int bFwd)
{
	u_int32_t ip = inet_addr(szIP);
	IPListEntry *pItem;

	if (ip == INADDR_NONE)
	{
		if (strcmp(szIP, "255.255.255.255") || !bFwd)
		{
			s_bBadSection = 1;
			log_message(LOG_ERR, "Invalid IP address "
				"in config - %s", szIP);
			return;
		}
	}

	pItem = (IPListEntry*)malloc(sizeof(IPListEntry));
	pItem->nIP = ip;
	pItem->nMask = 0xffffffff;
	pItem->pNext = *ppList;
	*ppList = pItem;
}

static void parse_cidr_property(IPListEntry **ppList, char *szIP)
{
	u_int32_t ip, mask;
	IPListEntry *pItem;
	char *pTmp = strchr(szIP, '/');
	int count = 32;

	if (pTmp)
	{
		*(pTmp++) = 0;
		count = atoi(pTmp);
	}

	ip = inet_addr(szIP);
	if (ip == INADDR_NONE || count < 1 || count > 32)
	{
		if (pTmp)
			*(pTmp-1) = '/';

		log_message(LOG_ERR, "Invalid CIDR value in config - %s", szIP);
		s_bBadSection = 1;
		return;
	}

	mask = htonl(0xffffffff & ~((1 << (32 - count)) - 1));
	ip &= mask;

	pItem = (IPListEntry*)malloc(sizeof(IPListEntry));
	pItem->nIP = ip;
	pItem->nMask = mask;
	pItem->pNext = *ppList;
	*ppList = pItem;
}

static void process_option_line(char *szName, char *szValue)
{
	if (!strcmp(szName, "interface"))
		parse_ip_property(&s_pInterfaces, szValue, 0);
	else
		log_message(LOG_WARNING, "Unknown option - %s", szName);
}

static void process_property_line(char *szLine)
{
	char *pValue = strchr(szLine, '=');
	if (!pValue)
		return;

	*(pValue++) = 0;
	trim_line(szLine);
	trim_line(pValue);
	if (!(*szLine) || !(*pValue))
		return;

	make_lower(szLine);
	if (s_bOptionSection)
	{
		process_option_line(szLine, pValue);
		return;
	}
	else if (!s_pCurrent)
		return;

	if (!strcmp(szLine, "from"))
		parse_cidr_property(&s_pCurrent->pFromList, pValue);
	else if (!strcmp(szLine, "notfrom"))
		parse_cidr_property(&s_pCurrent->pNotFromList, pValue);
	else if (!strcmp(szLine, "origin"))
		parse_ip_property(&s_pCurrent->pOrigin, pValue, 0);
	else if (!strcmp(szLine, "to"))
		parse_ip_property(&s_pCurrent->pFwdList, pValue, 1);
	else
		log_message(LOG_WARNING, "Unknown rule property - %s", szLine);
}

int read_config_file(const char *szFile)
{	
	FILE *fp;
	int nTotal = 0, nTivo = 0, nMDNS = 0;
	TunnelListEntry *pTmp;

	cleanup_config();
	s_pCurrent = NULL;
	s_bOptionSection = 0;

	fp = fopen(szFile, "r");
	if (fp)
	{
		char buf[1024];
		while (fgets(buf, 1024, fp))
		{
			buf[1023] = 0;
			trim_line(buf);
			if (!*buf)
				continue;

			if (*buf == '[')
				process_section_line(buf);
			else
				process_property_line(buf);
		}

		fclose(fp);
		validate_current_tunnel();
	}
	else
	{
		log_message(LOG_ERR, "Can't open config file %s", szFile);
		return 0;
	}

	pTmp = s_pTunnels;
	while (pTmp)
	{
		nTotal++;
		if (pTmp->nType == TUNNEL_TIVO)
			nTivo++;
		else
			nMDNS++;

		pTmp = pTmp->pNext;
	}

	log_message(LOG_INFO, "%d tunnel%s loaded"
#ifdef ENABLE_MDNS
		" (%d TiVo beacon, %d mDNS)"
#endif
		,
		nTotal, (nTotal == 1) ? "" : "s"
#ifdef ENABLE_MDNS
		, nTivo, nMDNS
#endif
		);

	return 1;
}
