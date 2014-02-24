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

#if HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#if HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#if HAVE_FCNTL_H
# include <fcntl.h>
#endif

#include <pwd.h>
#include <signal.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "logger.h"
#include "cfgfile.h"

#if defined(__APPLE__)
	#define iphdr ip
	#define SOL_IP IPPROTO_IP
#endif


#define IP_VERSION 4

static int raw_skt, tivo_sock = -1, mdns_sock = -1;
static char *szCfgFile = SYSCONFDIR "/tivobridge.conf";
static char *szRunUser = NULL;
static int daemon_mode = 1, run_flag = 1, reload_config = 0;

// Raw socket functions

typedef struct raw_pkt
{
	struct ip ip;
	struct udphdr udp;
	char data[1];
} raw_pkt;

static unsigned short checksum(unsigned short* addr,char len)
{
	/* This is a simplified version that expects even number of bytes */
	register long sum = 0;

	while(len > 1)
	{
        	sum += *addr++;
	        len -= 2;
        }

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

static void send_packet(const TunnelListEntry *pTunnel, const IPListEntry *pFwd,
	struct in_addr *pSrcIP, int nSrcPort, char *szData, int nLen)
{
	int nPort, pkt_len, rc;
	raw_pkt *pkt;
	u_int32_t addrfrom;
	struct sockaddr_in sa;

	sa.sin_addr.s_addr = pFwd->nIP;
	sa.sin_family = AF_INET;

	switch (pTunnel->nType)
	{
	case TUNNEL_TIVO:	nPort = 2190; break;
	case TUNNEL_MDNS:	nPort = 5353; break;
	default:		return;
	}

	pkt_len = sizeof(raw_pkt) + nLen - 1;
	pkt = (raw_pkt*)malloc(pkt_len);
	if (!pkt)
		return;

	addrfrom = pTunnel->pOrigin ? pTunnel->pOrigin->nIP : pSrcIP->s_addr;

	pkt->ip.ip_v = IP_VERSION;
	pkt->ip.ip_hl = sizeof(struct iphdr) >> 2;
	pkt->ip.ip_tos = 0;
	pkt->ip.ip_len = htons(pkt_len);
	pkt->ip.ip_id = htons(getpid() & 0xffff);
	pkt->ip.ip_off = 0;
	pkt->ip.ip_ttl = 0xff;
	pkt->ip.ip_p = IPPROTO_UDP;
	pkt->ip.ip_sum = 0;
	pkt->ip.ip_src.s_addr = addrfrom;
	pkt->ip.ip_dst.s_addr = pFwd->nIP;
	pkt->ip.ip_sum = checksum((unsigned short*)pkt, sizeof(struct ip));

	pkt->udp.uh_sport = htons(nSrcPort);
	pkt->udp.uh_dport = htons(nPort);
	pkt->udp.uh_ulen = htons(pkt_len - sizeof(struct ip));
	pkt->udp.uh_sum = 0;

	memcpy(pkt->data, szData, nLen);
	rc = sendto(raw_skt, pkt, pkt_len, 0, (struct sockaddr*)&sa,
		sizeof(sa));
	free(pkt);
}

// Main processing logic

static int drop_privs()
{
	struct passwd *info = NULL;

	if (szRunUser)
		info = getpwnam(szRunUser);
	if (!info)
		info = getpwnam("nobody");
	if (!info)
		return 0;
	if (info->pw_uid == 0)
		return 0;

	return (setuid(info->pw_uid) == 0);
}

RETSIGTYPE handle_reconfig(int sig)
{
	reload_config = 1;
}

RETSIGTYPE handle_term(int sig)
{
	run_flag = 0;
}

#if HAVE_WORKING_FORK
static void daemonize()
{
	pid_t pid;
	int i;

	pid = fork();
	if (pid<0) exit(1);	// Error
	if (pid>0) exit(0);	// Parent exits

	setsid();
	umask(027);
	chdir("/");

	i = getdtablesize();
	while (i--)
		close(i);
	i = open("/dev/null", O_RDWR);
	dup(i);
	dup(i);

	signal(SIGCHLD, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGHUP, handle_reconfig);
	signal(SIGTERM, handle_term);
}
#endif

static void show_version()
{
	printf(PACKAGE_STRING " - TiVo"
#ifdef ENABLE_MDNS
		"/mDNS"
#endif
		" packet repeater\n");
}

static void show_usage(char *szCmd)
{
	printf("Usage:  %s [-c config_file] [-u username] [-f] [-v] [-h]\n",
		szCmd);
}

static void parse_options(int argc, char** argv)
{
	int cont_flag = 1, opt_err = 0, show_ver = 0, show_help = 0;

	do
	{
		int ch = getopt(argc, argv, "fvhc:u:");
		if (ch == -1)
			break;

		switch (ch)
		{
		case 'c':	szCfgFile = strdup(optarg); break;
		case 'u':	szRunUser = strdup(optarg); break;
		case 'v':	show_ver = 1; break;
		case 'h':	show_help = 1; break;
		case 'f':	daemon_mode = 0; break;
		case '?':
		default:	opt_err = 1; break;
		}
	} while (cont_flag);

	if (opt_err || show_help)
	{
		show_version();
		show_usage(argv[0]);
		exit(opt_err ? 1 : 0);
	}

	if (show_ver)
	{
		show_version();
		exit(0);
	}
}

static int create_listeners()
{
	struct sockaddr_in addr;
	struct ip_mreq req;
	int oneopt;

	tivo_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (tivo_sock < 0)
		return 0;

	addr.sin_port = htons(2190);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(tivo_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
		return 0;

#if defined(IP_PKTINFO)
# define CHECK_DST_ADDR
	oneopt = 1;
	if (setsockopt(tivo_sock, SOL_IP, IP_PKTINFO, &oneopt, 
		sizeof(oneopt)) < 0)
		return 0;
#elif defined(IP_RECVIF)
# define CHECK_DST_ADDR
	oneopt = 1;
	if (setsockopt(tivo_sock, IPPROTO_IP, IP_RECVIF, &oneopt,
		sizeof(oneopt)) < 0)
		return 0;
#endif

#ifdef ENABLE_MDNS
	mdns_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (mdns_sock < 0)
		return 0;

	addr.sin_port = htons(5353);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;

	oneopt = 1;
	if (setsockopt(mdns_sock, SOL_SOCKET, SO_REUSEADDR, &oneopt, sizeof(oneopt)) < 0) {
	    return 0;
	}

#ifdef SO_REUSEPORT
	oneopt = 1;
	if (setsockopt(mdns_sock, SOL_SOCKET, SO_REUSEPORT, &oneopt, sizeof(oneopt)) < 0) {
	    return 0;
	}
#endif

	if (bind(mdns_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
		return 0;

	req.imr_interface.s_addr = INADDR_ANY;
	req.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
	if (setsockopt(mdns_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &req,
		sizeof(req)) < 0)
		return 0;

#if defined(IP_PKTINFO)
	oneopt = 1;
	if (setsockopt(mdns_sock, SOL_IP, IP_PKTINFO, &oneopt, 
		sizeof(oneopt)) < 0)
		return 0;
#elif defined(IP_RECVIF)
	oneopt = 1;
	if (setsockopt(mdns_sock, IPPROTO_IP, IP_RECVIF, &oneopt,
		sizeof(oneopt)) < 0)
		return 0;
#endif
#endif

	return 1;
}

static const char* aszTunnelTypes[] = { NULL, "TiVo beacon", "mDNS" };

static int check_addr_filter(const IPListEntry *pList, u_int32_t nIP,
				int nDefault)
{
	if (!pList)
		return nDefault;

	while (pList)
	{
		if ((nIP & pList->nMask) == pList->nIP)
			return 1;

		pList = pList->pNext;
	}

	return 0;
}

static void process_tunnels(int nType, struct in_addr *pSrcIP, int nSrcPort,
	u_char *pData, int nLen)
{
	if (!daemon_mode)
	{
		printf(
#ifdef CHECK_DST_ADDR
			"  "
#else
			"Received "
#endif
			"%s packet from %s\n", aszTunnelTypes[nType],
			inet_ntoa(*pSrcIP));
	}

	const TunnelListEntry *pTunnel = get_tunnel_list();
	while (pTunnel)
	{
		const TunnelListEntry *pCur = pTunnel;
		const IPListEntry *pFwd;
		pTunnel = pTunnel->pNext;

		if (nType != pCur->nType)
			continue;
		if (!check_addr_filter(pCur->pFromList, pSrcIP->s_addr, 1))
			continue;
		if (check_addr_filter(pCur->pNotFromList, pSrcIP->s_addr, 0))
			continue;

		pFwd = pCur->pFwdList;
		while (pFwd)
		{
			if (pFwd->nIP == pSrcIP->s_addr)
			{
				pFwd = pFwd->pNext;
				continue;
			}

			send_packet(pCur, pFwd, pSrcIP, nSrcPort, pData, nLen);

			if (!daemon_mode)
			{
				struct in_addr ip;
				ip.s_addr = pFwd->nIP;
				printf("  Forwarded to %s\n", inet_ntoa(ip));
			}

			pFwd = pFwd->pNext;
		}
	}
}

#ifdef CHECK_DST_ADDR
static int check_interfaces(struct in_addr *pAddr)
{
	if (!daemon_mode)
	{
		printf("Received packet on interface %s\n",
			inet_ntoa(*pAddr));
	}

	const IPListEntry *pIFList = get_interface_list();
	return check_addr_filter(pIFList, pAddr->s_addr, 1);
}
#endif

static int receive_packet(int sock, void *pBuf, int *pLen,
	struct sockaddr_in *pSrc)
{
	struct msghdr msg;
	struct iovec iov;
	struct ifreq ifr;
	struct cmsghdr *cmptr;
	struct sockaddr_in *pIFAddr;
	int sz, if_index = 0;

	union
	{
		struct cmsghdr msg;
#ifdef IP_PKTINFO
		char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#else
		char control[CMSG_SPACE(sizeof(struct sockaddr_dl))];
#endif
	} control_u;

	iov.iov_base = pBuf;
	iov.iov_len = *pLen;
	msg.msg_control = control_u.control;
	msg.msg_controllen = sizeof(control_u);
	msg.msg_flags = 0;
	msg.msg_name = pSrc;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	*pLen = sz = recvmsg(sock, &msg, 0);
	if (sz <= 0)
		return 0;

#ifdef CHECK_DST_ADDR
	if (msg.msg_controllen < sizeof(struct cmsghdr))
		return 0;

# if defined(IP_PKTINFO)
	cmptr = CMSG_FIRSTHDR(&msg);
	while (cmptr)
	{
		if (cmptr->cmsg_level == SOL_IP && cmptr->cmsg_type == IP_PKTINFO)
			if_index = ((struct in_pktinfo*)CMSG_DATA(cmptr))->ipi_ifindex;

		cmptr = CMSG_NXTHDR(&msg, cmptr);
	}
# elif defined(IP_RECVIF)
	cmptr = CMSG_FIRSTHDR(&msg);
	while (cmptr)
	{
		if (cmptr->cmsg_level == IPPROTO_IP && cmptr->cmsg_type == IP_RECVIF)
			if_index = ((struct sockaddr_dl*)CMSG_DATA(cmptr))->sdl_index;

		cmptr = CMSG_NXTHDR(&msg, cmptr);
	}
# endif

# if defined (__APPLE__) || !defined(IP_PKTINFO)
	if (!if_index || !if_indextoname(if_index, ifr.ifr_name))
		return 0;
# else
	if (!(ifr.ifr_ifindex = if_index) ||
		ioctl(sock, SIOCGIFNAME, &ifr) == -1)
		return 0;
# endif

	ifr.ifr_addr.sa_family = AF_INET;
	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
		return 0;
	
	pIFAddr = ((struct sockaddr_in*)&ifr.ifr_addr);
	if (!check_interfaces(&(pIFAddr->sin_addr)))
		return 0;
#endif

	return 1;
}

int main(int argc, char** argv)
{
	parse_options(argc, argv);

#if HAVE_WORKING_FORK
	if (daemon_mode)
		daemonize();
	else
		log_to_stderr = 1;
#endif

	raw_skt = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (raw_skt < 0)
	{
		log_message(LOG_ERR, "Can't create raw socket");
		return 1;
	}

	if (!create_listeners())
	{
		log_message(LOG_ERR, "Can't create listener socket(s)");
		return 1;
	}

	if (!drop_privs())
	{
		log_message(LOG_ERR, "Unable to drop root privileges");
		return 1;
	}

	if (!read_config_file(szCfgFile))
		return 1;

	while (run_flag)
	{
		struct sockaddr_in addr;
		unsigned char buf[3076];
		int rc;
		struct timeval tv;
		fd_set ready;

		if (reload_config)
		{
			log_message(LOG_INFO, "Reloading configuration file");
			read_config_file(szCfgFile);
			reload_config = 0;
		}

		FD_ZERO(&ready);
		FD_SET(tivo_sock, &ready);
#ifdef ENABLE_MDNS
		FD_SET(mdns_sock, &ready);
#endif
		tv.tv_sec = 0;
		tv.tv_usec = 100000;
		rc = select(FD_SETSIZE, SELECT_TYPE_ARG234 &ready, NULL, 
			NULL, SELECT_TYPE_ARG5 &tv);
		if (rc <= 0)
			continue;

		if (FD_ISSET(tivo_sock, &ready))
		{
			int len = 3076;
			if (!receive_packet(tivo_sock, buf, &len, &addr))
				continue;

			process_tunnels(TUNNEL_TIVO, &addr.sin_addr,
				ntohs(addr.sin_port), buf, len);
		}

#ifdef ENABLE_MDNS
		if (FD_ISSET(mdns_sock, &ready))
		{
			int len = 3076;
			if (!receive_packet(mdns_sock, buf, &len, &addr))
				continue;

			if (ntohs(addr.sin_port) == 5353)
			{
				process_tunnels(TUNNEL_MDNS, &addr.sin_addr,
					5353, buf, len);
			}
		}
#endif
	}

	log_message(LOG_INFO, "Shutting down...");

	cleanup_config();

	close(raw_skt);
	if (tivo_sock >= 0)
		close(tivo_sock);
	if (mdns_sock >= 0)
		close(mdns_sock);

	return 0;
}
