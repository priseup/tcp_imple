#include "../sys/param.h"
#include "../sys/systm.h"
#include "../sys/malloc.h"
#include "../sys/mbuf.h"
#include "../sys/protosw.h"
#include "../sys/socket.h"
#include "../sys/time.h"
#include "../sys/kernel.h"
#include "sys/errno.h"
#include "sys/types.h"

#include "../net/if.h"
#include "../net/route.h"
#include "hp300\include\endian.h"

#include "in.h"
#include "in_systm.h"
#include "in_var.h"
#include "ip.h"
#include "ip_icmp.h"
#include "icmp_var.h"

/*
 * ICMP routines: error generation, receive packet processing, and
 * routines to turnaround packets back to the originator, and
 * host table maintenance routines.
 */

int	icmpmaskrepl = 0;
#ifdef ICMPPRINTFS
int	icmpprintfs = 0;
#endif

extern	struct protosw inetsw[];

/*
 * Generate an error packet of type error
 * in response to bad packet ip.
 */
void
icmp_error(n, type, code, dest, destifp)
	struct mbuf *n;
	int type, code;
	n_long dest;
	struct ifnet *destifp;
{
    struct ip *oip = mtod(n, struct ip*);
    int oiplen = oip->ip_len;
    int icmplen = 0;

    if (type != ICMP_REDIRECT)
        icmpstat.icps_error++;

    // 只给第一个数据报分片报错
    if ((oip->ip_off & IP_OFFMASK))   
    {
        goto freeit;
    }

    if (oip->ip_p == IPPROTO_ICMP 
        && type != ICMP_REDIRECT
        && n->m_len >= oiplen + ICMP_MINLEN
        && !ICMP_INFOTYPE(((struct icmp*)((caddr_t)oip + oiplen))->icmp_type))
    {
        icmpstat.icps_oldicmp++;
        goto freeit;
    }

    /* Don't send error in response to a multicast or broadcast packet */
    if (n->m_flags & (M_BCAST | M_MCAST))
    {
        goto freeit;
    }

    struct mbuf *m = m_gethdr(0, MT_HEADER);
    if (!m)
        goto freeit;
    icmplen = oiplen + min(8, oip->ip_len);
    m->m_len = icmplen + ICMP_MINLEN;
    MH_ALIGN(m, m->m_len);

    struct icmp *icmp = mtod(m, struct icmp*);
    icmpstat.icps_outhist[type]++;
    icmp->icmp_type = type;
    if (type == ICMP_REDIRECT)
        icmp->icmp_gwaddr.s_addr = dest;
    else
    {
        icmp->icmp_void = 0;

        if (type == ICMP_PARAMPROB)
        {
            icmp->icmp_pptr = code;
            code = 0;
        }
        else if (type == ICMP_UNREACH
            && code == ICMP_UNREACH_NEEDFRAG && destifp)
        {
            icmp->icmp_nextmtu = htons(destifp->if_mtu);
        }
    }
    icmp->icmp_code = code;

    memcpy((char*)(&icmp->icmp_ip), oip, icmplen);
    struct ip *nip = &icmp->icmp_ip;
    nip->ip_len = htons((u_short)(nip->ip_len + oiplen));
    
    /*
    * Now, copy old ip header (without options)
    * in front of icmp message.
    */
    if (m->m_data - sizeof(struct ip) < m->m_pktdat)
        printf("icmp len");
    m->m_data -= sizeof(struct ip);
    m->m_len += sizeof(struct ip);
    m->m_pkthdr.len = m->m_len;
    m->m_pkthdr.rcvif = n->m_pkthdr.rcvif;
    nip = mtod(m, struct ip *);
    memcpy((caddr_t)nip, (caddr_t)oip, sizeof(struct ip));
    nip->ip_len = m->m_len;
    nip->ip_hl = sizeof(struct ip) >> 2;
    nip->ip_p = IPPROTO_ICMP;
    nip->ip_tos = 0;
    icmp_reflect(m);

freeit:
    m_freem(n);
}

static struct sockaddr_in icmpsrc = { sizeof (struct sockaddr_in), AF_INET };
static struct sockaddr_in icmpdst = { sizeof (struct sockaddr_in), AF_INET };
static struct sockaddr_in icmpgw = { sizeof (struct sockaddr_in), AF_INET };
struct sockaddr_in icmpmask = { 8, 0 };
extern u_char ip_protox[IPPROTO_MAX];

/*
 * Process a received ICMP message.
 */
void
icmp_input(m, hlen)
	register struct mbuf *m;
	int hlen;
{
    struct ip *ip = mtod(m, struct ip*);
    int icmplen = ip->ip_len;
    struct icmp *icmp = NULL;
    void(*ctlfunc) (int, struct sockaddr *, struct ip*);

    if (icmplen < ICMP_MINLEN)
    {
        icmpstat.icps_tooshort++;

        goto freeit;
    }
    int i = hlen + min(icmplen, ICMP_ADVLENMIN);
    if (m->m_len < i && !m_pullup(m, i))
    {
        icmpstat.icps_tooshort++;
        return;
    }
    icmp = (struct icmp *)(mtod(m, caddr_t) + hlen);
    if (in_cksum(icmp, icmplen))
    {
        icmpstat.icps_checksum++;
        goto freeit;
    }
    if (icmp->icmp_type > ICMP_MAXTYPE)
        goto raw;
    icmpstat.icps_inhist[icmp->icmp_type]++;
    struct in_ifaddr *a = NULL;
    int code = icmp->icmp_code;
    switch (icmp->icmp_type)
    {
    case ICMP_UNREACH:
        switch (code)
        {
        case ICMP_UNREACH_NET:
        case ICMP_UNREACH_HOST:
        case ICMP_UNREACH_PROTOCOL:
        case ICMP_UNREACH_PORT:
        case ICMP_UNREACH_SRCFAIL:
            code += PRC_UNREACH_NET;
            break;
        case ICMP_UNREACH_NEEDFRAG:
            code += PRC_MSGSIZE;
            break;
        case ICMP_UNREACH_NET_UNKNOWN:
        case ICMP_UNREACH_NET_PROHIB:
        case ICMP_UNREACH_TOSNET:
            code = PRC_REDIRECT_NET;
            break;
        case ICMP_UNREACH_HOST_UNKNOWN:
        case ICMP_UNREACH_ISOLATED:
        case ICMP_UNREACH_HOST_PROHIB:
        case ICMP_UNREACH_TOSHOST:
            code = PRC_UNREACH_HOST;
            break;
        default:
            goto badcode;
        }
        goto deliver;

    case ICMP_TIMXCEED:
        if (code > 1)
            goto badcode;
        code += PRC_TIMXCEED_INTRANS;
        goto deliver;
    case ICMP_PARAMPROB:
        if (code > 1)
            goto badcode;
        code = PRC_PARAMPROB;
        goto deliver;

    case ICMP_SOURCEQUENCH:
        if (code)
            goto badcode;
        code = PRC_QUENCH;
    deliver:
        if (icmplen < ICMP_ADVLENMIN
            || icmplen < ICMP_ADVLEN(icmp)
            || icmp->icmp_ip.ip_hl < (sizeof(struct ip) >> 2))
        {
            icmpstat.icps_badlen;
            goto freeit;
        }
        NTOHS(icmp->icmp_ip.ip_len);
        icmpsrc.sin_addr = icmp->icmp_ip.ip_dst;
        if (ctlfunc = inetsw[ip_protox[ip->ip_p]].pr_ctlinput)
            (*ctlfunc)(code, (struct sockaddr *)&icmpsrc, &icmp->icmp_ip);
        break;

    badcode:
        icmpstat.icps_badcode++;
        break;

    case ICMP_ECHO:
        icmp->icmp_type = ICMP_ECHOREPLY;
        goto reflect;
    case ICMP_TSTAMP:
        if (icmplen < ICMP_TSLEN)
        {
            icmpstat.icps_badlen++;
            break;
        }
        icmp->icmp_type = ICMP_TSTAMPREPLY;
        icmp->icmp_code = 0;
        icmp->icmp_rtime = iptime();
        icmp->icmp_ttime = iptime();
        goto reflect;
    case ICMP_MASKREQ:
        if (!icmpmaskrepl)
            break;
        if (icmplen < ICMP_MASKLEN)
            break;
        switch (ip->ip_dst.s_addr)
        {
        case INADDR_BROADCAST:
        case INADDR_ANY:
            icmpdst.sin_addr = ip->ip_src;
            break;
        default:
            icmpdst.sin_addr = ip->ip_dst;
        }

        a = (struct in_ifaddr *)ifaof_ifpforaddr((struct sockaddr *)&icmpdst, m->m_pkthdr.rcvif);
        if (a == 0)
            break;
        icmp->icmp_type = ICMP_MASKREPLY;
        icmp->icmp_mask = a->ia_sockmask.sin_addr.s_addr;

        if (ip->ip_src.s_addr = 0)
        {
            if (a->ia_ifp->if_flags & IFF_BROADCAST)
                ip->ip_src = a->ia_broadaddr.sin_addr;
            if (a->ia_ifp->if_flags & IFF_POINTOPOINT)
                ip->ip_src = a->ia_dstaddr.sin_addr;
        }
    reflect:
        ip->ip_len += hlen;
        icmpstat.icps_reflect++;
        icmpstat.icps_outhist[icmp->icmp_type]++;
        icmp_reflect(m);
        return;
    case ICMP_IREQ:
        break;
    case ICMP_REDIRECT:
        if (code > 3)
            goto badcode;
        if (icmplen < ICMP_ADVLENMIN
            || icmplen < ICMP_ADVLEN(icmp)
            || icmp->icmp_ip.ip_hl < (sizeof(struct ip) >> 2))
        {
            icmpstat.icps_badlen++;
            break;
        }
        icmpgw.sin_addr = ip->ip_src;
        icmpdst.sin_addr = icmp->icmp_gwaddr;
        icmpsrc.sin_addr = icmp->icmp_ip.ip_dst;

        rtredirect((struct sockaddr *)&icmpsrc,
            (struct sockaddr *)&icmpdst,
            (struct sockaddr *)0,
            RTF_GATEWAY | RTF_HOST,
            (struct sockaddr *)&icmpgw,
            (struct rtentry **)0);
        pfctlinput(PRC_REDIRECT_HOST, (struct sockaddr *)&icmpsrc);
        break;
    case ICMP_ECHOREPLY:
    case ICMP_ROUTERADVERT:
    case ICMP_ROUTERSOLICIT:
    case ICMP_TSTAMPREPLY:
    case ICMP_IREQREPLY:
    case ICMP_MASKREPLY:
    default:
        break;
    }

raw:
    rip_input(m);
    return;

freeit:
    m_freem(m);
}

/*
 * Reflect the ip packet back to the source
 */
void
icmp_reflect(m)
	struct mbuf *m;
{
    struct ip *ip = mtod(m, struct ip*);
    struct in_addr t = ip->ip_dst;
    ip->ip_dst = ip->ip_src;
    struct in_ifaddr *ia = NULL;
    struct mbuf *srcroute = NULL;
    int optlen = 0;
    if (!in_canforward(ip->ip_src)
        && (ntohl(ip->ip_src.s_addr) & IN_CLASSA_NET)
        != (IN_LOOPBACKNET << IN_CLASSA_NSHIFT))
    {
        m_freem(m);
        goto done;
    }

    /*
    * If the incoming packet was addressed directly to us,
    * use dst as the src for the reply.  Otherwise (broadcast
    * or anonymous), use the address which corresponds
    * to the incoming interface.
    */
    for (ia = in_ifaddr; ia; ia = ia->ia_next)
    {
        if (ia->ia_addr.sin_addr.s_addr == t.s_addr)
            break;
        if ((ia->ia_ifp->if_flags & IFF_BROADCAST) &&
            ia->ia_broadaddr.sin_addr.s_addr == t.s_addr)
            break;
    }
    icmpdst.sin_addr = t;

    // 如果没有匹配，
    // 就选择正在接收的接口的in_ifaddr结构
    // 或者in_ifaddr中的第一个地址(如果该接口没有被配置成IP可用的)
    // m->m_pkthdr.rcvif->if_addrlist->ifa_addr
    if (!ia)
        ia = (struct in_ifaddr *)ifaof_ifpforaddr(
        (struct sockaddr *)&icmpdst, m->m_pkthdr.rcvif);
    if (!ia)
        ia = in_ifaddr;

    ip->ip_src = ia->ia_addr.sin_addr;
    ip->ip_ttl = MAXTTL;

    if (ip->ip_hl << 2 > sizeof(*ip))
    {
        optlen = ip->ip_hl << 2 - sizeof(*ip);
        char *cp = (char*)(ip + 1);
        srcroute = ip_srcroute();
        if (srcroute == NULL)
        {
            srcroute = m_gethdr(0, MT_HEADER);
            mtod(srcroute, struct in_addr*)->s_addr = 0;
        }

        int len = 0;
        for (optlen; optlen > 0; optlen -= len, cp += len)
        {
            if (cp[IPOPT_OPTVAL] = IPOPT_EOL)
            {
                break;
            }
            if (cp[IPOPT_OPTVAL] = IPOPT_NOP)
            {
                len = 1;
                continue;
            }

            if (cp[IPOPT_OFFSET] < IPOPT_MINOFF)
            {
                break;
            }
            switch (cp[IPOPT_OPTVAL])
            {
            case IPOPT_RR:
            case IPOPT_TS:
            case IPOPT_SECURITY:
                len = cp[IPOPT_OLEN];
                memcpy(mtod(srcroute, caddr_t) + srcroute->m_len,
                    cp, len);
                srcroute->m_len += len;
            }
        }

        while (srcroute->m_len % 4)
        {
            *(mtod(srcroute, caddr_t) + srcroute->m_len)
                = IPOPT_EOL;
            srcroute->m_len++;
        }

        optlen = ip->ip_hl << 2 - sizeof(*ip);
        ip->ip_len -= optlen;
        ip->ip_hl = sizeof(struct ip) >> 2;
        m->m_len -= optlen;

        if (m->m_flags & M_PKTHDR)
            m->m_pkthdr.len -= optlen;

        memmove(ip + 1, ip + optlen + sizeof(struct ip), m->m_len - sizeof(struct ip));
    }

    m->m_flags &= ~(M_BCAST | M_MCAST);
    icmp_send(m, srcroute);
done:
    if (srcroute)
        m_free(srcroute);
}

/*
 * Send an icmp packet back to the ip level,
 * after supplying a checksum.
 */
void
icmp_send(m, opts)
	register struct mbuf *m;
	struct mbuf *opts;
{
    struct ip *ip = mtod(m, struct ip*);
    int hlen = ip->ip_hl << 2;
    m->m_data += hlen;
    m->m_len -= hlen;
    struct icmp *icmp = mtod(m, struct icmp*);
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = in_cksum(m, m->m_len);
    m->m_data -= hlen;
    m->m_len += hlen;

    ip_output(m, opts, NULL, 0, NULL);
}

n_time
iptime()
{
    struct timeval atv;
    u_long t;

    atv.tv_sec = 0;
    atv.tv_usec = 4567000;
//    microtime(&atv);
    t = (atv.tv_sec % (24 * 60 * 60)) * 1000 + atv.tv_usec / 1000;
    return (htonl(t));
}

int
icmp_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
{
    if (namelen != 1)
        return ENOTDIR;

    switch (name[0])
    {
    case ICMPCTL_MASKREPL:
        return sysctl_int(oldp, oldlenp, newp, newlen, icmpmaskrepl);
    default:
        return EPFNOSUPPORT;
    }
    return EPFNOSUPPORT;
}
