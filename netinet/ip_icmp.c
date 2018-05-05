#include "../sys/param.h"
#include "../sys/systm.h"
#include "../sys/malloc.h"
#include "../sys/mbuf.h"
#include "../sys/protosw.h"
#include "../sys/socket.h"
#include "../sys/time.h"
#include "../sys/kernel.h"
#include "sys/errno.h"

#include "../net/if.h"
#include "../net/route.h"

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
    int ioplen = oip->ip_len;

    // 只给第一个数据报分片报错
    if ((oip->ip_off & IP_OFFMASK))   
    {
        m_freem(n);
        return;
    }

    if (oip->ip_p == IPPROTO_ICMP)
    { 
    }

    if (n->m_flags & (M_BCAST | M_MCAST))
    {
        // 1. to ip multicast or broadcast
        // 2. ip_src is not a single cast (zero based address
        //      loop address, broadcast, multicast, E)
    }

    struct mbuf *m = m_gethdr(0, MT_DATA);
    MH_ALIGN(m, ICMP_MINLEN + oip->ip_hl << 2 + 8);

    struct icmp *icmp = mtod(m, struct icmp*);
    icmp->icmp_type = type;
    icmp->icmp_code = code;
    icmp->icmp_gwaddr.s_addr = 0;
    icmp->icmp_pptr = 0;
    icmp->icmp_nextmtu = 3;
    m->m_len += sizeof(struct icmp);

    memcpy(icmp+1, oip->ip_hl << 2);
    m->m_len += oip->ip_hl << 2;
    
    int len = min(8, ioplen);
    memcpy(mtod(m, caddr_t) + m->m_len, mtod(n, caddr_t) + oip->ip_hl << 2);
    m->m_len += len;

    m->m_data = (caddr_t)icmp;
    m->m_data -= sizeof(struct ip);
    m->m_len += sizeof(struct ip);
    memcpy(mtod(m, caddr_t), oip, sizeof (*oip));

    struct ip *ip = mtod(m, struct ip *);
    ip->ip_len = m->m_len;
    ip->ip_hl = sizeof(*ip) >> 2;
    ip->ip_p = IPPROTO_ICMP;
    ip->ip_tos = 0;

    icmp_reflect(m);
    m_freem(n);
}

static struct sockaddr_in icmpsrc = { sizeof (struct sockaddr_in), AF_INET };
static struct sockaddr_in icmpdst = { sizeof (struct sockaddr_in), AF_INET };
static struct sockaddr_in icmpgw = { sizeof (struct sockaddr_in), AF_INET };
struct sockaddr_in icmpmask = { 8, 0 };

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
    int hlen = ip->ip_hl << 2;

    if (icmplen < ICMP_MINLEN)
    {
        icps_tooshort++;
        m_freeem(m);

        return;
    }
    if (m->m_len < sizeof (struct ip) + ICMP_MINLEN
        && !m_pullup(m, sizeof(struct ip) + ICMP_MINLEN))
    {
        m_freeem(m);
        return;
    }
    icmp = (struct icmp *)(mtod(m, caddr_t) + hlen);
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = in_cksum(icmp, icmplen);
    
    int type = icmp->icmp_type;
    int code = icmp->icmp_code;
    switch (type)
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
        if ()
    badcode:
        icmpstat.icps_badcode++;
        break;
    case ICMP_ECHO:
        icmp->icmp_type = ICMP_ECHOREPLY;
        goto reflect;
    case ICMP_TSTAMP:
        icmp->icmp_type = ICMP_TSTAMPREPLY;
        icmp->icmp_rtime = iptime();
        icmp->icmp_ttime = iptime();
        goto reflect;
    case ICMP_MASKREQ:
        if (!icmpmaskrepl)
            break;
        if (icmplen < ICMP_MASKLEN)
            break;

        if (icmp->icmp_mask == 0
            || icmp->icmp_mask == 255)
            icmpdst.sin_addr = ip->ip_src;
        struct ip a = ifaof_offoraddr();
        icmp->icmp_type = ICMP_MASKREPLY;
    case ICMP_IREQ:
        break;
    case ICMP_REDIRECT:
        if (code > 3)
            goto badcode;
        if (icmplen < ICMP_ADVLENMIN)
            break;
        icmpgw.sin_addr = ip->ip_src;
        icmpdst.sin_addr = 0;
        icmpsrc.sin_addr = ip->ip_dst;

        rnredirect();
        pfctlinput();

    case ICMP_ECHOREPLY:
    case ICMP_ROUTERADVERT:
    case ICMP_ROUTERSOLICIT:
    case ICMP_TSTAMPREPLY:
    case ICMP_IREQREPLY:
    case ICMP_MASKREPLY:
    default:
        break;

    reflect:
    ip->ip_len += hlen;
    icmpstat.icps_reflect++;
    icmpstat.icps_outhist[type];
    icmp_reflect(m);
    return;
    }

raw:
    rip_input(m);
    return;
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

    for (ia = in_ifaddr; ia; ia = ia->ia_next)
    {
        if (ia->ia_addr.sin_addr.s_addr == t.s_addr)
            break;
        if (ia->ia_broadaddr.sin_addr.s_addr == t.s_addr)
            break;
    }

    // 如果没有匹配，
    // 就选择正在接收的接口的in_ifaddr结构
    // 或者in_ifaddr中的第一个地址(如果该接口没有被配置成IP可用的)
    // m->m_pkthdr.rcvif->if_addrlist->ifa_addr
    if (!ia)
        ia = in_ifaddr;

    ip->ip_src = ia->ia_addr.sin_addr;
    ip->ip_ttl = MAXTTL;

    if (ip->ip_hl << 2 > sizeof(*ip))
    {
        int count = ip->ip_hl << 2 - sizeof(*ip);
        char *cp = (char*)(ip + 1);
        struct mbuf *srcroute = ip_srcroute();
        if (srcroute == NULL)
            srcroute = m_get(0, MT_DATA);
        int len = 0;
        for (count; count > 0; count -= len, cp += len)
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
                memcpy(mtod(srcroute, caddr_t) + srcroute->m_len,
                    cp + cp[IPOPT_OFFSET] - 1,
                    cp[IPOPT_OLEN]);
                srcroute->m_len += cp[IPOPT_OLEN];
            }
        }
    }

    icmp_send(m, srcroute);
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
