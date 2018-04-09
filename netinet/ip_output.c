#include "../sys/param.h"
#include "../sys/malloc.h"
#include "../sys/mbuf.h"
#include "../sys/errno.h"
#include "../sys/protosw.h"
#include "../sys/socket.h"
#include "../sys/socketvar.h"

#include "../net/if.h"
#include "../net/route.h"

#include "in.h"
#include "in_systm.h"
#include "ip.h"
#include "in_pcb.h"
#include "in_var.h"
#include "ip_var.h"

#ifdef vax
#include <machine/mtpr.h>
#endif

static struct mbuf *ip_insertoptions(struct mbuf *, struct mbuf *, int *);
static void ip_mloopback
	(struct ifnet *, struct mbuf *, struct sockaddr_in *);

/*
 * IP output.  The packet in mbuf chain m contains a skeletal IP
 * header (with len, off, ttl, proto, tos, src, dst).
 * The mbuf chain containing the packet will be freed.
 * The mbuf opt, if present, will not be freed.
 */
int
ip_output(m0, opt, ro, flags, imo)
	struct mbuf *m0;
	struct mbuf *opt;
	struct route *ro;
	int flags;
	struct ip_moptions *imo;
{
    struct ip *ip, *mhip;
    struct mbuf *m = m0;
    int hlen = sizeof(struct ip);
    int len, off, error = 0;

    if (opt)
    {
        m0 = ip_insertoptions(m0, opt, &hlen);
    }

    ip = mtod(m0, struct ip*);

    if ((flags & (IP_FORWARDING | IP_RAWOUTPUT)) == 0)
    {
        ip->ip_v = IPVERSION;
        ip->ip_off = IP_DF;
        ip->ip_id = ip_id++;
        ip->ip_hl = hlen >> 2;
    }
    else 
        hlen = ip->ip_hl << 2;

    struct route iproute;
#define SATOSIN(sa) ((struct sockaddr_in *)(sa))
#define SINTOSA(sin) ((struct sockaddr_in *)(sin))
    if (ro == NULL
        || SATOSIN(&ro->ro_dst)->sin_addr.s_addr != ip->ip_dst.s_addr)
    {
        if (ro != NULL)
            RTFREE(ro->ro_rt);
    }
   
    struct sockaddr_in *dst = SATOSIN(&ro->ro_dst);

    dst->sin_addr = ip->ip_dst;
    dst->sin_family = AF_INET;
    dst->sin_len = sizeof dst;

    struct ifnet  *ifp = NULL;
    struct ifaddr *ia = NULL;
    struct in_ifaddr *ifa = NULL;
#define IFATOINA(ifa) ((struct in_ifaddr *)(ifa))
    if (flags & IP_ROUTETOIF)
    {
        if ((ifa = IFATOINA(ifa_ifwithdstaddr(SINTOSA(&dst))) == NULL
            && (ifa = IFATOINA(ifa_ifwithnet(SINTOSA(&dst)))) == NULL))
            return ENETUNREACH;
        else
            ifp = ifa->ia_ifa.ifa_ifp;
    }
    else
    {
        if (ro == NULL)
            ro = &iproute;
        ro->ro_dst = *(struct sockaddr *)dst;
        rtalloc(ro);

        if (ro->ro_rt == NULL)
            return EHOSTUNREACH;

        ia = ro->ro_rt->rt_ifa;
        ifp = ro->ro_rt->rt_ifp;

        // 下一跳不是分组的最终目的地
        if (IFATOINA(ia)->ia_addr.sin_addr.s_addr != ip->ip_dst.s_addr)
        {
            dst->sin_addr = IFATOINA(ia)->ia_addr.sin_addr;
        }
    }

    if (ip->ip_src.s_addr == 0)
        ip->ip_src = SATOSIN(ia->ifa_dstaddr)->sin_addr;
// or     ip->ip_src = IFATOINA(ia)->ia_addr.sin_addr;

    if (in_broadcast(ip->ip_dst, ifp))
    {
        ifp->if_flags |= IFF_BROADCAST;
    }
    else
        m0->m_flags |= ~M_BCAST;

    if (m0->m_pkthdr.len > ifp->if_baudrate)
        return EMSGSIZE;
    if (dst->sin_addr.s_addr == 0)
        return EADDRNOTAVAIL;

    m0->m_flags |= M_BCAST;
    if (m0->m_pkthdr.len < ifp->if_baudrate)
    {
        HTONS(ip->ip_len);
        HTONS(ip->ip_off);

        in_cksum(m0, hlen);
        if (ifp->if_output)
            (ifp->if_output)(ifp, m0, NULL, ro->ro_rt);
    }
    else
    {
        // 断开分组
    }

    if (ro == &iproute)
        RTFREE(ro->ro_rt);

bad:
    m_free(m0);
    return 0;
}

/*
 * Insert IP options into preformed packet.
 * Adjust IP destination as required for IP source routing,
 * as indicated by a non-zero in_addr at the start of the options.
 */
static struct mbuf *
ip_insertoptions(m, opt, phlen)
	register struct mbuf *m;
	struct mbuf *opt;
	int *phlen;
{
    struct ip *ip = mtod(m, struct ip*);
    struct ipoption *option = mtod(opt, struct option*);
    *phlen = ip->ip_hl << 2;
    int optlen = option->ipopt_list[IPOPT_OLEN];
    if (m->m_len + optlen > IP_MAXPACKET)
        return m;

    if (option->ipopt_dst.s_addr == 0)
        return m;

    ip->ip_dst = option->ipopt_dst;

    struct mbuf *n = NULL;
    if (m->m_flags == M_EXT
        || (m->m_pktdat + MHLEN - (m->m_data + m->m_len)) < optlen)
    {
        n = m_gethdr(0, MT_HEADER);

        n->m_len = 0;
        n->m_pkthdr = m->m_pkthdr;
        n->m_data += 8;
        n->m_data += max_linkhdr;

        memcpy(mtod(n, caddr_t), mtod(m, caddr_t), *phlen);

        m->m_data += *phlen;
        m->m_len -= *phlen;
        n->m_len += *phlen;

        n->m_next = m;
        m = n;
    }
    else
    {
        memmove(mtod(m, caddr_t) - optlen, mtod(m, caddr_t), *phlen);
        m->m_data -= optlen;
    }

    memcpy(mtod(m, caddr_t) + *phlen, option->ipopt_list, optlen);
    m->m_len += optlen;

    m->m_pkthdr.len += optlen;
    m->m_len += optlen;

    *phlen += optlen;
    mtod(m, struct ip*)->ip_len += optlen;
   
    return m;
}

/*
 * Copy options from ip to jp,
 * omitting those not copied during fragmentation.
 */
int
ip_optcopy(ip, jp)
	struct ip *ip, *jp;
{
    return 0;
}

/*
 * IP socket option processing.
 */
int
ip_ctloutput(op, so, level, optname, mp)
	int op;
	struct socket *so;
	int level, optname;
	struct mbuf **mp;
{
    struct inpcb *inp = sotoinpcb(so);
    struct mbuf *m = *mp;
    int optval;
    int error = 0;

    if (level != IPPROTO_IP)
    {
        if (mp && *mp)
            m_free(*mp);

        return error;
    }

    switch (op)
    {
    case PRCO_SETOPT:
        switch (optname)
        {
        case IP_OPTIONS:
            return ip_pcbopts(&inp->inp_options, m);
        case IP_TOS:
        case IP_TTL:
        case IP_RECVOPTS:
        case IP_RECVRETOPTS:
        case IP_RECVDSTADDR:
            if (m->m_len != sizeof(int))
            {
                error = EINVAL;
            }
            else
            {
                optval = *mtod(m, int*);
                switch (optname)
                {
                case IP_TOS:
                    inp->inp_ip.ip_tos = optval;
                    break;
                case IP_TTL:
                    inp->inp_ip.ip_ttl = optval;
                    break;

#define OPTSET(bit) \
if (optval)   \
    inp->inp_flags |= bit;    \
else    \
    inp->inp_flags &= ~bit;

                case IP_RECVOPTS:
                    OPTSET(INP_RECVOPTS);
                    break;
                case IP_RECVRETOPTS:
                    OPTSET(INP_RECVRETOPTS);
                    break;
                case IP_RECVDSTADDR:
                    OPTSET(INP_RECVDSTADDR);
                    break;
                }
            }
        default:
            m_free(m);
            error = EINVAL;
            break;
        }
        break;
    case PRCO_GETOPT:
        if (!(*mp = m = m_get(0, MT_SOOPTS)))
        {
            error = ENOBUFS;
            break;
        }
        m->m_len = sizeof(int);
        switch (optname)
        {
        case IP_OPTIONS:
        {
            if (inp->inp_options)
            {
                memcpy(mtod(m, caddr_t), mtod(inp->inp_options, caddr_t), inp->inp_options->m_len);
                m->m_len = inp->inp_options->m_len;
            }
            else
            {
                m->m_len = 0;
            }
            break;
        }
        case IP_TOS:
            *mtod(m, int*) = inp->inp_ip.ip_tos;
            break;
        case IP_TTL:
            *mtod(m, int*) = inp->inp_ip.ip_ttl;
            break;

#define OPTBIT(bit) (inp->inp_flags & bit ? 1 : 0)
        case IP_RECVOPTS:
            *mtod(m, int*) = OPTBIT(INP_RECVOPTS);
            break;
        case IP_RECVRETOPTS:
            *mtod(m, int*) = OPTBIT(INP_RECVRETOPTS);
            break;
        case IP_RECVDSTADDR:
            *mtod(m, int*) = OPTBIT(INP_RECVDSTADDR);
            break;
        }
        break;
    default:
        m_free(m);
        error = EINVAL;
        break;
    }

    return error;
}

/*
 * Set up IP options in pcb for insertion in output packets.
 * Store in mbuf with pointer in pcbopt, adding pseudo-option
 * with destination address if source routed.
 */
int
#ifdef notyet
ip_pcbopts(optname, pcbopt, m)
	int optname;
#else
ip_pcbopts(pcbopt, m)
#endif
	struct mbuf **pcbopt;
	register struct mbuf *m;
{
    if (!pcbopt)
        return 0;
    m_free(*pcbopt);

    if (m == NULL)
        return 0;
    if (m->m_len == 0)
        return 0;

    if (m->m_len % 4 != 0)
        goto bad;

    int cnt = m->m_len;
    memmove(m->m_data + sizeof (struct in_addr), m->m_data, m->m_len);
    m->m_len += sizeof(struct in_addr);
    mtod(m, struct in_addr*)->s_addr = 0;

    u_char *cp = mtod(m, caddr_t) + sizeof (struct in_addr);
    int optlen = 0;
    int off = 0;
    for (; cnt > 0; cnt -= optlen, cp += optlen)
    {
        switch (cp[IPOPT_OPTVAL])
        {
        case IPOPT_EOL:
            break;
        case IPOPT_NOP:
            optlen = 1;
            break;
        case IPOPT_LSRR:
        case IPOPT_SSRR:
            optlen = cp[IPOPT_OLEN];
            off = cp[IPOPT_OFFSET];
            off--;

            m->m_len -= 4;
            cp[IPOPT_OLEN] -= 4;
            optlen -= 4;

            memcpy(mtod(m, caddr_t), cp+off, sizeof (struct in_addr));
            memmove(cp + off, cp + off + sizeof(struct in_addr), optlen - off - 1);
            break;
        default:
            optlen = cp[IPOPT_OLEN];
            if (optlen > cnt)
                goto bad;
        }
    }

    if (m->m_len > MAX_IPOPTLEN + 4)
        goto bad;

    *pcbopt = m;

    return 0;

bad:
    m_free(m);
    return EINVAL;
}

/*
 * Set the IP multicast options in response to user setsockopt().
 */
int
ip_setmoptions(optname, imop, m)
	int optname;
	struct ip_moptions **imop;
	struct mbuf *m;
{
    return 0;
}

/*
 * Return the IP multicast options in response to user getsockopt().
 */
int
ip_getmoptions(optname, imo, mp)
	int optname;
	register struct ip_moptions *imo;
	register struct mbuf **mp;
{
    return 0;
}

/*
 * Discard the IP multicast options.
 */
void
ip_freemoptions(imo)
	register struct ip_moptions *imo;
{
    return 0;
}

/*
 * Routine called from ip_output() to loop back a copy of an IP multicast
 * packet to the input queue of a specified interface.  Note that this
 * calls the output routine of the loopback "driver", but with an interface
 * pointer that might NOT be &loif -- easier than replicating that code here.
 */
static void
ip_mloopback(ifp, m, dst)
	struct ifnet *ifp;
	register struct mbuf *m;
	register struct sockaddr_in *dst;
{
    return 0;
}
