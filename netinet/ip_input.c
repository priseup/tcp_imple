#include "../sys/socket.h"
#include "../sys/errno.h"
#include "../sys/time.h"
#include "../sys/kernel.h"
#include "../sys/protosw.h"
#include "../sys/domain.h"
#include "../sys/mbuf.h"
#include "../sys/sysctl.h"

#include "../net/if.h"
#include "../net/route.h"

#include "in.h"
#include "in_systm.h"
#include "ip.h"
#include "in_var.h"
#include "ip_var.h"
#include "ip_icmp.h"
#include "in_pcb.h"

#ifndef	IPFORWARDING
#ifdef GATEWAY
#define	IPFORWARDING	1	/* forward IP packets not for us */
#else /* GATEWAY */
#define	IPFORWARDING	0	/* don't forward IP packets not for us */
#endif /* GATEWAY */
#endif /* IPFORWARDING */
#ifndef	IPSENDREDIRECTS
#define	IPSENDREDIRECTS	1
#endif

int	ipforwarding = IPFORWARDING;
int	ipsendredirects = IPSENDREDIRECTS;
int	ip_defttl = IPDEFTTL;
#ifdef DIAGNOSTIC
int	ipprintfs = 0;
#endif

extern  struct ipq	ipq;			/* ip reass. queue */
extern	struct domain inetdomain;
extern	struct protosw inetsw[];

u_char	ip_protox[IPPROTO_MAX];
int	ipqmaxlen = IFQ_MAXLEN;
struct	in_ifaddr *in_ifaddr;			/* first inet address */
struct	ifqueue ipintrq;
/*
 * We need to save the IP options in case a protocol wants to respond
 * to an incoming packet over the same route if the packet got here
 * using IP source routing.  This allows connection establishment and
 * maintenance when the remote end is on a network that is not known
 * to us.
 */
int	ip_nhops = 0;
static	struct ip_srcrt {
	struct	in_addr dst;			/* final destination */
	char	nop;				/* one NOP to align */
	char	srcopt[IPOPT_OFFSET + 1];	/* OPTVAL, OLEN and OFFSET */
	struct	in_addr route[MAX_IPOPTLEN/sizeof(struct in_addr)];
} ip_srcrt;

#ifndef GATEWAY
extern	int if_index;
u_long	*ip_ifmatrix;
#endif

#define RSA_SIN(ro_dst) ((struct sockaddr_in *)&ro_dst)

static void save_rte (u_char *, struct in_addr);
/*
 * IP initialization: fill in IP protocol switch table.
 * All protocols not implemented in kernel go to raw IP protocol handler.
 */
void
ip_init()
{
    struct protosw *pr = pffindproto(PF_INET, IPPROTO_RAW, SOCK_RAW);
    if (pr == NULL)
        perror("canot find the protosw\n");

    for (int i = 0; i < IPPROTO_MAX; i++)
        ip_protox[i] = pr - inetdomain.dom_protosw;

    for (struct protosw *p = inetdomain.dom_protosw;
        p < inetdomain.dom_protoswNPROTOSW; p++)
    {
        if (p->pr_protocol != IPPROTO_RAW)
            ip_protox[p->pr_protocol] = p - inetdomain.dom_protosw;
    }

    ipq.ipq_prev = ipq.ipq_next = &ipq;
    ip_id = time.tv_sec & 0xffff;
    int i = (if_index + 1) * (if_index + 1) * sizeof(u_long);
    ip_ifmatrix = malloc(i);
    memset(ip_ifmatrix, 0, i);
  
    ipintrq.ifq_maxlen = ipqmaxlen;
}

struct	sockaddr_in ipaddr = { sizeof(ipaddr), AF_INET };
struct	route ipforward_rt;

/*
 * Ip input routine.  Checksum and byte swap header.  If fragmented
 * try to reassemble.  Process options.  Pass to next level.
 */
void
ipintr()
{
    struct ip *ip;
    struct mbuf *m;
    int cksum;
    int hlen;

next:
    IF_DEQUEUE(&ipintrq, m);
    if (!m)
        goto bad;
    if (!in_ifaddr)
        goto bad;
    ip = mtod(m, struct ip*);

    if (ip->ip_v != IPVERSION)
        goto bad;
    if ((m->m_flags & M_PKTHDR) == 0)
        goto bad;

    if (m->m_len < sizeof *ip)
        m = m_pullup(m, sizeof *ip);
    if (!m)
        goto bad;

    hlen = ip->ip_hl << 2;
    if (hlen < sizeof (struct ip))
        goto bad;
    if (m->m_len < hlen)
        m = m_pullup(m, hlen);
    if (m == NULL)
        goto bad;
  
    ip->ip_sum = 0;
    ip->ip_sum = in_cksum(m, hlen);
    if (ip->ip_sum)
        goto bad;

    NTOHS(ip->ip_len);
    NTOHS(ip->ip_id);
    NTOHS(ip->ip_off);

    if (ip->ip_len > m->m_pkthdr.len)
    {
        goto bad;
    }
    else
    {
        m_adj(m, m->m_pkthdr.len - ip->ip_len);
    }

    // the source route from the previous packet is
    // discarded by clearing ip_nhops
    ip_nhops = 0;
    if (hlen > sizeof (struct ip))
    {
        if (ip_dooptions(m) != 0)
            goto next;
    }

    // match with the one of the broadcast addresses associated with
    // the receiving interface 
    struct sockaddr_in *sin = NULL;
    for (struct in_ifaddr *ia = in_ifaddr; ia; ia = ia->ia_next)
    {
        u_long src_addr = ntohl(ip->ip_dst.s_addr);
        if (ia->ia_addr.sin_addr.s_addr == src_addr)
        {
            goto ours;
        }
        if (ia->ia_broadaddr.sin_addr.s_addr == src_addr)
        {
            goto ours;
        }
        if (ia->ia_netbroadcast.s_addr == src_addr)
        {
            goto ours;
        }
        if (ia->ia_subnet = src_addr)
        {
            goto ours;
        }
        if (ia->ia_net == src_addr)
        {
            goto ours;
        }
        for (struct in_multi *im = ia->ia_multiaddrs;
            im; im = im->inm_next)
            if (im->inm_addr.s_addr == src_addr)
            {

            }
        if (INADDR_ANY == src_addr 
            || INADDR_BROADCAST == src_addr)
        {

        }
    }

    if (ipforwarding)
        ip_forward(m, 0);
    else
        goto bad;

    // reassembly and demultiplexing
    // in chapter 10

    struct protosw *pr = &inetsw[ip_protox[ip->ip_p]];
    (pr->pr_input)(m, hlen);
    goto next;

ours:
    ;  // reassembly
bad:
    m_freem(m);
    goto next;
}

/*
 * Take incoming datagram fragment and try to
 * reassemble it into whole datagram.  If a chain for
 * reassembly of this datagram already exists, then it
 * is given as fp; otherwise have to make a chain.
 */
struct ip *
ip_reass(ip, fp)
	register struct ipasfrag *ip;
	register struct ipq *fp;
{
    return NULL;
}

/*
 * Free a fragment reassembly header and all
 * associated datagrams.
 */
void
ip_freef(fp)
	struct ipq *fp;
{
}

/*
 * Put an ip fragment on a reassembly chain.
 * Like insque, but pointers in middle of structure.
 */
void
ip_enq(p, prev)
	register struct ipasfrag *p, *prev;
{
}

/*
 * To ip_enq as remque is to insque.
 */
void
ip_deq(p)
	register struct ipasfrag *p;
{
}

/*
 * IP timer processing;
 * if a timer expires on a reassembly
 * queue, discard it.
 */
void
ip_slowtimo()
{

}

/*
 * Drain off all datagram fragments.
 */
void
ip_drain()
{

}

/*
 * Do option processing on a datagram,
 * possibly discarding it if bad options are encountered,
 * or forwarding it if source-routed.
 * Returns 1 if packet has been forwarded/freed,
 * 0 if the packet should be processed further.
 */
int
ip_dooptions(m)
	struct mbuf *m;
{
    struct ip *ip = mtod(m, struct ip*);
    u_char *cp = (u_char *)(ip + 1);
    struct ip_timestamp *ipt;
    struct in_ifaddr *ia;
    int opt, optlen;
    int cnt, off;
    int type, code;
    int forward = 0;
    struct in_addr sin, dst;
    n_time ntime;

    dst = ip->ip_dst;
    cnt = (ip->ip_hl << 2) - sizeof(struct ip);

    type = ICMP_PARAMPROB;
    code = 0;

    for (; cnt > 0; cnt -= optlen, cp += optlen)
    {
        opt = cp[IPOPT_OPTVAL];
        if (opt == IPOPT_EOL)
            break;
        if (opt == IPOPT_NOP)
            optlen = 1;
        else
        {
            optlen = cp[IPOPT_OLEN];
            if (optlen < 0 || optlen > cnt)
            {
                code = &cp[IPOPT_OLEN] - (u_char*)ip;
                goto bad;
            }

            off = cp[IPOPT_OFFSET];
            switch (opt)
            {
            case IPOPT_RR:
                if (off < IPOPT_MINOFF)
                {
                    code = &cp[IPOPT_MINOFF] - (u_char*)ip;
                    goto bad;
                }

                off--;
                if (optlen - off < sizeof(struct in_addr))      // if no space remains, ignore
                {
                    continue;
                }
                
                ipaddr.sin_addr = ip->ip_dst;

                // locate outgoing interface;
                // if we're the destination, use the incoming interface(should be same)
                if ((ia = (struct in_ifaddr *)ifa_ifwithaddr((struct sockaddr *)&ipaddr)) == NULL
                     && (ia = ip_rtaddr(ipaddr.sin_addr)) == NULL)
                {
                    type = ICMP_UNREACH;
                    code = ICMP_UNREACH_HOST;
                    goto bad;
                }
                *(struct in_addr *)&cp[off] = ia->ia_addr.sin_addr;
                cp[IPOPT_OFFSET] += sizeof (struct in_addr);
                break;
            case IPOPT_TS:
                if (optlen < 5) // 时间戳的最小长度
                {
                    code = &cp[IPOPT_OLEN] - (u_char*)ip;
                    goto bad;
                }

                off--;
                ipt = (struct ip_timestamp *)&cp[off];

                if (++ipt->ipt_oflw >= 16)
                {
                    type = ICMP_PARAMPROB;
                    goto bad;
                }

                switch (ipt->ipt_flg)
                {
                case IPOPT_TS_TSONLY: // only record time
                    break;
                case IPOPT_TS_TSANDADDR: // record both time and address
                    if (ipt->ipt_ptr + sizeof (struct in_addr) + sizeof (n_time) > optlen)
                    {
                        continue;
                    }
                    ipaddr.sin_addr = dst;
                    if ((ia = ifaof_ifpforaddr(&ipaddr, m->m_pkthdr.rcvif)) == NULL)
                        continue;
                    *(struct in_addr *)&cp[ipt->ipt_ptr] = ia->ia_addr.sin_addr;
                    ipt->ipt_ptr += sizeof (struct in_addr);
                    ipt->ipt_len += sizeof(struct in_addr);
                    break;
                case IPOPT_TS_PRESPEC: // only record time for specific address
                    ipaddr.sin_addr = dst;
                    if (ifa_ifwithaddr(&ipaddr) == NULL)
                        continue;
                   
                    *(struct in_addr *)&cp[ipt->ipt_ptr] = ia->ia_addr.sin_addr;
                    ipt->ipt_ptr += sizeof (struct in_addr);
                    ipt->ipt_len += sizeof(struct in_addr);
                    break;
                default:
                    goto bad;
                }

                ntime = iptime();
                *(n_time *)&cp[ipt->ipt_ptr] = ntime;
                ipt->ipt_ptr += sizeof(ntime);
                ipt->ipt_len += sizeof(ntime);
                break;
            case IPOPT_LSRR:
            case IPOPT_SSRR:
                if (off < IPOPT_MINOFF)
                {
                    code = &cp[IPOPT_MINOFF] - (u_char*)ip;
                    goto bad;
                }

                ipaddr.sin_addr = ip->ip_dst;
                if (ifa_ifwithaddr((struct sockaddr *)&ipaddr) == NULL)
                {
                    if (opt == IPOPT_SSRR)
                    {
                        type = ICMP_UNREACH;
                        code = ICMP_UNREACH_SRCFAIL;
                        goto bad;
                    }

                    // 如果本地地址不在路由中，则上一个系统把分组发送到错误的主机了
                    // 对宽松路由来说，这不是错误，仅意味着ip必须把分组转到到目的地
                    break;
                }

                off--;
                if (ifa_ifwithaddr((struct sockaddr *)&ipaddr))
                {
                    if (optlen - off < sizeof(struct in_addr))
                    {
                        save_rte(cp, ip->ip_src);
                        break;
                    }
                }

                ipaddr.sin_addr = *(struct in_addr*)(cp + off);    // get the outgoing interface
                if (opt == IPOPT_SSRR)
                {
                    if ((ia = (struct in_ifaddr *)ifa_ifwithdstaddr((struct sockaddr *)&ipaddr)) == NULL)
                    {
                        ia = (struct in_ifaddr *)ifa_ifwithnet((struct sockaddr *)&ipaddr);
                    }
                }
                else
                {
                    ia = ip_rtaddr(ipaddr.sin_addr);
                }

                if (ia == NULL)
                {
                    type = ICMP_UNREACH;
                    code = ICMP_UNREACH_SRCFAIL;
                    goto bad;
                }

                ip->ip_dst = *(struct in_addr*)(cp + off);
                *(struct in_addr*)(cp + off) = ia->ia_addr.sin_addr;
                cp[IPOPT_OFFSET] += sizeof (struct in_addr);

                if (!IN_MULTICAST(ipaddr.sin_addr.s_addr))
                    forward = 1;
                break;
            default:
                break;
            }
        }
    }


    if (forward)
    {
        ip_forward(m, 1);
        return 1;
    }

    return 0;

bad:
    ip->ip_len -= ip->ip_hl << 2;  // icmp_error假设首部长度不包含在分组长度里
    icmp_error(m, type, code, 0, 0);
    ipstat.ips_badoptions++;

    return 1;
}

/*
 * Given address of next destination (final or next hop),
 * return internet address info of interface to be used to get there.
 */
struct in_ifaddr *
ip_rtaddr(dst)
	 struct in_addr dst;
{
    struct sockaddr_in *sin;

    sin = (struct sockaddr_in *)&ipforward_rt.ro_dst;

    if (ipforward_rt.ro_rt == NULL
        || sin->sin_addr.s_addr != dst.s_addr)
    {
        if (ipforward_rt.ro_rt != NULL)
        {
            rtfree(ipforward_rt.ro_rt);
            ipforward_rt.ro_rt = NULL;
        }
    }
    sin->sin_addr = dst;
    sin->sin_family = AF_INET;
    sin->sin_len = sizeof *sin;

    ipforward_rt.ro_dst = *(struct sockaddr *)&sin;
    rtalloc(&ipforward_rt);
  
    if (ipforward_rt.ro_rt == NULL)
        return NULL;

    return (struct in_ifaddr *)(ipforward_rt.ro_rt->rt_ifa);
}

/*
 * Save incoming source route for use in replies,
 * to be picked up later by ip_srcroute if the receiver is interested.
 */
void
save_rte(option, dst)
	u_char *option;
	struct in_addr dst;
{
    if (option[IPOPT_OLEN] > sizeof ip_srcrt - (1 + sizeof (dst)))
        return;

    ip_srcrt.dst = dst;
    memcpy(ip_srcrt.srcopt, option, option[IPOPT_OLEN]);

    ip_nhops = (option[IPOPT_OLEN] - IPOPT_OFFSET - 1) / sizeof(struct in_addr);
}

/*
 * Retrieve incoming source route for use in replies,
 * in the same form used by setsockopt.
 * The first hop is placed before the options, will be removed later.
 */
struct mbuf *
ip_srcroute()
{
    struct mbuf *m = NULL;
    struct in_addr *src, *dst;
    struct ipoption *option;

    if (ip_nhops == 0)
        return NULL;

    if ((m = m_get(0, MT_SOOPTS)) == NULL)
        return NULL;

#define OPTSIZ (sizeof (ip_srcrt.nop) + sizeof (ip_srcrt.srcopt))
    m->m_len = sizeof (struct in_addr) * (ip_nhops + 1) + OPTSIZ;

    src = &ip_srcrt.route[ip_nhops-1];
    option = mtod(m, struct ipoption *);

    option->ipopt_dst = *src--;
    
    ip_srcrt.nop = IPOPT_NOP;
    ip_srcrt.srcopt[IPOPT_OFFSET]  = IPOPT_MINOFF; // should be adjusted to MINOFF
    memcpy(option->ipopt_list, ip_srcrt.nop, OPTSIZ);

    dst = (struct in_addr*)(option->ipopt_list + OPTSIZ);
    while (src - ip_srcrt.route >= 0)
    {
        *dst++ = *src--;
    }

    *dst = ip_srcrt.dst;
    return m;
}

/*
 * Strip out IP options, at higher
 * level protocol in the kernel.
 * Second argument is buffer to which options
 * will be moved, and return value is their length.
 * XXX should be deleted; last arg currently ignored.
 */
void
ip_stripoptions(m, mopt)
	register struct mbuf *m;
	struct mbuf *mopt;
{
    ;
}

u_char inetctlerrmap[PRC_NCMDS] = {
	0,		0,		0,		0,
	0,		EMSGSIZE,	EHOSTDOWN,	EHOSTUNREACH,
	EHOSTUNREACH,	EHOSTUNREACH,	ECONNREFUSED,	ECONNREFUSED,
	EMSGSIZE,	EHOSTUNREACH,	0,		0,
	0,		0,		0,		0,
	ENOPROTOOPT
};

/*
 * Forward a packet.  If some error occurs return the sender
 * an icmp packet.  Note we can't always generate a meaningful
 * icmp message because icmp doesn't have a large enough repertoire
 * of codes and types.
 *
 * If not forwarding, just drop the packet.  This could be confusing
 * if ipforwarding was zero but some routing protocol was advancing
 * us as a gateway to somewhere.  However, we must let the routing
 * protocol deal with that.
 *
 * The srcrt parameter indicates whether the packet is being forwarded
 * via a source route.
 */
void
ip_forward(m, srcrt)
	struct mbuf *m;
	int srcrt;
{
    int type, code;
    struct ip *ip = mtod(m, struct ip*);
    struct ifnet *ifp = m->m_pkthdr.rcvif;
    if (srcrt)
        ;

    if (ifp->if_flags & IFF_BROADCAST)
        m->m_flags |= M_BCAST;

    if (in_canforward(ip->ip_src) == 0)
        return;

    HTONS(ip->ip_id);
    HTONS(ip->ip_len);
    HTONS(ip->ip_off);

    if (ip->ip_ttl <= IPTTLDEC)
    {
        type = ICMP_TIMXCEED_INTRANS;
        code = ICMP_TIMXCEED;

        icmp_error(m, type, code, 0, ifp);
        m_free(m);
    }
    
    ip->ip_ttl -= IPTTLDEC;

    if (ipforward_rt.ro_rt == NULL
        || RSA_SIN(ipforward_rt.ro_dst)->sin_addr.s_addr != ip->ip_dst.s_addr)
    {
        if (ipforward_rt.ro_rt != NULL)
        {
            rtfree(ipforward_rt.ro_rt);
            ipforward_rt.ro_rt = NULL;
        }
    }
    struct sockaddr_in sin;
    sin.sin_addr = ip->ip_dst;
    sin.sin_family = AF_INET;
    sin.sin_len = sizeof sin;
    
    ipforward_rt.ro_dst = *(struct sockaddr *)&sin;
    rtalloc(&ipforward_rt);
    if (ipforward_rt.ro_rt == NULL)
    {
        code = ICMP_UNREACH;
        icmp_error(m, type, code, 0, 0);
        m_free(m);
    }

    struct mbuf *mc = m_copy(m, 0, min(m->m_len, 64));
 
    ip_ifmatrix[ifp->if_index]++;
    ip_ifmatrix[ipforward_rt.ro_rt->rt_ifp->if_index]++;

    struct in_addr dst;
    // only routers send redirect messages and that hosts must update their
    // routing tables when receiving ICMP redirect messages
    if (m->m_pkthdr.rcvif == ipforward_rt.ro_rt->rt_ifp
        && ipforward_rt.ro_rt->rt_flags & (RTF_DYNAMIC | RTF_MODIFIED) == 0
        && RSA_SIN(ipforward_rt.ro_dst)->sin_addr.s_addr != 0
        && ipsendredirects && !srcrt)
    {
        //if the subnet mask bits of the source address and the outgoing interface's
        //address are the same, the addressed are on the same IP network
        if ((ip->ip_src.s_addr & ((struct in_ifaddr*)ipforward_rt.ro_rt->rt_ifa)->ia_subnetmask)
            == ((struct in_ifaddr*)ipforward_rt.ro_rt->rt_ifa)->ia_net)
        {
            if (ipforward_rt.ro_rt->rt_flags & RTF_GATEWAY)
                dst.s_addr = ((struct sockaddr_in *)ipforward_rt.ro_rt->rt_gateway)->sin_addr.s_addr;
            else
                dst.s_addr = RSA_SIN(ipforward_rt.ro_dst)->sin_addr.s_addr;
        }
    }

    //int	 ip_output __P((struct mbuf *,
    //    struct mbuf *, struct route *, int, struct ip_moptions *));
    int error = ip_output(m, NULL, ipforward_rt.ro_rt, IP_FORWARDING|IP_ALLOWBROADCAST, NULL);
    if (error)
    {
        ipstat.ips_cantforward++;
    }
    else
    {
        ipstat.ips_forward++;

        if (type)
            ipstat.ips_redirectsent++;
        else
        {
            if (mc)
                m_freem(mc);
            return;
        }
    }

    if (mc == NULL)
        return;

    switch (error)
    {
    case 0:
        break;
    case ENOBUFS:
        type = ICMP_SOURCEQUENCH;
        code = 0;
        break;
    case EMSGSIZE:
        code = ICMP_UNREACH;
        code = ICMP_UNREACH_NEEDFRAG;
        break;
    case ENETDOWN:
    case EHOSTDOWN:
    case ENETUNREACH:
    case EHOSTUNREACH:
        type = ICMP_UNREACH;
        code = ICMP_UNREACH_HOST;
        break;
    default:
        code = ICMP_UNREACH_HOST;
        break;
    }
    icmp_error(mc, type, code, 0, ifp);
}

int
ip_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
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
    case IPCTL_FORWARDING:
        return sysctl_int(oldp, oldlenp, newp, newlen, &ipforwarding);
    case IPCTL_SENDREDIRECTS:
        return sysctl_int(oldp, oldlenp, newp, newlen, &ipsendredirects);
    case IPCTL_DEFTTL:
        return sysctl_int(oldp, oldlenp, newp, newlen, &ip_defttl);
    default:
        return EOPNOTSUPP;
    }
}
