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

    if (IN_MULTICAST(ntohl(ip->ip_dst.s_addr))) {
        struct in_multi *inm;
        extern struct ifnet loif;

        m->m_flags |= M_MCAST;
        /*
        * IP destination address is multicast.  Make sure "dst"
        * still points to the address in "ro".  (It may have been
        * changed to point to a gateway address, above.)
        */
        dst = (struct sockaddr_in *)&ro->ro_dst;
        /*
        * See if the caller provided any multicast options
        */
        if (imo != NULL) {
            ip->ip_ttl = imo->imo_multicast_ttl;
            if (imo->imo_multicast_ifp != NULL)
                ifp = imo->imo_multicast_ifp;
        }
        else
            ip->ip_ttl = IP_DEFAULT_MULTICAST_TTL;
        /*
        * Confirm that the outgoing interface supports multicast.
        */
        if ((ifp->if_flags & IFF_MULTICAST) == 0) {
            ipstat.ips_noroute++;
            error = ENETUNREACH;
            goto bad;
        }
        /*
        * If source address not specified yet, use address
        * of outgoing interface.
        */
        if (ip->ip_src.s_addr == INADDR_ANY) {
            register struct in_ifaddr *ia;

            for (ia = in_ifaddr; ia; ia = ia->ia_next)
                if (ia->ia_ifp == ifp) {
                    ip->ip_src = IA_SIN(ia)->sin_addr;
                    break;
                }
        }

        IN_LOOKUP_MULTI(ip->ip_dst, ifp, inm);
        if (inm != NULL &&
            (imo == NULL || imo->imo_multicast_loop)) {
            /*
            * If we belong to the destination multicast group
            * on the outgoing interface, and the caller did not
            * forbid loopback, loop back a copy.
            */
            ip_mloopback(ifp, m, dst);
        }
#ifdef MROUTING
        else {
            /*
            * If we are acting as a multicast router, perform
            * multicast forwarding as if the packet had just
            * arrived on the interface to which we are about
            * to send.  The multicast forwarding function
            * recursively calls this function, using the
            * IP_FORWARDING flag to prevent infinite recursion.
            *
            * Multicasts that are looped back by ip_mloopback(),
            * above, will be forwarded by the ip_input() routine,
            * if necessary.
            */
            extern struct socket *ip_mrouter;
            if (ip_mrouter && (flags & IP_FORWARDING) == 0) {
                if (ip_mforward(m, ifp) != 0) {
                    m_freem(m);
                    goto done;
                }
            }
        }
#endif
        /*
        * Multicasts with a time-to-live of zero may be looped-
        * back, above, but must not be transmitted on a network.
        * Also, multicasts addressed to the loopback interface
        * are not sent -- the above call to ip_mloopback() will
        * loop back a copy if this host actually belongs to the
        * destination group on the loopback interface.
        */
        if (ip->ip_ttl == 0 || ifp == &loif) {
            m_freem(m);
            goto done;
        }

        goto sendit;
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
sendit:
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
        if (!(ip->ip_off & IP_DF))
        {
            m_free(m0);
            ipstat.ips_cantfrag++;
            return EMSGSIZE;
        }

        int step = (ifp->if_baudrate - ip->ip_hl << 2) & ~7;
        if (step % 8)
            return EMSGSIZE;
        {
            int mhlen = hlen + step, firstlen = 0, mnext = 0;
            struct mbuf *n = NULL;
            do
            {
                if (mhlen + step < ip->ip_len)
                    len = step;
                else
                    len = ip->ip_len - mhlen;

                struct mbuf *n = m_get(0, MT_DATA);
                if (!n)
                {
                    m = n;
                    goto sendorfree;
                }

                // 为链路层首部腾出空间
                // 如果ip_ouput不这么做，则网络接口驱动器就必须再分配一个
                // mbuf来存放链路层首部或移动数据。
                // 两种工作都很耗时，在这里预分配将其避免
                mtod(n, caddr_t) += max_linkhdr;

                memcpy(mtod(n, caddr_t), ip, sizeof *ip);
                int optlen = ip_optcopy(ip, mtod(n, struct ip*));
                
                struct ip *frag_ip = mtod(n, struct ip*);
                frag_ip->ip_hl = (sizeof (struct ip) + optlen) >> 2;
                frag_ip->ip_off = (mnext - hlen) / 8 + ip->ip_off & IP_OFFMASK; // ip可能也是一个被frag的分组
                frag_ip->ip_off &= ~IP_DF;

                if (ip->ip_off & IP_MF)
                {
                    frag_ip->ip_off &= IP_MF;
                }
                else
                {
                    if (len >= 8)
                        frag_ip->ip_off &= IP_MF;
                }

                struct mbuf *next = NULL;
                if ((next = m_copy(m0, mnext, len)) == NULL)
                {
                    m = n;
                    goto sendorfree;
                }
                n->m_next = next;

                n->m_len += sizeof(struct ip) + optlen;
                n->m_pkthdr.len = n->m_len + next->m_len;
                HTONS(frag_ip->ip_len);
                HTONS(frag_ip->ip_off);

                in_cksum(n, frag_ip->ip_hl << 2);
                n->m_pkthdr.rcvif = NULL;

                m->m_nextpkt = n;
                m = n;
            } while (mhlen < ip->ip_len);

            m = m0;
            ip->ip_len = hlen + step;
            ip->ip_off |= IP_MF;
            m_adj(m, ip->ip_len - ip->ip_len);

            HTONS(ip->ip_len);
            HTONS(ip->ip_off);
        }
    }

    if (ro == &iproute)
        RTFREE(ro->ro_rt);

sendorfree:
    if (!m)
    {
        m = m0;
        while (m)
        {
            m_freem(m);
            m = m->m_nextpkt;
        }
        return ENOBUFS;
    }
    else
    {
        m = m0;
        int err = 0;
        while (m)
        {
            if (err)
                m_freem(m);
            else
                if (ifp->if_output)
                    err = (ifp->if_output)(ifp, m, NULL, ro->ro_rt);
             
            m = m->m_nextpkt;
        }

        return 0;
    }
done:
    if (ro == &iproute && (flags & IP_ROUTETOIF) == 0 && ro->ro_rt)
        RTFREE(ro->ro_rt);
    return (error);
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
    u_char *src = (u_char *)(ip + 1);
    u_char *dst = (u_char *)(jp + 1);
    int src_len = (ip->ip_hl << 2) - sizeof *ip;
    int opt_len = 0;
   
    for (; src_len > 0; src_len -= opt_len)
    {
        int opt_type = src[IPOPT_OPTVAL];
        if (opt_type == IPOPT_EOL)
            break;
        if (opt_type == IPOPT_NOP)
        {
            opt_len += 1;
            *dst++ = *src++;
            continue;
        }
        if (IPOPT_COPIED(opt_type))
        {
            opt_len = src[IPOPT_OLEN];
            memcpy(dst, src, opt_len);
            dst += opt_len;
            src += opt_len;
        }
    }

    while ((dst - (u_char *)ip) % 4)
    {
        *dst++ = IPOPT_EOL;

    }

    return dst - (u_char *)(jp + 1);
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
        case IP_MULTICAST_IF:
        case IP_MULTICAST_TTL:
        case IP_MULTICAST_LOOP:
        case IP_ADD_MEMBERSHIP:
        case IP_DROP_MEMBERSHIP:
            error = ip_setmoptions(optname, &inp->inp_moptions, m);
            break;
        freeit:
        default:
            error = EINVAL;
            break;
            if (m)
                m_free(m);
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
        case IP_MULTICAST_IF:
        case IP_MULTICAST_TTL:
        case IP_MULTICAST_LOOP:
        case IP_ADD_MEMBERSHIP:
        case IP_DROP_MEMBERSHIP:
            error = ip_getmoptions(optname, inp->inp_moptions, mp);
            break;
        default:
            error = ENOPROTOOPT;
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
    int error = 0;
    u_char loop;
    int i;
    struct in_addr addr;
    struct ip_mreq *mreq;
    struct ifnet *ifp;
    struct ip_moptions *imo = *imop;
    struct route ro;
    struct sockaddr_in *dst;

    if (imo == NULL)
    {
        imo = (struct ip_moptions*)malloc(sizeof(*imo));
        if (imo == NULL)
            return ENOBUFS;
        *imop = imo;
        imo->imo_multicast_ifp = NULL;
        imo->imo_multicast_ttl = IP_DEFAULT_MULTICAST_TTL;
        imo->imo_multicast_loop = IP_DEFAULT_MULTICAST_LOOP;
        imo->imo_num_memberships = 0;
    }

    switch (optname)
    {
    case IP_MULTICAST_IF:
        if (m == NULL || m->m_len != sizeof (struct in_addr))
        {
            error = EINVAL;
            break;
        }
        addr = *(mtod(m, struct in_addr *));
        if (addr.s_addr == INADDR_ANY)
        {
            imo->imo_multicast_ifp = NULL;
            break;
        }
        INADDR_TO_IFP(addr, ifp);
        if (ifp == NULL
            || (ifp->if_flags & IFF_MULTICAST) == 0)
        {
            error = EADDRNOTAVAIL;
            break;
        }
        imo->imo_multicast_ifp = ifp;
        break;

    case IP_MULTICAST_TTL:
        if (m == NULL || m->m_len != 1)
        {
            error = EINVAL;
            break;
        }
        imo->imo_multicast_ttl = *(mtod(m, u_char *));
        break;
    case IP_MULTICAST_LOOP:
        if (m == NULL || m->m_len != 1
            || (loop = *(mtod(m, u_char *)) > 1))
        {
            error = EINVAL;
            break;
        }
        imo->imo_multicast_loop = loop;
        break;
    case IP_ADD_MEMBERSHIP:
        if (m == NULL 
            || m->m_len != sizeof (struct ip_mreq))
        {
            error = EINVAL;
            break;
        }
        if (mreq->imr_interface.s_addr == INADDR_ANY)
        {
            ro.ro_rt = NULL;
            dst = (struct sockaddr_in *)&ro.ro_dst;
            dst->sin_len = sizeof(*dst);
            dst->sin_family = AF_INET;
            dst->sin_addr = mreq->imr_multiaddr;
            rtalloc(&ro);
            if (ro.ro_rt == NULL)
            {
                error = EADDRNOTAVAIL;
                break;
            }
            ifp = ro.ro_rt->rt_ifp;
            rtfree(ro.ro_rt);
        }
        else
        {
            INADDR_TO_IFP(mreq->imr_interface, ifp);
        }
        if (ifp == NULL
            || (ifp->if_flags & IFF_MULTICAST) == 0)
        {
            error = EADDRNOTAVAIL;
            break;
        }
		/*
		 * See if the membership already exists or if all the
		 * membership slots are full.
		 */
		for (i = 0; i < imo->imo_num_memberships; ++i) {
			if (imo->imo_membership[i]->inm_ifp == ifp &&
			    imo->imo_membership[i]->inm_addr.s_addr
						== mreq->imr_multiaddr.s_addr)
				break;
		}
		if (i < imo->imo_num_memberships) {
			error = EADDRINUSE;
			break;
		}
		if (i == IP_MAX_MEMBERSHIPS) {
			error = ETOOMANYREFS;
			break;
		}
		/*
		 * Everything looks good; add a new record to the multicast
		 * address list for the given interface.
		 */
		if ((imo->imo_membership[i] =
		    in_addmulti(&mreq->imr_multiaddr, ifp)) == NULL) {
			error = ENOBUFS;
			break;
		}
		++imo->imo_num_memberships;
		break;

	case IP_DROP_MEMBERSHIP:
		/*
		 * Drop a multicast group membership.
		 * Group must be a valid IP multicast address.
		 */
		if (m == NULL || m->m_len != sizeof(struct ip_mreq)) {
			error = EINVAL;
			break;
		}
		mreq = mtod(m, struct ip_mreq *);
		if (!IN_MULTICAST(ntohl(mreq->imr_multiaddr.s_addr))) {
			error = EINVAL;
			break;
		}
		/*
		 * If an interface address was specified, get a pointer
		 * to its ifnet structure.
		 */
		if (mreq->imr_interface.s_addr == INADDR_ANY)
			ifp = NULL;
		else {
			INADDR_TO_IFP(mreq->imr_interface, ifp);
			if (ifp == NULL) {
				error = EADDRNOTAVAIL;
				break;
			}
		}
		/*
		 * Find the membership in the membership array.
		 */
		for (i = 0; i < imo->imo_num_memberships; ++i) {
			if ((ifp == NULL ||
			     imo->imo_membership[i]->inm_ifp == ifp) &&
			     imo->imo_membership[i]->inm_addr.s_addr ==
			     mreq->imr_multiaddr.s_addr)
				break;
		}
		if (i == imo->imo_num_memberships) {
			error = EADDRNOTAVAIL;
			break;
		}
		/*
		 * Give up the multicast address record to which the
		 * membership points.
		 */
		in_delmulti(imo->imo_membership[i]);
		/*
		 * Remove the gap in the membership array.
		 */
		for (++i; i < imo->imo_num_memberships; ++i)
			imo->imo_membership[i-1] = imo->imo_membership[i];
		--imo->imo_num_memberships;
		break;

    default:
        error = EOPNOTSUPP;
        break;
    }

    if (imo->imo_multicast_ifp == NULL
        && imo->imo_multicast_ttl == IP_DEFAULT_MULTICAST_TTL
        && imo->imo_multicast_loop == IP_DEFAULT_MULTICAST_LOOP
        && imo->imo_num_memberships == 0)
    {
        free(*imop);
        *imop = NULL;
    }
    return error;
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
        u_char *ttl;
        u_char *loop;
        struct in_addr *addr;
        struct in_ifaddr *ia;

        *mp = m_get(M_WAIT, MT_SOOPTS);

        switch (optname) {

        case IP_MULTICAST_IF:
            addr = mtod(*mp, struct in_addr *);
            (*mp)->m_len = sizeof(struct in_addr);
            if (imo == NULL || imo->imo_multicast_ifp == NULL)
                addr->s_addr = INADDR_ANY;
            else {
                IFP_TO_IA(imo->imo_multicast_ifp, ia);
                addr->s_addr = (ia == NULL) ? INADDR_ANY
                    : IA_SIN(ia)->sin_addr.s_addr;
            }
            return (0);

        case IP_MULTICAST_TTL:
            ttl = mtod(*mp, u_char *);
            (*mp)->m_len = 1;
            *ttl = (imo == NULL) ? IP_DEFAULT_MULTICAST_TTL
                : imo->imo_multicast_ttl;
            return (0);

        case IP_MULTICAST_LOOP:
            loop = mtod(*mp, u_char *);
            (*mp)->m_len = 1;
            *loop = (imo == NULL) ? IP_DEFAULT_MULTICAST_LOOP
                : imo->imo_multicast_loop;
            return (0);

        default:
            return (EOPNOTSUPP);
        }

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
    register struct ip *ip;
    struct mbuf *copym;

    copym = m_copy(m, 0, M_COPYALL);
    if (copym != NULL) {
        /*
        * We don't bother to fragment if the IP length is greater
        * than the interface's MTU.  Can this possibly matter?
        */
        ip = mtod(copym, struct ip *);
        ip->ip_len = htons((u_short)ip->ip_len);
        ip->ip_off = htons((u_short)ip->ip_off);
        ip->ip_sum = 0;
        ip->ip_sum = in_cksum(copym, ip->ip_hl << 2);
        (void)looutput(ifp, copym, (struct sockaddr *)dst, NULL);
    }
}
