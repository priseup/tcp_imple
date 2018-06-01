#include <stdlib.h>
#include <string.h>
#include "../sys/types.h"
#include "../sys/errno.h"
#include "../netinet/if_ether.h"
#include "if.h"
#include "if_dl.h"
#include "route.h"
#include "if_types.h"
#include "../sys/time.h"
#include "../sys/socket.h"
#include "../hp300/include/endian.h"
#include "../sys/mbuf.h"

extern struct ifqueue pkintrq;

u_char	etherbroadcastaddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
extern	struct ifnet loif;
#define senderr(e) { error = (e); goto bad;}

u_char	ether_ipmulticast_min[6] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x00};
u_char	ether_ipmulticast_max[6] = {0x01, 0x00, 0x5e, 0x7f, 0xff, 0xff};
/*
 * Ethernet output routine.
 * Encapsulate a packet of type family for the local net.
 * Use trailer local net encapsulation if enough data in first
 * packet leaves a multiple of 512 bytes of data in remainder.
 * Assumes that ifp is actually pointer to arpcom structure.
 */
int
ether_output(ifp, m0, dst, rt0)
	register struct ifnet *ifp;
	struct mbuf *m0;
	struct sockaddr *dst;
	struct rtentry *rt0;
{
    short type;
    int error = 0;
    u_char edst[6];
    struct mbuf *m = m0;
    struct rtentry *rt;
    struct mbuf *mcopy = (struct mbuf *)0;
    struct ether_header *eh;
    int len = m->m_pkthdr.len;
    struct arpcom *ac = (struct arpcom *)ifp;

    if (!(ifp->if_flags & IFF_UP))
        return ENETDOWN;

    extern struct timeval time;
 //   struct ifqueue *ifq = NULL;
 //   extern struct ifqueue ipintrq;

    ifp->if_lastchange = time;

    if (rt = rt0)
    {
        if ((rt->rt_flags & RTF_UP) == 0)
        {
            if (rt0 = rt = rtalloc1(dst, 1))
                rt->rt_refcnt--;
            else
                senderr(EHOSTUNREACH);
        }
        if (rt->rt_flags & RTF_GATEWAY)
        {
            if (rt->rt_gwroute == 0)
                goto lookup;
            if (((rt = rt->rt_gwroute)->rt_flags & RTF_UP) == 0)
            {
                rtfree(rt);
                rt = rt0;
lookup:
                rt->rt_gwroute = rtalloc1(rt->rt_gateway, 1);
                if ((rt = rt->rt_gwroute) == 0)
                    senderr(EHOSTUNREACH);
            }
        }
        if (rt->rt_flags & RTF_REJECT)
            if (rt->rt_rmx.rmx_expire == 0
                || time.tv_sec < rt->rt_rmx.rmx_expire)
                senderr(rt == rt0 ? EHOSTDOWN : EHOSTUNREACH);
    }

    switch (dst->sa_family)
    {
    case AF_INET:
        if (!arpresolve(ac, rt, m, dst, edst))
            return 0;
        if ((ifp->if_flags & IFF_SIMPLEX) && (m0->m_flags & IFF_BROADCAST))
            mcopy = m_copy(m0, 0, len);

        type = ETHERTYPE_IP;

        break;
    case AF_ISO:
        break;
    case AF_UNSPEC:
        eh = (struct ether_header *)dst->sa_data;
        memcpy(edst, eh->ether_dhost, sizeof (edst));

        type = eh->ether_type;

        break;
    default:
        senderr(EAFNOSUPPORT);
        break;
    }

    if (mcopy)
        looutput(ifp, mcopy, dst, rt);

    M_PREPEND(m, sizeof (struct ether_header), M_DONTWAIT);
    if (m == NULL)
        senderr(ENOBUFS); // should be an error code

    eh = mtod(m, struct ether_header*);

    eh->ether_type = HTONS(type);
    memcpy(eh->ether_dhost, edst, sizeof (edst));
    memcpy(eh->ether_shost, ac->ac_enaddr, sizeof (ac->ac_enaddr));

    if (IF_QFULL(&ifp->if_snd))
    {
        IF_DROP(&ifp->if_snd);
        senderr(ENOBUFS);
    }
    IF_ENQUEUE(&ifp->if_snd, m0);

    if ((ifp->if_flags & IFF_OACTIVE) == 0)
    {
        if (ifp->if_start)
            (ifp->if_start)(ifp);
    }

    ifp->if_obytes = len + sizeof(struct ether_header);
    if (m->m_flags & M_MCAST)
        ifp->if_omcasts++;

bad:
    if (m)
        m_freem(m);
    return error;
}

/*
 * Process a received Ethernet packet;
 * the packet is in the mbuf chain m without
 * the ether header, which is provided separately.
 */
void
ether_input(ifp, eh, m)
	struct ifnet *ifp;
	register struct ether_header *eh;
	struct mbuf *m;
{
    struct timeval time;
    struct ifqueue *ifq = NULL;
    extern struct ifqueue ipintrq;
    struct arpcom *ac = (struct arpcom*)ifp;
    
    // cannot do it in global area;;;?????
    ipintrq.ifq_maxlen = IFQ_MAXLEN;

    if ((ifp->if_flags & IFF_UP) == 0)
    {
        m_freem(m);
        return ;
    }

    time.tv_sec = time.tv_usec = 0;
    ifp->if_ibytes += m->m_pkthdr.len + 14;

    ifp->if_lastchange = time;

    if (memcmp(eh->ether_dhost, etherbroadcastaddr, sizeof(etherbroadcastaddr)) == 0)
        m->m_flags |= M_BCAST;
    else if (eh->ether_dhost[0] & 0x1)
        m->m_flags |= M_MCAST;

    switch (htons(eh->ether_type))
    {
    case ETHERTYPE_IP:
        ifq = &ipintrq;
        break;
    case ETHERTYPE_ARP:
        ifq = &arpintrq;
        break;
    default:
        if (eh->ether_type > ETHERMTU)  // not process the ether_type or 802.3
            m_freem(m);                        /*if (eh->ether_type < 65535)*/
        return;
    }

    if (IF_QFULL(ifq))
    {
        IF_DROP(ifq);
        m_freem(m);
    }
    else
    {
        IF_ENQUEUE(ifq, m);
    }
}

/*
 * Convert Ethernet address to printable (loggable) representation.
 */
static char digits[] = "0123456789abcdef";
char *
ether_sprintf(ap)
	register u_char *ap;
{
    return NULL;
}

/*
 * Perform common duties while attaching to interface list
 */
void
ether_ifattach(struct ifnet *ifp)
{
    struct ifaddr *ifa = NULL;

    ifp->if_type = IFT_ETHER;
    ifp->if_addrlen = 6;
    ifp->if_hdrlen = 14;
    ifp->if_mtu = ETHERMTU;

    for (ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
    {
        struct sockaddr_dl *dl = (struct sockaddr_dl *)(ifa->ifa_addr);
        dl->sdl_alen = ifp->if_addrlen;

        memcpy(LLADDR(dl), ((struct arpcom*)ifp)->ac_enaddr, sizeof(((struct arpcom*)ifp)->ac_enaddr));
    }
}

/*
 * Add an Ethernet multicast address or range of addresses to the list for a
 * given interface.
 */
int
ether_addmulti(ifr, ac)
	struct ifreq *ifr;
	register struct arpcom *ac;
{
        register struct ether_multi *enm;
        struct sockaddr_in *sin;
        u_char addrlo[6];
        u_char addrhi[6];

        switch (ifr->ifr_addr.sa_family) {

        case AF_UNSPEC:
            memcpy(addrlo, ifr->ifr_addr.sa_data, 6);
            memcpy(addrhi, addrlo, 6);
            break;

#ifndef INET
        case AF_INET:
            sin = (struct sockaddr_in *)&(ifr->ifr_addr);
            if (sin->sin_addr.s_addr == INADDR_ANY) {
                /*
                * An IP address of INADDR_ANY means listen to all
                * of the Ethernet multicast addresses used for IP.
                * (This is for the sake of IP multicast routers.)
                */
                memcpy(addrlo, ether_ipmulticast_min, 6);
                memcpy(addrhi, ether_ipmulticast_max, 6);
            }
            else {
                ETHER_MAP_IP_MULTICAST(&sin->sin_addr, addrlo);
                memcpy(addrhi, addrlo, 6);
            }
            break;
#endif

        default:
            return (EAFNOSUPPORT);
        }

        /*
        * Verify that we have valid Ethernet multicast addresses.
        */
        if ((addrlo[0] & 0x01) != 1 || (addrhi[0] & 0x01) != 1) {
            return (EINVAL);
        }
        /*
        * See if the address range is already in the list.
        */
        ETHER_LOOKUP_MULTI(addrlo, addrhi, ac, enm);
        if (enm != NULL) {
            /*
            * Found it; just increment the reference count.
            */
            ++enm->enm_refcount;
            return (0);
        }
        /*
        * New address or range; malloc a new multicast record
        * and link it into the interface's multicast list.
        */
        enm = (struct ether_multi *)malloc(sizeof(*enm));
        if (enm == NULL) {
            return (ENOBUFS);
        }
        memcpy(enm->enm_addrlo, addrlo, 6);
        memcpy(enm->enm_addrhi, addrhi, 6);
        enm->enm_ac = ac;
        enm->enm_refcount = 1;
        enm->enm_next = ac->ac_multiaddrs;
        ac->ac_multiaddrs = enm;
        ac->ac_multicnt++;
        /*
        * Return ENETRESET to inform the driver that the list has changed
        * and its reception filter should be adjusted accordingly.
        */
        return (ENETRESET);

}

/*
 * Delete a multicast address record.
 */
int
ether_delmulti(ifr, ac)
	struct ifreq *ifr;
	register struct arpcom *ac;
{
        register struct ether_multi *enm;
        register struct ether_multi **p;
        struct sockaddr_in *sin;
        u_char addrlo[6];
        u_char addrhi[6];

        switch (ifr->ifr_addr.sa_family) {

        case AF_UNSPEC:
            memcpy(addrlo, ifr->ifr_addr.sa_data, 6);
            memcpy(addrhi, addrlo, 6);
            break;

#ifndef INET
        case AF_INET:
            sin = (struct sockaddr_in *)&(ifr->ifr_addr);
            if (sin->sin_addr.s_addr == INADDR_ANY) {
                /*
                * An IP address of INADDR_ANY means stop listening
                * to the range of Ethernet multicast addresses used
                * for IP.
                */
                memcpy(addrlo, ether_ipmulticast_min, 6);
                memcpy(addrhi, ether_ipmulticast_max, 6);
            }
            else {
                ETHER_MAP_IP_MULTICAST(&sin->sin_addr, addrlo);
                memcpy(addrhi, addrlo, 6);
            }
            break;
#endif

        default:
            return (EAFNOSUPPORT);
        }

        /*
        * Look up the address in our list.
        */
        ETHER_LOOKUP_MULTI(addrlo, addrhi, ac, enm);
        if (enm == NULL) {
            return (ENXIO);
        }
        if (--enm->enm_refcount != 0) {
            /*
            * Still some claims to this record.
            */
            return (0);
        }
        /*
        * No remaining claims to this record; unlink and free it.
        */
        for (p = &enm->enm_ac->ac_multiaddrs;
            *p != enm;
            p = &(*p)->enm_next)
            continue;
        *p = (*p)->enm_next;
        free(enm);
        ac->ac_multicnt--;
        /*
        * Return ENETRESET to inform the driver that the list has changed
        * and its reception filter should be adjusted accordingly.
        */
        return (ENETRESET);

}
