#include "if.h"
#include "if_types.h"
#include "..\sys\errno.h"
#include "..\sys\mbuf.h"
#include "..\sys\sockio.h"
#include "bpf.h"
#include "route.h"
#include "netisr.h"
#include <stddef.h>
#include <stdio.h>

#define LOMTU 1536

struct ifnet loif;

int loioctl(struct ifnet *ifp, int, caddr_t);

void loopattach(int n)
{
    struct ifnet *ifp = &loif;

	ifp->if_next = NULL;
	ifp->if_name = "lo";
    ifp->if_flags = IFF_MULTICAST | IFF_LOOPBACK;
    ifp->if_type = IFT_LOOP;
    ifp->if_mtu = LOMTU;
    ifp->if_metric = 0;

    ifp->if_output = looutput;
    ifp->if_ioctl = loioctl;

    if_attach(ifp);
}

int loioctl(struct ifnet *ifp, int cmd, caddr_t data)
{
    struct ifaddr *ifa;
    struct ifreq *ifr;
    int error = 0;
    
    switch (cmd)
    {
    case SIOCSIFADDR:
        ifp->if_flags |= IFF_UP;
        ifa = (struct ifaddr *)data;

        // everything else is done at a higher level.
        break;
    default:
        error = EINVAL;
        break;
    }
    return error;
}

int looutput(struct ifnet *ifp,
	struct mbuf *m,
	struct sockaddr *dst,
	struct rtentry *rt)
{
    extern struct timeval time;
    extern struct ifqueue ipintrq;

    int isr;
    struct ifqueue *ifq = NULL;

    if ((m->m_flags & M_PKTHDR) == 0)
        perror("looutput no HDR");
        //panic("looutput no HDR");

    ifp->if_lastchange = time;
    if (loif.if_bpf)
    {
        struct mbuf m0;
        u_int af = dst->sa_family;

        m0.m_next = m;
        m0.m_len = 4;
        m0.m_data = (char*)&af;

        bpf_mtap(loif.if_bpf, &m0);
    }
    m->m_pkthdr.rcvif = ifp;

    if (rt && rt->rt_flags & (RTF_REJECT | RTF_BLACKHOLE))
    {
        m_freem(m);
        return (rt->rt_flags & RTF_BLACKHOLE ? 0 : 
                rt->rt_flags & RTF_HOST ? EHOSTUNREACH : ENETUNREACH);
    }
    ifp->if_opackets++;
    ifp->if_obytes += m->m_pkthdr.len;
    switch (dst->sa_family)
    {
    case AF_INET:
        ifq = &ipintrq;
        isr = NETISR_IP;
        break;
    //case AF_ISO:
    //    ifq = &clnlintrq;
    //    isr = NETISR_ISO;
    //    break;

    default:
        printf("lo%d: can't handle af%d\n", ifp->if_unit, dst->sa_family);
        m_freem(m);
        return EAFNOSUPPORT;
    }

    if (IF_QFULL(ifq))
    {
        IF_DROP(ifq);
        m_freem(m);

        return (ENOBUFS);
    }
    IF_ENQUEUE(ifq, m);

    ifp->if_ipackets++;
    ifp->if_ibytes += m->m_pkthdr.len;

	return 0;
}

/* ARGSUSED */
void
lortrequest(cmd, rt, sa)
	int cmd;
	struct rtentry *rt;
	struct sockaddr *sa;
{
}
