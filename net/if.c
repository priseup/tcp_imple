#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "if.h"
#include "radix.h"
#include "if_types.h"
#include "if_dl.h"
#include "..\sys\mbuf.h"
#include "..\sys\socketvar.h"
#include "..\sys\protosw.h"
#include "..\sys\sockio.h"
#include "route.h"

// global variables
int if_index = 0;
struct	ifnet	*ifnet;
int ifqmaxlen = IFQ_MAXLEN;
struct ifaddr **ifnet_addrs;

int ifconf(int cmd, caddr_t data)
{
    extern struct ifnet *ifnet;

    struct ifconf *ifc = (struct ifconf *)data;
    struct ifnet *ifp = ifnet;
    struct ifaddr *ifa = NULL;
    char *ep;
    struct ifreq ifr, *ifrp;
    int space = ifc->ifc_len, error = 0;
    ifrp = ifc->ifc_req;
    ep = ifr.ifr_name + sizeof(ifr.ifr_name) - 2;

    for (ifa = ifp->if_addrlist; space > sizeof(ifr) && ifp; ifp = ifp->if_next)
    {
        strncpy(ifr.ifr_name, ifp->if_name, IFNAMSIZ - 1);
        sprintf(ifr.ifr_name+strlen(ifr.ifr_name), "%d", ifp->if_unit);

        if (ifa == NULL)
        {
            memset(&ifr.ifr_addr, 0, sizeof(ifr.ifr_addr));
            *ifrp = ifr;
           
            space -= sizeof(ifr);
            ifrp++;
        }
        else
        {  
            for (; space > sizeof(ifr) && ifa; ifa = ifa->ifa_next)
            {     
                if (ifa->ifa_addr->sa_len <= sizeof(*ifa->ifa_addr))
                {
                    ifr.ifr_addr = *ifa->ifa_addr;
                    *ifrp = ifr;

                    space -= sizeof(ifr);
                    ifrp++;
                }
                else
                {
                    memcpy(ifrp->ifr_name, ifr.ifr_name, IFNAMSIZ);
                    space -= IFNAMSIZ;
                 
                    memcpy(&ifrp->ifr_addr, ifa->ifa_addr, ifa->ifa_addr->sa_len);
                    space -= ifr.ifr_addr.sa_len;
                
                    ifrp = (struct ifreq*)((char*)ifrp + IFNAMSIZ + ifr.ifr_addr.sa_len);
                }
            }
        }
    }

	return 0;
}

void if_down(struct ifnet *ifp)
{
    struct ifaddr *ifa = NULL;
   
    ifp->if_flags &= ~IFF_UP;
    for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
    {
        pfctlinput(PRC_IFDOWN, ifa);
    }

    if_qflush(&ifp->if_snd);
    rt_ifmsg(ifp);
}

void if_up(struct ifnet *ifp)
{
    struct ifaddr *ifa = NULL;

    ifp->if_flags |= IFF_UP;

    rt_ifmsg(ifp);
}

/*
 * Map interface name to
 * interface structure pointer.
 */
struct ifnet *
ifunit(name)
	register char *name;
{
    char ifname[16] = "";
    extern struct ifnet *ifnet;
    struct ifnet *ifp = ifnet;

    while (ifp)
    {
        strcpy(ifname, ifp->if_name);
        sprintf(ifname+strlen(ifname), "%d", ifp->if_unit);

        if (strcmp(name, ifname) == 0)
            return ifp;

        ifp = ifp->if_next;
    }

    return NULL;
}

int ifioctl(struct socket *so, int cmd,
	caddr_t data, struct proc *p)
{
    struct ifreq *ifrp = NULL;
    struct ifnet *ifp = NULL;

    if (cmd == SIOCGIFCONF)
        return ifconf(cmd, data);

    ifrp = (struct ifreq *)data;
    ifp = ifunit(ifrp->ifr_name); 

    switch (cmd)
    {
    case SIOCGIFFLAGS:
        ifrp->ifr_flags = ifp->if_flags;
        break;
    case SIOCGIFMETRIC:
        ifrp->ifr_metric = ifp->if_metric;
        break;
    case SIOCSIFFLAGS:
        if ((ifp->if_flags & IFF_UP) && ((ifrp->ifr_flags & IFF_UP) == 0))
            if_down(ifp);
        if (((ifp->if_flags & IFF_UP) == 0) && (ifrp->ifr_flags & IFF_UP))
            if_up(ifp);

        ifp->if_flags = (ifp->if_flags & IFF_CANTCHANGE) | (ifrp->ifr_flags & ~IFF_CANTCHANGE);
        if (ifp->if_ioctl)
            ifp->if_ioctl(ifp, cmd, data);
        break;
    case SIOCSIFMETRIC:
        ifp->if_metric = ifrp->ifr_metric;
        break;
    default:
        if (so->so_proto == 0)
            return EOPNOTSUPP;
        return so->so_proto->pr_usrreq(so, PRU_CONTROL, cmd, data, ifp);
    }

	return 0;
}

void if_attach(struct ifnet *ifp)
{
	struct ifnet **iflast = &ifnet;
	char buf[12] = "";
    static int if_indexlim = 8;

    while (*iflast)
        iflast = &(*iflast)->if_next;
    *iflast = ifp;

    if (ifnet_addrs == NULL)
        ifnet_addrs = calloc(1, sizeof(*ifnet_addrs) * if_indexlim);
    if (if_index >= if_indexlim)
    {
        if_indexlim <<= 1;
        ifnet_addrs = realloc(ifnet_addrs, sizeof(*ifnet_addrs) * if_indexlim);
        memset(ifnet_addrs+if_indexlim/2, 0, sizeof(*ifnet_addrs) * if_indexlim / 2);
    }

    ifp->if_index = ++if_index;
    ifp->if_addrlist = (struct ifaddr *)calloc(1, sizeof (struct ifaddr));

    // set the member of struct ifaddr pointed by if_addrlist
	struct ifaddr *ifa = ifp->if_addrlist;
    ifa->ifa_next = NULL;
    ifa->ifa_ifp = ifp;
    ifa->ifa_addr = (struct sockaddr *)calloc(2, sizeof (struct sockaddr_dl));
    ifa->ifa_rtrequest = NULL;
    ifa->ifa_flags = ifp->if_flags;
    ifa->ifa_refcnt++;
    ifa->ifa_metric = ifp->if_metric;

    // set the member of struct sockaddr_dl pointed by ifa_addr && ifa_netmask
    struct sockaddr_dl *dl_addr = (struct sockaddr_dl *)ifa->ifa_addr;
    dl_addr->sdl_len = sizeof (*dl_addr);
    dl_addr->sdl_family = AF_LINK;
    dl_addr->sdl_index = ifp->if_index;
    dl_addr->sdl_type = ifp->if_type;
    strcpy(dl_addr->sdl_data, ifp->if_name);
	sprintf(buf, "%d", ifp->if_unit);
    strcat(dl_addr->sdl_data, buf);
    dl_addr->sdl_nlen = strlen(dl_addr->sdl_data);
    dl_addr->sdl_alen = 6;
    dl_addr->sdl_slen = 0;

    struct sockaddr_dl *dl_netmask = dl_addr + 1;
    int masklen = offsetof(struct sockaddr_dl, sdl_data[0]) + dl_addr->sdl_nlen;
    dl_netmask->sdl_len = masklen;
    for (int j = 0; j < dl_addr->sdl_nlen; j++)
        dl_netmask->sdl_data[j] = 0xff;

    ifa->ifa_netmask = (struct sockaddr *)dl_netmask;

    //add if_addrlist to the global variable "ifnext_addrs"
    ifnet_addrs[if_index - 1] = ifa;

    if (ifp->if_output == ether_output)
        ether_ifattach(ifp);
}

void ifinit()
{
    struct ifnet *ifp = ifnet;

    while (ifp)
    {
        ifp->if_snd.ifq_maxlen = ifqmaxlen;
        ifp = ifp->if_next;
    }

    if_slowtimo(0);
}

void if_slowtimo(void *arg)
{
    struct ifnet *ifp = NULL;

    for (ifp = ifnet; ifp; ifp = ifp->if_next)
    {
        if (ifp->if_timer == 0)
            continue;
        if (--ifp->if_timer)
            continue;

        if (ifp->if_watchdog)
            ifp->if_watchdog(ifp->if_unit);
    }

    //timeout(if_slowtimo, (void*)0, hz/IFNET_SLOWHZ);
}

void if_freenameindex(struct if_nameindex *a)
{

}

char *if_indextoname(unsigned int a, char *b)
{
	return NULL;
}

//struct if_nameindex	*if_nameindex(void)
//{
	//return NULL;
//}

unsigned int if_nametoindex(const char *c)
{
	return 0;
}

// 丢弃队列ifq中的所有分组，
// 例如，当一个接口被关闭
void if_qflush(struct ifqueue *ifq)
{
	while (ifq->ifq_len > 0)
	{
		struct mbuf * m = ifq->ifq_head;
		ifq->ifq_head = ifq->ifq_head->m_nextpkt;

		m_freem(m);

		ifq->ifq_len--;
		ifq->ifq_drops++;
	}
}

#define sockaddr_equal(addr1, addr2) \
    memcmp((addr1), (addr2), (addr1)->sa_len) == 0

// locate an interface based on a complete address
struct	ifaddr *ifa_ifwithaddr(struct sockaddr *addr)
{
    extern struct ifnet *ifnet;
    struct ifnet *ifp = NULL;
    struct ifaddr *ifa = NULL;

    for (ifp = ifnet; ifp; ifp = ifp->if_next)
    {
        for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
        {
            if (sockaddr_equal(addr, ifa->ifa_addr))
            {
                return ifa;
            }
            else if (sockaddr_equal(addr, ifa->ifa_broadaddr))
            {
                return ifa;
            }
        }
    }

    return NULL;
}

// find an interface using a specific address family
struct	ifaddr *ifa_ifwithaf(int af)
{
    extern struct ifnet *ifnet;
    struct ifnet *ifp = NULL;
    struct ifaddr *ifa = NULL;

    for (ifp = ifnet; ifp; ifp = ifp->if_next)
    {
        for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
        {
            if (af == ifa->ifa_addr->sa_family)
            {
                return ifa;
            }
        }
    }

    return NULL;
}

// locate the point to point interface with a given destination address
struct	ifaddr *ifa_ifwithdstaddr(struct sockaddr *addr)
{
    extern struct ifnet *ifnet;
    struct ifnet *ifp = NULL;
    struct ifaddr *ifa = NULL;

    for (ifp = ifnet; ifp; ifp = ifp->if_next)
    {
        if ((ifp->if_flags & IFF_POINTOPOINT) == 0)
            continue;

        for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
        {
            if (sockaddr_equal(addr, ifa->ifa_dstaddr))
            {
                return ifa;
            }
        }
    }

    return NULL;
}

// find an interface on a specific network.
// if many, choice is most specific found
struct	ifaddr *ifa_ifwithnet(struct sockaddr *addr)
{
    extern struct ifnet *ifnet;
    struct ifnet *ifp = NULL;
    struct ifaddr *ifa = NULL;
    struct ifaddr *ifa_maybe = NULL;
    u_int af = addr->sa_family;

    if (af == AF_LINK)
    {
        struct sockaddr_dl *sdl = (struct sockaddr_dl *)addr;
        if (sdl->sdl_index && sdl->sdl_index <= if_index)
            return ifnet_addrs[sdl->sdl_index-1];
    }

    for (ifp = ifnet; ifp; ifp = ifp->if_next)
    {
        for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr->sa_family != af
                || ifa->ifa_netmask == 0)
                next : continue;

            char *cp = addr->sa_data;
            char *cp2 = ifa->ifa_addr->sa_data;
            char *cp3 = ifa->ifa_netmask->sa_data;
            char *cplim = cp3 + ifa->ifa_netmask->sa_len;

            while (cp3 < cplim)
                if ((*cp++ ^ *cp2++) & *cp3++)
                    goto next;
            if (ifa_maybe == 0
                || rn_refines((caddr_t)ifa->ifa_netmask,
                (caddr_t)ifa_maybe->ifa_netmask))
                ifa_maybe = ifa;
        }
    }

    return ifa_maybe;
}

// find an interface address specific to an interface best matching
struct	ifaddr *ifaof_ifpforaddr(struct sockaddr *addr, struct ifnet *ifp)
{
    register struct ifaddr *ifa;
    register char *cp, *cp2, *cp3;
    register char *cplim;
    struct ifaddr *ifa_maybe = 0;
    u_int af = addr->sa_family;

    if (af >= AF_MAX)
        return (0);
    for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family != af)
            continue;
        ifa_maybe = ifa;
        if (ifa->ifa_netmask == 0) {
            if (sockaddr_equal(addr, ifa->ifa_addr) ||
                (ifa->ifa_dstaddr && sockaddr_equal(addr, ifa->ifa_dstaddr)))
                return (ifa);
            continue;
        }
        cp = addr->sa_data;
        cp2 = ifa->ifa_addr->sa_data;
        cp3 = ifa->ifa_netmask->sa_data;
        cplim = ifa->ifa_netmask->sa_len + (char *)ifa->ifa_netmask;
        for (; cp3 < cplim; cp3++)
            if ((*cp++ ^ *cp2++) & *cp3)
                break;
        if (cp3 == cplim)
            return (ifa);
    }

    return (ifa_maybe);
}

void link_rtrequest(int cmd, struct rtentry *rt, struct sockaddr *sa)
{
}

#undef sockaddr_equal
