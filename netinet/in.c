#include "in.h"
#include "in_var.h"
#include "..\sys\socket.h"
#include "..\sys\errno.h"
#include "..\sys\sockio.h"
#include "..\sys\socketvar.h"
#include <stddef.h>

int	in_interfaces;		/* number of external internet interfaces */
extern struct in_ifaddr *in_ifaddr;
extern struct ifnet loif;

/*
* Delete any existing route for an interface.
*/
void
in_ifscrub(ifp, ia)
register struct ifnet *ifp;
register struct in_ifaddr *ia;
{
    if ((ia->ia_flags & IFA_ROUTE) == 0)
        return;
    if (ifp->if_flags & (IFF_LOOPBACK | IFF_POINTOPOINT))
        rtinit(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST);
    else
        rtinit(&(ia->ia_ifa), (int)RTM_DELETE, 0);
    ia->ia_flags &= ~IFA_ROUTE;
}


u_long in_netof(struct in_addr in)
{
    return in.s_addr;
}

int in_canforward(struct in_addr in)
{
    return AF_INET;
}

int in_localaddr(struct in_addr in)
{
	return 0xffffffff;
}

int in_broadcast(struct in_addr in, struct ifnet *ifp)
{
    return 0;
}

// functions below this comment is located at if.c file
struct ifaddr *ifa_ifwithaddr(struct sockaddr *addr)
{
    return NULL;
}

struct ifaddr *ifa_ifwithdstaddr(struct sockaddr *addr)
{
    return NULL;
}

struct ifaddr *ifa_ifwithdnet(struct sockaddr *addr)
{
    return NULL;
}

struct ifaddr *ifa_ifwithdaf(struct sockaddr *addr)
{
    return NULL;
}

struct ifaddr *ifaof_ifpforaddr(struct sockaddr *addr, struct ifnet *ifp)
{
    return NULL;
}

struct ifnet *ifunit(char *name)
{
    return NULL;
}

int in_control(struct socket *so, int cmd, caddr_t data, struct ifnet *ifp)
{
    struct ifreq *ifr = (struct ifreq *)data;
    struct in_ifaddr *ia = NULL;
    struct ifaddr *ifa = NULL;
    struct in_ifaddr *oia = NULL;
    struct in_aliasreq *ifra = (struct in_aliasreq*)data;
    struct sockaddr_in oldaddr;
    int error, hostIsNew, maskIsNew;
    u_long i;

    // find address for this interface, if it exists.
    if (ifp)
        for (ia = in_ifaddr; ia; ia = ia->ia_next)
            if (ia->ia_ifp = ifp)
                break;

    // 指派一个地址、网络掩码、目标地址
    // 指派一个广播地址
    // 取回一个地址、网络掩码、目标地址、广播地址
    // 给一个接口指派多播地址
    // 删除一个地址
    // 对于每组命令，在第一个switch语句中进行前提条件处理，然后在第二个switch语句中处理命令
    switch (cmd)
    {
    case SIOCAIFADDR:
    case SIOCDIFADDR:
        if (ifra->ifra_addr.sin_family == AF_INET)
        {
            if (ia->ia_ifp == ifp
                && ia->ia_addr.sin_addr.s_addr == ifra->ifra_addr.sin_addr.s_addr)
                break;
        }
        if (cmd == SIOCDIFADDR && ia == 0)
            return EADDRNOTAVAIL;
    case SIOCSIFADDR:
    case SIOCSIFNETMASK:
    case SIOCSIFDSTADDR:
        if ((so->so_state && SS_PRIV) == 0)
            return EPERM;

        if (ifp == 0)
            perror("in_control");
        if (ia == (struct in_ifaddr *)0)
        {
            oia = malloc(sizeof *oia, M_IFADDR, M_WAITOK);
            if (oia == NULL)
                return ENOBUFS;
            memset(oia, 0, sizeof *oia);

            if (ia = in_ifaddr)
            {
                for (; ia->ia_next; ia = ia->ia_next)
                    continue;
                ia->ia_next = oia;
            }
            else 
                in_ifaddr = oia;
            ia = oia;
            if (ifa = ifp->if_addrlist)
            {
                for (; ifa->ifa_next; ifa = ifa->ifa_next)
                    continue;
                ifa->ifa_next = (struct ifaddr *)ia;
            }
            else
                ifp->if_addrlist = (struct ifaddr *)ia;

            ia->ia_ifa.ifa_addr = (struct sockaddr *)&ia->ia_addr;
            ia->ia_ifa.ifa_dstaddr = (struct sockaddr *)&ia->ia_dstaddr;
            ia->ia_ifa.ifa_netmask = (struct sockaddr *)&ia->ia_sockmask;
            ia->ia_sockmask.sin_len = 8;
            if (ifp->if_flags & IFF_BROADCAST)
            {
                ia->ia_broadaddr.sin_len = sizeof(ia->ia_addr);
                ia->ia_broadaddr.sin_family = AF_INET;
            }
            ia->ia_ifp = ifp;
            if (ifp != &loif)
                in_interfaces++;
        }
        break;
    case SIOCSIFBRDADDR:
        if ((so->so_state & SS_PRIV) == 0)
            return EPERM;

    case SIOCGIFADDR:
    case SIOCGIFNETMASK:
    case SIOCGIFDSTADDR:
    case SIOCGIFBRDADDR:
        if (ia == NULL)
            return EADDRNOTAVAIL;
    }

    switch (cmd)
    {
    case SIOCGIFADDR:
        *((struct sockaddr_in *)&ifr->ifr_addr) = ia->ia_addr;
        break;

    case SIOCAIFADDR:
        maskIsNew = 0;
        hostIsNew = 1;
        error = 0;
        if (ia->ia_addr.sin_family == AF_INET)
        {
            if (ifra->ifra_addr.sin_len = 0)
            {
                ifra->ifra_addr = ia->ia_addr;
                hostIsNew = 0;
            }
            else if (ifra->ifra_addr.sin_addr.s_addr
                    == ia->ia_addr.sin_addr.s_addr)
                hostIsNew = 0;
        }
        if (ifra->ifra_mask.sin_len)
        {
            in_ifscrub(ifp, ia);
            ia->ia_sockmask = ifra->ifra_mask;
            ia->ia_subnetmask = ntohl(ia->ia_sockmask.sin_addr.s_addr);
            maskIsNew = 1;
        }
        if ((ifp->if_flags & IFF_POINTOPOINT) &&
            (ifra->ifra_dstaddr.sin_family == AF_INET))
        {
            in_ifscrub(ifp, ia);
            ia->ia_dstaddr = ifra->ifra_dstaddr;
            maskIsNew = 1;  // we lie; but the effect's the same
        }
        if (ifra->ifra_addr.sin_family == AF_INET
            && (hostIsNew || maskIsNew))
            error = in_ifinit(ifp, ia, &ifra->ifra_addr, 0);
        if ((ifp->if_flags & IFF_BROADCAST)
            && (ifra->ifra_broadaddr.sin_family == AF_INET))
            ia->ia_broadaddr = ifra->ifra_broadaddr;
        return error;
    case SIOCDIFADDR:
        in_ifscrub(ifp, ia);
        if ((ifa = ifp->if_addrlist) == (struct ifaddr *)ia)
            ifp->if_addrlist = ifa->ifa_next;
        else
        {
            while (ifa->ifa_next
                    && (ifa->ifa_next != (struct ifaddr *)ia))
                ifa = ifa->ifa_next;
            if (ifa->ifa_next)
                ifa->ifa_next = ((struct ifaddr *)ia)->ifa_next;
            else
                printf("couldn't unlink inifaddr from ifp\n");
        }
        oia = ia;
        if (oia == (ia = in_ifaddr))
            in_ifaddr = ia->ia_next;
        else
        {
            while (ia->ia_next && (ia->ia_next != oia))
                ia = ia->ia_next;
            if (ia->ia_next)
                ia->ia_next = oia->ia_next;
            else
                printf("didn't unlink inifaddr from list\n");
        }
        IFAFREE(&oia->ia_ifa);
        break;
    case SIOCSIFADDR:
        return (in_ifinit(ifp, ia,
                (struct sockaddr_in *)&ifr->ifr_addr, 1));
    case SIOCSIFNETMASK:
            i = ifra->ifra_addr.sin_addr.s_addr;
            ia->ia_subnetmask = ntohl(ia->ia_sockmask.sin_addr.s_addr = i);
            break;
    case SIOCSIFDSTADDR:
        if ((ifp->if_flags & IFF_POINTOPOINT) == 0)
            return EINVAL;
        oldaddr = ia->ia_dstaddr;
        ia->ia_dstaddr = *(struct sockaddr_in *)&ifr->ifr_dstaddr;
        if (ifp->if_ioctl && (error = (ifp->if_ioctl)(ifp, SIOCSIFDSTADDR, (caddr_t)ia)))
        {
            ia->ia_dstaddr = oldaddr;
            return error;
        }
        if (ia->ia_flags & IFA_ROUTE)
        {
            ia->ia_ifa.ifa_dstaddr = (struct sockaddr *)&oldaddr;
            rtinit(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST);
            ia->ia_ifa.ifa_dstaddr = (struct sockaddr *)&ia->ia_dstaddr;
            rtinit(&(ia->ia_ifa), (int)RTM_ADD, RTF_HOST|RTF_UP);
        }
        break;
    case SIOCSIFBRDADDR:
        if ((ifp->if_flags & IFF_BROADCAST) == 0)
            return EINVAL;
        ia->ia_broadaddr = *(struct sockaddr_in *)&ifr->ifr_broadaddr;
        break;
    case SIOCGIFNETMASK:
        *((struct sockaddr_in *)&ifr->ifr_addr) = ia->ia_sockmask;
        break;
    case SIOCGIFDSTADDR:
        if ((ifp->if_flags & IFF_POINTOPOINT) == 0)
            return EINVAL;
        *((struct sockaddr_in*)&ifr->ifr_dstaddr) = ia->ia_dstaddr;
        break;
    case SIOCGIFBRDADDR:
        if ((ifp->if_flags & IFF_BROADCAST) == 0)
            return EINVAL;
        *((struct sockaddr_in*)&ifr->ifr_dstaddr) = ia->ia_broadaddr;
        break;
    default :
        if (ifp == 0 || ifp->if_ioctl == 0)
            return (EOPNOTSUPP);
        return ((*ifp->if_ioctl)(ifp, cmd, data));
    }

    return 0;
}

int in_ifinit(struct ifnet *ifp, struct in_ifaddr *ia, struct sockaddr_in *sin, int scrub)
{
    return 0;
}
