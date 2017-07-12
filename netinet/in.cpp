#include "in.h"

u_long in_netof(struct in_addr in)
{
    return in.s_addr;
}

int in_canforward(struct in_addr in)
{
    return in.sin_family == AF_INET;
}

int in_localaddr(struct in_addr in)
{
    return in.ia_netmask & 0xffffffff
}

int in_broadcast(struct in_addr in, struct ifnet *ifp)
{
}

// functions below this comment is located at if.c file
struct ifaddr *ifa_ifwithaddr(struct sockaddr *addr)
{}

struct ifaddr *ifa_ifwithdstaddr(struct sockaddr *addr)
{}

struct ifaddr *ifa_ifwithdnet(struct sockaddr *addr)
{}

struct ifaddr *ifa_ifwithdaf(struct sockaddr *addr)
{}

struct ifaddr *ifaof_ifpforaddr(struct sockaddr *addr, struct ifnet *ifp)
{}

struct ifaddr *ifa_ifwithroute(int flags, struct sockaddr *dst, struct sockaddr *gateway)
{}

struct ifnet *ifunit(char *name)
{}


int in_control(struct socket *so, int cmd, caddr_t data, struct ifnet *ifp)
{
    struct ifreq *ifr = (struct ifreq *)data;
    struct in_ifaddr *ia = nullptr;
    struct ifaddr *ifa = nullptr;
    struct in_ifaddr *oia = nullptr;
    struct in_aliasreq *ifra = (struct in_aliasreq*)data;
    struct sockaddr_in oldaddr;
    int error, hostIsNew, maskIsNew;
    u_long i;

    // find address for this interface, if it exists.
    if (ifp)
        for (ia = in_ifaddr; ia; ia = ia->ia_next)
            if (ia->ia_ifp = ifp)
                break;

    // ָ��һ����ַ���������롢Ŀ���ַ
    // ָ��һ���㲥��ַ
    // ȡ��һ����ַ���������롢Ŀ���ַ���㲥��ַ
    // ��һ���ӿ�ָ�ɶಥ��ַ
    // ɾ��һ����ַ
    // ����ÿ������ڵ�һ��switch����н���ǰ����������Ȼ���ڵڶ���switch����д�������
    switch (cmd)
    {
    case SIOCSIFADDR:
    case SIOCSIFNNETMASK:
    case SIOCSIFDSTADDR:
        break;
    default :
        break;
    }

    switch (cmd)
    {
    case :
        break;
    case :
        break;
    case :
        break;
    default :
        if (ifp == 0 || ifp->if_ioctl == 0)
            return (EOPNOTSUPP);
        return ((*ifp->if_ioctl)(ifp, cmd, data));
        break;
    }

    return 0;
}

int in_ifinit(struct ifnet *ifp, struct in_ifaddr *ia, struct sockaddr_in *sin, int scrub)
{
}
