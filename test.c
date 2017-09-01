#include "test.h"
#include "sys\mbuf.h"
#include "net\if.h"
#include "net\if_dl.h"
#include <string.h>
#include <stdio.h>

bool mbuf_equal(struct mbuf *m1, struct mbuf *m2)
{
    if (m1->m_flags != m2->m_flags)
        return false;

    while (m1 && m2)
    {
        if (m1->m_len != m2->m_len)
            return false;

        if (memcmp(mtod(m1, caddr_t), mtod(m2, caddr_t), m1->m_len) != 0)
            return false;

        m1 = m1->m_next;
        m2 = m2->m_next;
    }

    if (m1 || m2)
        return false;

    return true;
}


void print_mbuf(struct mbuf *m, int offset, int len)
{
    while (m->m_len < offset)
    {
        m = m->m_next;
    }

	caddr_t p = mtod(m, caddr_t) + offset;
    while (m->m_len < len)
    {
        printf("%s\n", p);

        offset = 0;
        len -= m->m_len;
        m = m->m_next;
    }
    printf("%s\n", p);
    offset = 0;
}

void print_mbuf_content(struct mbuf *m)
{
    int i = 0, total_len = 0;
    while (m)
    {
        printf("%d mbuf: p=0x%p, m_len=%d\n", ++i, mtod(m, caddr_t), m->m_len);
        total_len += m->m_len;
		m = m->m_next;
    }
    printf("total_len=%d\n\n", total_len);
}

void print_global_ifnet()
{
    extern struct ifnet *ifnet;
    struct ifnet *ifnet_backup = ifnet;

    while (ifnet)
    {
        print_ifnet(ifnet);
        ifnet = ifnet->if_next;
    }
    ifnet = ifnet_backup;
}

void print_ifnet(struct ifnet *ifp)
{
    if (ifp)
    {
        printf("if_name: %s\n", ifp->if_name);
        printf("if_unit: %d\n", ifp->if_unit);
        printf("if_index: %d\n", ifp->if_index);
        printf("if_flags: %d\n", ifp->if_flags);
        printf("if_pcount: %d\n", ifp->if_pcount);

        print_ifaddr(ifp->if_addrlist);

        printf("if_mtu: %d\n", ifp->if_mtu);
        printf("if_type: %d\n", ifp->if_type);
        printf("if_addrlen: %d\n", ifp->if_addrlen);
        printf("if_hdrlen: %d\n", ifp->if_hdrlen);
        printf("if_metric: %d\n", ifp->if_metric);
        printf("if_baudrate: %d\n", ifp->if_baudrate);
        printf("if_ipackets: %d\n", ifp->if_ipackets);
        printf("if_ierrors: %d\n", ifp->if_ierrors);
        printf("if_opackets: %d\n", ifp->if_opackets);
        printf("if_oerrors: %d\n", ifp->if_oerrors);
        printf("if_collisions: %d\n", ifp->if_collisions);
        printf("if_ibytes: %d\n", ifp->if_ibytes);
        printf("if_obytes: %d\n", ifp->if_obytes);
        printf("if_imcasts: %d\n", ifp->if_imcasts);
        printf("if_omcasts: %d\n", ifp->if_omcasts);
        printf("if_iqdrops: %d\n", ifp->if_iqdrops);
        printf("if_noproto: %d\n", ifp->if_noproto);
        printf("if_lastchange: _1\n");
    }
}

void print_global_ifaddr()
{
    extern int if_index;
    extern struct ifaddr **ifnet_addrs;
    struct ifaddr **ifnet_addrs_backup = ifnet_addrs;
   
    int i = 0;
    while (*ifnet_addrs && i++ < if_index)
    {
        print_ifaddr(*ifnet_addrs);
        ifnet_addrs++;
    }
    ifnet_addrs = ifnet_addrs_backup;
}

void print_ifaddr(struct ifaddr *addrp)
{
    if (addrp)
    {
        printf("ifa_addr: %p\n", addrp->ifa_addr);
        printf("ifa_dstaddr: %p\n", addrp->ifa_dstaddr);
        printf("ifa_netmask: %p\n", addrp->ifa_netmask);
        printf("ifa_flags: %d\n", addrp->ifa_flags);
        printf("ifa_refcnt: %d\n", addrp->ifa_refcnt);
        printf("ifa_metric: %d\n", addrp->ifa_metric);

        print_sockaddr_dl((struct sockaddr_dl*)addrp->ifa_addr);
        print_sockaddr_dl((struct sockaddr_dl*)addrp->ifa_dstaddr);
        print_sockaddr_dl((struct sockaddr_dl*)addrp->ifa_netmask);
    }
}

void print_sockaddr_dl(struct sockaddr_dl *sip)
{
    if (sip)
    {
        printf("sdl_len: %d\n", sip->sdl_len);
        printf("sdl_family: %d\n", sip->sdl_family);
        printf("sdl_index: %d\n", sip->sdl_index);
        printf("sdl_type: %d\n", sip->sdl_type); // same as if_data: ifi_type
        printf("sdl_nlen: %d\n", sip->sdl_nlen);
        printf("sdl_alen: %d\n", sip->sdl_alen);
        printf("sdl_slen: %d\n", sip->sdl_slen);
        printf("sdl_data: %s\n", sip->sdl_data);
    }
}

void print_i_global_ifnet(int index)
{
    extern struct ifnet *ifnet;
    struct ifnet *ifnet_traverse = ifnet;

    for (int i = 0; i < index && ifnet_traverse; i++)
    {
        ifnet_traverse = ifnet_traverse->if_next;
    }
    if (ifnet_traverse == NULL)
        printf("index is out of range of global ifnet\n");

    print_ifnet(ifnet_traverse);
}

void print_i_global_ifaddr(int index)
{
    extern struct ifaddr **ifnet_addrs;
    struct ifaddr **ifnet_addrs_traverse = ifnet_addrs;

    for (int i = 0; i < index && ifnet_addrs_traverse; i++)
    {
        ifnet_addrs_traverse++;
    }
    if (ifnet_addrs_traverse == NULL)
        printf("index is out of range of global ifnet_addrs\n");

    print_ifaddr(*ifnet_addrs_traverse);
}
