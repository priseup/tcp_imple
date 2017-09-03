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
    printf("\n**************%s START************\n", __FUNCTION__);

    while (m->m_len < offset)
    {
        offset -= m->m_len;
        m = m->m_next;
    }

    while (len && m)
    {
        caddr_t p = mtod(m, caddr_t) + offset;
        printf("%s\n", p);

        len -= min(m->m_len - offset, len);
        m = m->m_next;
        offset = 0;
    }              

    printf("**************%s END************\n", __FUNCTION__);
}

void print_mbuf_content(struct mbuf *m)
{
    printf("\n**************%s START************\n", __FUNCTION__);

    int i = 0, total_len = 0;
    while (m)
    {
        printf("%dst mbuf: p=0x%p, m_len=%d\n", ++i, mtod(m, caddr_t), m->m_len);
        printf("content: %s\n", mtod(m, caddr_t));
      
        total_len += m->m_len;
		m = m->m_next;
    }

    printf("total_len=%d\n", total_len);

    printf("**************%s END************\n", __FUNCTION__);
}

void print_global_ifnet()
{
    printf("\n**************%s START************\n", __FUNCTION__);

    extern struct ifnet *ifnet;
    struct ifnet *ifp = ifnet;

    while (ifp)
    {
        print_ifnet(ifp);
        ifp = ifp->if_next;
    }

    printf("**************%s END************\n", __FUNCTION__);
}

void print_ifnet(struct ifnet *ifp)
{
    printf("\n**************%s START************\n", __FUNCTION__);

    if (ifp)
    {
        printf("if_name: %s\n", ifp->if_name);
        printf("if_unit: %d\n", ifp->if_unit);
        printf("if_index: %d\n", ifp->if_index);
        printf("if_flags: %d\n", ifp->if_flags);
        printf("if_pcount: %d\n", ifp->if_pcount);

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

        printf("if_snd.ifq_head @ %p\n", ifp->if_snd.ifq_head);
        printf("if_snd.ifq_tail @ %p\n", ifp->if_snd.ifq_tail);
        printf("if_snd.ifq_len: %d\n", ifp->if_snd.ifq_len);
        printf("if_snd.ifq_maxlen: %d\n", ifp->if_snd.ifq_maxlen);
        printf("if_snd.ifq_drops: %d\n", ifp->if_snd.ifq_drops);

        if (ifp->if_snd.ifq_head)
            print_mbuf_content(ifp->if_snd.ifq_head);
        else
            printf("ifp->if_snd.ifq_head is NULL\n");
        if (ifp->if_snd.ifq_tail)
            print_mbuf_content(ifp->if_snd.ifq_tail);
        else
            printf("ifp->if_snd.ifq_tail is NULL\n");

        print_ifaddr(ifp->if_addrlist);
    }

    printf("**************%s END************\n", __FUNCTION__);
}

void print_global_ifaddr()
{
    printf("\n**************%s START************\n", __FUNCTION__);

    extern int if_index;
    extern struct ifaddr **ifnet_addrs;
    struct ifaddr **pifa = ifnet_addrs;
   
    int i = 0;
    while (*pifa && i++ < if_index)
    {
        print_ifaddr(*pifa);
        pifa++;
    }

    printf("**************%s END************", __FUNCTION__);
}

void print_ifaddr(struct ifaddr *ifa)
{
    printf("\n**************%s START************\n", __FUNCTION__);

    if (ifa)
    {
        printf("ifa_addr: %p\n", ifa->ifa_addr);
        printf("ifa_dstaddr: %p\n", ifa->ifa_dstaddr);
        printf("ifa_netmask: %p\n", ifa->ifa_netmask);
        printf("ifa_flags: %d\n", ifa->ifa_flags);
        printf("ifa_refcnt: %d\n", ifa->ifa_refcnt);
        printf("ifa_metric: %d\n", ifa->ifa_metric);

        print_sockaddr_dl((struct sockaddr_dl*)ifa->ifa_addr);
        print_sockaddr_dl((struct sockaddr_dl*)ifa->ifa_dstaddr);
        print_sockaddr_dl((struct sockaddr_dl*)ifa->ifa_netmask);
    }

    printf("**************%s END************\n", __FUNCTION__);
}

void print_sockaddr_dl(struct sockaddr_dl *sdl)
{
    printf("\n**************%s START************\n", __FUNCTION__);

    if (sdl)
    {
        printf("sdl_len: %d\n", sdl->sdl_len);
        printf("sdl_family: %d\n", sdl->sdl_family);
        printf("sdl_index: %d\n", sdl->sdl_index);
        printf("sdl_type: %d\n", sdl->sdl_type); // same as if_data: ifi_type
        printf("sdl_nlen: %d\n", sdl->sdl_nlen);
        printf("sdl_alen: %d\n", sdl->sdl_alen);
        printf("sdl_slen: %d\n", sdl->sdl_slen);
        printf("sdl_data: %s\n", sdl->sdl_data);
    }

    printf("**************%s END************\n", __FUNCTION__);
}

void print_i_global_ifnet(int index)
{
    printf("\n**************%s START************\n", __FUNCTION__);

    extern struct ifnet *ifnet;
    struct ifnet *ifp = ifnet;

    for (int i = 0; i < index && ifp; i++)
    {
        ifp = ifp->if_next;
    }
    if (ifp == NULL)
        printf("index is out of range of global ifnet\n");

    print_ifnet(ifp);

    printf("**************%s END************\n", __FUNCTION__);
}

void print_i_global_ifaddr(int index)
{
    printf("\n**************%s START************\n", __FUNCTION__);

    extern struct ifaddr **ifnet_addrs;
    struct ifaddr **ifnet_addrs_traverse = ifnet_addrs;

    for (int i = 0; i < index && ifnet_addrs_traverse; i++)
    {
        ifnet_addrs_traverse++;
    }
    if (ifnet_addrs_traverse == NULL)
        printf("index is out of range of global ifnet_addrs\n");

    print_ifaddr(*ifnet_addrs_traverse);

    printf("**************%s END************\n", __FUNCTION__);
}

void print_sockaddr(struct sockaddr *sa)
{
    printf("sa_len: %u\n", sa->sa_len);
    printf("sa_family: %u\n", sa->sa_family);

    printf("sa_data: %s\n", sa->sa_data);
}

void print_ifconf(struct ifconf *ifc)
{
    printf("ifc_len: %d\n", ifc->ifc_len);
   
    struct ifreq *ifrq = ifc->ifc_req;
    while ((char*)ifrq < ((char*)ifc + ifc->ifc_len))   {
        print_ifreq(ifrq);
        ifrq++;
    }
}

void print_ifreq(struct ifreq *ifrq)
{
    printf("ifr_name: %s\n", ifrq->ifr_name);

    print_sockaddr(&ifrq->ifr_addr);
    print_sockaddr(&ifrq->ifr_dstaddr);
    print_sockaddr(&ifrq->ifr_broadaddr);

    printf("ifr_flags: %d\n", ifrq->ifr_flags);
    printf("ifr_metric: %d\n", ifrq->ifr_metric);
    printf("ifr_data: %s\n", ifrq->ifr_data);
}