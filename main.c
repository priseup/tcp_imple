#include "test.h"
#include "sys\mbuf.h"
#include "net\if.h"
#include "net\if_slvar.h"
#include "netinet\if_ether.h"
#include <stdio.h>
#include <string.h>
#include "hp300\dev\device.h"
#include "hp300\include\endian.h"
#include "sys\socketvar.h"

#define N 1024

#define CHAPTER1
#define CHAPTER2
#define CHAPTER3
#define CHAPTER3
#define CHAPTER4

int main(void)
{
    char buf[N] = {'\0'};
    char *p = "it's a test of mbuf on T460s, end...";

#ifdef CHAPTER2
    {
        struct mbuf *m1;
        struct mbuf *m2;

        MGET(m1, 0, MT_HEADER);
        MGET(m2, 0, MT_DATA);

        m_copyback(m1, 0, strlen(p), p);
        print_mbuf(m1, 0, 0);
        print_mbuf_content(m1);

        m_copyback(m2, 4, strlen(p), p);
        print_mbuf(m2, 4, 0);
        print_mbuf_content(m2);

        m_adj(m1, -5);
        print_mbuf(m1, 0, 0);
        print_mbuf_content(m1);

        m_cat(m1, m2);
        print_mbuf(m1, 0, 0);
        print_mbuf_content(m1);

        m_copydata(m1, 4, 5, buf);
        print_mbuf(m1, 0, 0);
        print_mbuf_content(m1);
        printf("%s\n", buf);

        struct mbuf *m3 = m_copym(m2, 15, 40, 0);
        print_mbuf(m3, 0, 0);
        print_mbuf_content(m3);

        struct ifnet ifnet1;
        struct mbuf *m4 = m_devget(buf, 20, 5, &ifnet1, NULL);
        print_mbuf(m4, 0, 0);
        print_mbuf_content(m4);
    }
#endif  // CHAPTER2

#ifdef CHAPTER3
    {
        struct hp_device dev;
        dev.hp_addr = "hp_addr";
        dev.hp_unit = 0;
        leattach(&dev);
        print_global_ifnet();
        print_global_ifaddr();

        loopattach(6);
        print_global_ifnet();
        print_global_ifaddr();

        slattach();
        print_global_ifnet();
        print_global_ifaddr();

        ifinit();
        print_global_ifnet();
    }
#endif  // CHAPTER3

#ifdef CHAPTER4
{
    int unit = 5;
    char buf[1024];
    int len = 100;
    struct mbuf *m1;
    struct ether_header eh;
//    struct mbuf *m2;

//    m1->m_flags = M_PKTHDR;

    eh.ether_type = htons(ETHERTYPE_IP);
    memcpy(eh.ether_dhost, etherbroadcastaddr, sizeof etherbroadcastaddr);

    MGET(m1, 0, MT_HEADER);
//   MGET(m2, 0, MT_DATA);

    m_copyback(m1, 0, strlen(p), p);
    print_mbuf(m1, 0, strlen(p));
    
    memcpy(buf, &eh, sizeof eh);
    memcpy(buf + sizeof eh, m1, sizeof *m1);

    leread(unit, buf, len);  // ether_input() is called, so no test for ether_input()
    print_mbuf(m1, 0, len);

    struct ifnet ifnet1;
    memset(&ifnet1, 0, sizeof (ifnet1));
    ifnet1.if_flags |= IFF_UP;
    ifnet1.if_snd.ifq_maxlen = IFQ_MAXLEN;
//    ifnet1.if_start = lestart;

    struct rtentry rt;
    rt.rt_flags = RTF_UP;

    struct sockaddr sa;
    sa.sa_family = AF_UNSPEC;
//    ether_output(&ifnet1, &m1, &sa, &rt);

    char data[1024] = "";
    ((struct ifconf *)data)->ifc_len = 1024;
    ((struct ifconf *)data)->ifc_req = (struct ifreq *)(data + sizeof(struct ifconf));
    ifconf(0, data);
//    print_ifconf((struct ifconf *)data);

    struct socket so;
    strcpy(((struct ifreq *)data)->ifr_name, "le0", strlen("le0"));
    //((struct ifreq *)data)->ifr_addr = (struct sockaddr *)(data + offsetof(struct ifreq, ifr_ifru));
    ifioctl(&so, 0, data, NULL);
}
#endif  // CHAPTER4

    return 0;
}
