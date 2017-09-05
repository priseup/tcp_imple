#ifndef TEST_TEST_H
#define TEST_TEST_H

#include <stdbool.h>

struct mbuf;
struct ifnet;
struct ifaddr;
struct sockaddr_dl;

bool mbuf_equal(struct mbuf *m1, struct mbuf *m2);

// chapter2
void  print_mbuf(struct mbuf *m, int offset, int len);
void print_mbuf_content(struct mbuf *m);

// chapter3
void print_ifnet(struct ifnet *ifp);
void print_global_ifnet();
void print_i_global_ifnet(int i);
void print_ifaddr(struct ifaddr *addrp);
void print_global_ifaddr();
void print_i_global_ifaddr(int i);
void print_sockaddr_dl(struct sockaddr_dl *sip);


// chapter4
void print_ifconf(struct ifconf *ifc);
void print_ifreq(struct ifreq *ifrq);

#endif // TEST_TEST_H

