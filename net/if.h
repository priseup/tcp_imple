#ifndef NET_IF_H
#define NET_IF_H

#include "route.h"
#include "..\sys\time.h"
#include "..\sys\socket.h"
#include "..\netinet\in.h"
#include "../sys/mbuf.h"

#define	IFF_UP		0x1		/* interface is up */
#define	IFF_BROADCAST	0x2		/* broadcast address valid */
#define	IFF_DEBUG	0x4		/* turn on debugging */
#define	IFF_LOOPBACK	0x8		/* is a loopback net */
#define	IFF_POINTOPOINT	0x10		/* interface is point-to-point link */
#define	IFF_NOTRAILERS	0x20		/* avoid use of trailers */
#define	IFF_RUNNING	0x40		/* resources allocated */
#define	IFF_NOARP	0x80		/* no address resolution protocol */
#define	IFF_PROMISC	0x100		/* receive all packets */
#define	IFF_ALLMULTI	0x200		/* receive all multicast packets */
#define	IFF_OACTIVE	0x400		/* transmission in progress */
#define	IFF_SIMPLEX	0x800		/* can't hear own transmissions */
#define	IFF_LINK0	0x1000		/* per link layer defined bit */
#define	IFF_LINK1	0x2000		/* per link layer defined bit */
#define	IFF_LINK2	0x4000		/* per link layer defined bit */
#define	IFF_MULTICAST	0x8000		/* supports multicast */

#define	IFA_ROUTE	RTF_UP		/* route installed */

/* flags set internally only: */
#define	IFF_CANTCHANGE \
	(IFF_BROADCAST|IFF_POINTOPOINT|IFF_RUNNING|IFF_OACTIVE|\
	    IFF_SIMPLEX|IFF_MULTICAST|IFF_ALLMULTI)

struct mbuf;

struct ifnet
{
    struct ifnet *if_next;
    struct ifaddr *if_addrlist;
    char *if_name;
    short if_unit;
    u_short if_index;
    short if_flags;
    short if_timer;
    int if_pcount;
    caddr_t if_bpf;

	struct	if_data 
    {
/* generic interface information */
		u_char	ifi_type;	/* ethernet, tokenring, etc */
		u_char	ifi_addrlen;	/* media address length */
		u_char	ifi_hdrlen;	/* media header length */
		u_long	ifi_mtu;	/* maximum transmission unit */
		u_long	ifi_metric;	/* routing metric(external only) */
		u_long	ifi_baudrate;	/* linespeed */
/* volatile statistics */
		u_long	ifi_ipackets;	/* packets received on interface */
		u_long	ifi_ierrors;	/* input errors on interface */
		u_long	ifi_opackets;	/* packets sent on interface */
		u_long	ifi_oerrors;	/* output errors on interface */
		u_long	ifi_collisions;	/* collisions on csma interfaces */
		u_long	ifi_ibytes;	/* total number of octets received */
		u_long	ifi_obytes;	/* total number of octets sent */
		u_long	ifi_imcasts;	/* packets received via multicast */
		u_long	ifi_omcasts;	/* packets sent via multicast */
		u_long	ifi_iqdrops;	/* dropped on input, this interface */
		u_long	ifi_noproto;	/* destined for unsupported protocol */
		struct	timeval ifi_lastchange;/* last updated */
	} if_data;

    int(*if_init)(int);
    int(*if_output)(struct ifnet *, struct mbuf *,
            struct sockaddr*, struct rtentry *);
    int(*if_start)(struct ifnet *);
    int(*if_done)(struct ifnet *);
    int(*if_ioctl)(struct ifnet *, int, caddr_t);
    int(*if_reset)(int);
    int(*if_watchdog)(int);

	struct ifqueue 
    {
		struct	mbuf *ifq_head;
		struct	mbuf *ifq_tail;
		int	ifq_len;
		int	ifq_maxlen;
		int	ifq_drops;
	} if_snd;			/* output queue */

#define if_mtu if_data.ifi_mtu
#define if_type if_data.ifi_type
#define if_addrlen if_data.ifi_addrlen
#define if_hdrlen if_data.ifi_hdrlen
#define if_metric if_data.ifi_metric
#define if_baudrate if_data.ifi_baudrate
#define if_ipackets if_data.ifi_ipackets
#define if_ierrors if_data.ifi_ierrors
#define if_opackets if_data.ifi_opackets
#define if_oerrors if_data.ifi_oerrors
#define if_collisions if_data.ifi_collisions
#define if_ibytes if_data.ifi_ibytes
#define if_obytes if_data.ifi_obytes
#define if_imcasts if_data.ifi_imcasts
#define if_omcasts if_data.ifi_omcasts
#define if_iqdrops if_data.ifi_iqdrops
#define if_noproto if_data.ifi_noproto
#define if_lastchange if_data.ifi_lastchange
};

/*
 * Message format for use in obtaining information about interfaces
 * from getkerninfo and the routing socket
 */
struct if_msghdr {
	u_short	ifm_msglen;	/* to skip over non-understood messages */
	u_char	ifm_version;	/* future binary compatability */
	u_char	ifm_type;	/* message type */
	int	ifm_addrs;	/* like rtm_addrs */
	int	ifm_flags;	/* value of if_flags */
	u_short	ifm_index;	/* index for associated ifp */
	struct	if_data ifm_data;/* statistics and other data about if */
};

/*
 * Message format for use in obtaining information about interface addresses
 * from getkerninfo and the routing socket
 */
struct ifa_msghdr {
	u_short	ifam_msglen;	/* to skip over non-understood messages */
	u_char	ifam_version;	/* future binary compatability */
	u_char	ifam_type;	/* message type */
	int	ifam_addrs;	/* like rtm_addrs */
	int	ifam_flags;	/* value of ifa_flags */
	u_short	ifam_index;	/* index for associated ifp */
	int	ifam_metric;	/* value of ifa_metric */
};

struct ifreq
{
#define IFNAMSIZ 16
    char ifr_name[IFNAMSIZ];
    union
    {
        struct sockaddr ifru_addr;
        struct sockaddr ifru_dstaddr;
        struct sockaddr ifru_broadaddr;
        short ifru_flags;
        int ifru_metric;
        caddr_t ifru_data;
    } ifr_ifru;

#define ifr_addr        ifr_ifru.ifru_addr
#define ifr_dstaddr     ifr_ifru.ifru_dstaddr
#define ifr_broadaddr   ifr_ifru.ifru_broadaddr
#define ifr_flags       ifr_ifru.ifru_flags
#define ifr_metric      ifr_ifru.ifru_metric
#define ifr_data        ifr_ifru.ifru_data
};

struct ifaliasreq
{
    char    ifra_name[IFNAMSIZ];
    struct sockaddr_in  ifra_addr;
    struct sockaddr_in  ifra_broadaddr;
    struct sockaddr_in  ifra_mask;
};

struct ifconf
{
    int ifc_len;
    union
    {
        caddr_t ifcu_buf;
        struct ifreq *ifcu_req;
    } ifc_ifcu;

#define ifc_buf ifc_ifcu.ifcu_buf
#define ifc_req ifc_ifcu.ifcu_req
};

struct ifaddr
{
    struct ifaddr *ifa_next;
    struct ifnet *ifa_ifp;
    struct sockaddr *ifa_addr;
    struct sockaddr *ifa_dstaddr;
#define ifa_broadaddr ifa_dstaddr
    struct sockaddr *ifa_netmask;
    void(*ifa_rtrequest)();
    u_short ifa_flags;
    short ifa_refcnt;
    int ifa_metric;
};

#define IFAFREE(ifa)    \
    if((ifa)->ifa_refcnt <= 0) \
        ifafree(ifa);   \
    else    \
       (ifa)->ifa_refcnt--;


#define IF_QFULL(ifq)   \
(   \
	(ifq)->ifq_len >= (ifq)->ifq_maxlen    \
)

#define IF_DROP(ifq)    \
{   \
	(ifq)->ifq_drops++; \
}

#define IF_ENQUEUE(ifq, m)  \
{   \
    if ((ifq)->ifq_len == 0)    \
    {   \
        (m)->m_nextpkt = NULL;  \
        (ifq)->ifq_head = (m);  \
    }   \
    else    \
    {   \
        (m)->m_nextpkt = (ifq)->ifq_tail->m_nextpkt; \
        (ifq)->ifq_tail->m_nextpkt = (m); \
    }   \
    (ifq)->ifq_tail = (m);  \
	(ifq)->ifq_len++;   \
}

#define IF_PREPEND(ifq, m)  \
{   \
    if ((ifq)->ifq_head == NULL)    \
    {   \
        IF_ENQUEUE(ifq, m)    \
    }   \
    else    \
    {   \
        (m)->m_nextpkt = (ifq)->ifq_head; \
        (ifq)->ifq_head = m;    \
        (ifq)->ifq_len++;   \
    }   \
}

#define IF_DEQUEUE(ifq, m)  \
{   \
	(m) = NULL;   \
	if((ifq)->ifq_len > 0) \
    { \
        (m) = (ifq)->ifq_head;    \
        (ifq)->ifq_head = (ifq)->ifq_head->m_nextpkt;   \
        (ifq)->ifq_len--;   \
    } \
}

#define	IFQ_MAXLEN	50
#define	IFNET_SLOWHZ	1		/* granularity is 1 second */

void	ether_ifattach(struct ifnet *);
void	ether_input(struct ifnet *, struct ether_header *, struct mbuf *);
int	    ether_output(struct ifnet *,
	   struct mbuf *, struct sockaddr *, struct rtentry *);
char	*ether_sprintf(u_char *);

void	if_attach(struct ifnet *);
void	if_down(struct ifnet *);
void	if_qflush(struct ifqueue *);
void	if_slowtimo(void *);
void	if_up(struct ifnet *);
void	ifubareset(int);
int	ifconf(int, caddr_t);
void	ifinit(void);
int	ifioctl(struct socket *, int, caddr_t, struct proc *);
int	ifpromisc(struct ifnet *, int);
struct	ifnet *ifunit(char *);

struct	ifaddr *ifa_ifwithaddr(struct sockaddr *);
struct	ifaddr *ifa_ifwithaf(int);
struct	ifaddr *ifa_ifwithdstaddr(struct sockaddr *);
struct	ifaddr *ifa_ifwithnet(struct sockaddr *);
struct	ifaddr *ifa_ifwithroute(int, struct sockaddr *,
					struct sockaddr *);
struct	ifaddr *ifaof_ifpforaddr(struct sockaddr *, struct ifnet *);
void	ifafree(struct ifaddr *);
void	link_rtrequest(int, struct rtentry *, struct sockaddr *);

int	loioctl(struct ifnet *, int, caddr_t);
void	loopattach(int);
int	looutput(struct ifnet *,
	   struct mbuf *, struct sockaddr *, struct rtentry *);
void	lortrequest(int, struct rtentry *, struct sockaddr *);


#endif  // NET_IF_H
