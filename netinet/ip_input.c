#include "../sys/socket.h"
#include "../sys/errno.h"
#include "../sys/time.h"
#include "../sys/kernel.h"

#include "../net/if.h"
#include "../net/route.h"

#include "in.h"
#include "in_systm.h"
#include "ip.h"
#include "in_var.h"
#include "ip_var.h"
#include "../sys/protosw.h"
#include "../sys/domain.h"

/*#include "ip_icmp.h"*/
/*#include "in_pcb.h"*/


/*#include <sys/param.h>*/
/*#include <sys/systm.h>*/
/*#include <sys/malloc.h>*/
/*#include <sys/mbuf.h>*/
/*#include <sys/domain.h>*/
/*#include <sys/protosw.h>*/
/*#include <sys/socket.h>*/
/*#include <sys/errno.h>*/
/*#include <sys/time.h>*/
/*#include <sys/kernel.h>*/

/*#include <net/if.h>*/
/*#include <net/route.h>*/

/*#include <netinet/in.h>*/
/*#include <netinet/in_systm.h>*/
/*#include <netinet/ip.h>*/
/*#include <netinet/in_pcb.h>*/
/*#include <netinet/in_var.h>*/
/*#include <netinet/ip_var.h>*/
/*#include <netinet/ip_icmp.h>*/

#ifndef	IPFORWARDING
#ifdef GATEWAY
#define	IPFORWARDING	1	/* forward IP packets not for us */
#else /* GATEWAY */
#define	IPFORWARDING	0	/* don't forward IP packets not for us */
#endif /* GATEWAY */
#endif /* IPFORWARDING */
#ifndef	IPSENDREDIRECTS
#define	IPSENDREDIRECTS	1
#endif
int	ipforwarding = IPFORWARDING;
int	ipsendredirects = IPSENDREDIRECTS;
int	ip_defttl = IPDEFTTL;
#ifdef DIAGNOSTIC
int	ipprintfs = 0;
#endif

extern  struct ipq	ipq;			/* ip reass. queue */
extern	struct domain inetdomain;
extern	struct protosw inetsw[];

u_char	ip_protox[IPPROTO_MAX];
int	ipqmaxlen = IFQ_MAXLEN;
struct	in_ifaddr *in_ifaddr;			/* first inet address */
struct	ifqueue ipintrq;
/*
 * We need to save the IP options in case a protocol wants to respond
 * to an incoming packet over the same route if the packet got here
 * using IP source routing.  This allows connection establishment and
 * maintenance when the remote end is on a network that is not known
 * to us.
 */
int	ip_nhops = 0;
static	struct ip_srcrt {
	struct	in_addr dst;			/* final destination */
	char	nop;				/* one NOP to align */
	char	srcopt[IPOPT_OFFSET + 1];	/* OPTVAL, OLEN and OFFSET */
	struct	in_addr route[MAX_IPOPTLEN/sizeof(struct in_addr)];
} ip_srcrt;

#ifndef GATEWAY
extern	int if_index;
u_long	*ip_ifmatrix;
#endif

static void save_rte __P((u_char *, struct in_addr));
/*
 * IP initialization: fill in IP protocol switch table.
 * All protocols not implemented in kernel go to raw IP protocol handler.
 */
void
ip_init()
{
    struct protosw *pr = pffindproto(PF_INET, IPPROTO_RAW, SOCK_RAW);
    if (pr == NULL)
        perror("canot find the protosw\n");

    for (int i = 0; i < IPPROTO_MAX; i++)
        ip_protox[i] = pr - inetdomain.dom_protosw;

    for (struct protosw *p = inetdomain.dom_protosw;
        p < inetdomain.dom_protoswNPROTOSW; p++)
    {
        if (p->pr_protocol != IPPROTO_RAW)
            ip_protox[p->pr_protocol] = p - inetdomain.dom_protosw;
    }

    ipq.ipq_prev = ipq.ipq_next = &ipq;
    ip_id = time.tv_sec & 0xffff;
    int i = (if_index + 1) * (if_index + 1) * sizeof(u_long);
    ip_ifmatrix = malloc(i);
    memset(ip_ifmatrix, 0, i);
  
    ipintrq.ifq_maxlen = ipqmaxlen;
}

struct	sockaddr_in ipaddr = { sizeof(ipaddr), AF_INET };
struct	route ipforward_rt;

/*
 * Ip input routine.  Checksum and byte swap header.  If fragmented
 * try to reassemble.  Process options.  Pass to next level.
 */
void
ipintr()
{
}

/*
 * Take incoming datagram fragment and try to
 * reassemble it into whole datagram.  If a chain for
 * reassembly of this datagram already exists, then it
 * is given as fp; otherwise have to make a chain.
 */
struct ip *
ip_reass(ip, fp)
	register struct ipasfrag *ip;
	register struct ipq *fp;
{
    return NULL;
}

/*
 * Free a fragment reassembly header and all
 * associated datagrams.
 */
void
ip_freef(fp)
	struct ipq *fp;
{
}

/*
 * Put an ip fragment on a reassembly chain.
 * Like insque, but pointers in middle of structure.
 */
void
ip_enq(p, prev)
	register struct ipasfrag *p, *prev;
{
}

/*
 * To ip_enq as remque is to insque.
 */
void
ip_deq(p)
	register struct ipasfrag *p;
{
}

/*
 * IP timer processing;
 * if a timer expires on a reassembly
 * queue, discard it.
 */
void
ip_slowtimo()
{

}

/*
 * Drain off all datagram fragments.
 */
void
ip_drain()
{

}

/*
 * Do option processing on a datagram,
 * possibly discarding it if bad options are encountered,
 * or forwarding it if source-routed.
 * Returns 1 if packet has been forwarded/freed,
 * 0 if the packet should be processed further.
 */
int
ip_dooptions(m)
	struct mbuf *m;
{
    return 0;
}

/*
 * Given address of next destination (final or next hop),
 * return internet address info of interface to be used to get there.
 */
struct in_ifaddr *
ip_rtaddr(dst)
	 struct in_addr dst;
{
    struct in_ifaddr *p = NULL;
    return p;
}

/*
 * Save incoming source route for use in replies,
 * to be picked up later by ip_srcroute if the receiver is interested.
 */
void
save_rte(option, dst)
	u_char *option;
	struct in_addr dst;
{

}

/*
 * Retrieve incoming source route for use in replies,
 * in the same form used by setsockopt.
 * The first hop is placed before the options, will be removed later.
 */
struct mbuf *
ip_srcroute()
{
    struct mbuf *m = NULL;
    return m;
}

/*
 * Strip out IP options, at higher
 * level protocol in the kernel.
 * Second argument is buffer to which options
 * will be moved, and return value is their length.
 * XXX should be deleted; last arg currently ignored.
 */
void
ip_stripoptions(m, mopt)
	register struct mbuf *m;
	struct mbuf *mopt;
{
    ;
}

u_char inetctlerrmap[PRC_NCMDS] = {
	0,		0,		0,		0,
	0,		EMSGSIZE,	EHOSTDOWN,	EHOSTUNREACH,
	EHOSTUNREACH,	EHOSTUNREACH,	ECONNREFUSED,	ECONNREFUSED,
	EMSGSIZE,	EHOSTUNREACH,	0,		0,
	0,		0,		0,		0,
	ENOPROTOOPT
};

/*
 * Forward a packet.  If some error occurs return the sender
 * an icmp packet.  Note we can't always generate a meaningful
 * icmp message because icmp doesn't have a large enough repertoire
 * of codes and types.
 *
 * If not forwarding, just drop the packet.  This could be confusing
 * if ipforwarding was zero but some routing protocol was advancing
 * us as a gateway to somewhere.  However, we must let the routing
 * protocol deal with that.
 *
 * The srcrt parameter indicates whether the packet is being forwarded
 * via a source route.
 */
void
ip_forward(m, srcrt)
	struct mbuf *m;
	int srcrt;
{
    ;
}

int
ip_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
{
    return 0;
}
