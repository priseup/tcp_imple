#include "../sys/param.h"
#include "../sys/malloc.h"
#include "../sys/mbuf.h"
#include "../sys/errno.h"
#include "../sys/protosw.h"
#include "../sys/socket.h"
#include "../sys/socketvar.h"

#include "../net/if.h"
#include "../net/route.h"

#include "in.h"
#include "in_systm.h"
#include "ip.h"
#include "in_pcb.h"
#include "in_var.h"
#include "ip_var.h"

#ifdef vax
#include <machine/mtpr.h>
#endif

static struct mbuf *ip_insertoptions __P((struct mbuf *, struct mbuf *, int *));
static void ip_mloopback
	__P((struct ifnet *, struct mbuf *, struct sockaddr_in *));

/*
 * IP output.  The packet in mbuf chain m contains a skeletal IP
 * header (with len, off, ttl, proto, tos, src, dst).
 * The mbuf chain containing the packet will be freed.
 * The mbuf opt, if present, will not be freed.
 */
int
ip_output(m0, opt, ro, flags, imo)
	struct mbuf *m0;
	struct mbuf *opt;
	struct route *ro;
	int flags;
	struct ip_moptions *imo;
{
    return 0;
}

/*
 * Insert IP options into preformed packet.
 * Adjust IP destination as required for IP source routing,
 * as indicated by a non-zero in_addr at the start of the options.
 */
static struct mbuf *
ip_insertoptions(m, opt, phlen)
	register struct mbuf *m;
	struct mbuf *opt;
	int *phlen;
{
    return NULL;
}

/*
 * Copy options from ip to jp,
 * omitting those not copied during fragmentation.
 */
int
ip_optcopy(ip, jp)
	struct ip *ip, *jp;
{
    return 0;
}

/*
 * IP socket option processing.
 */
int
ip_ctloutput(op, so, level, optname, mp)
	int op;
	struct socket *so;
	int level, optname;
	struct mbuf **mp;
{
    return 0;
}

/*
 * Set up IP options in pcb for insertion in output packets.
 * Store in mbuf with pointer in pcbopt, adding pseudo-option
 * with destination address if source routed.
 */
int
#ifdef notyet
ip_pcbopts(optname, pcbopt, m)
	int optname;
#else
ip_pcbopts(pcbopt, m)
#endif
	struct mbuf **pcbopt;
	register struct mbuf *m;
{
    return 0;
}

/*
 * Set the IP multicast options in response to user setsockopt().
 */
int
ip_setmoptions(optname, imop, m)
	int optname;
	struct ip_moptions **imop;
	struct mbuf *m;
{
    return 0;
}

/*
 * Return the IP multicast options in response to user getsockopt().
 */
int
ip_getmoptions(optname, imo, mp)
	int optname;
	register struct ip_moptions *imo;
	register struct mbuf **mp;
{
    return 0;
}

/*
 * Discard the IP multicast options.
 */
void
ip_freemoptions(imo)
	register struct ip_moptions *imo;
{
    return 0;
}

/*
 * Routine called from ip_output() to loop back a copy of an IP multicast
 * packet to the input queue of a specified interface.  Note that this
 * calls the output routine of the loopback "driver", but with an interface
 * pointer that might NOT be &loif -- easier than replicating that code here.
 */
static void
ip_mloopback(ifp, m, dst)
	struct ifnet *ifp;
	register struct mbuf *m;
	register struct sockaddr_in *dst;
{
    return 0;
}
