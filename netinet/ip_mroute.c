/*
 * Procedures for the kernel part of DVMRP,
 * a Distance-Vector Multicast Routing Protocol.
 * (See RFC-1075.)
 *
 * Written by David Waitzman, BBN Labs, August 1988.
 * Modified by Steve Deering, Stanford, February 1989.
 *
 * MROUTING 1.1
 */

#ifndef MROUTING
int	ip_mrtproto;				/* for netstat only */
#else

#include "../sys/param.h"
#include "../sys/errno.h"
#include "../sys/ioctl.h"
#include "../sys/malloc.h"
#include "../sys/mbuf.h"
#include "../sys/protosw.h"
#include "../sys/socket.h"
#include "../sys/socketvar.h"
#include "../sys/time.h"

#include "../net/if.h"
#include "../net/route.h"
#include "../net/raw_cb.h"

#include "in.h"
#include "in_systm.h"
#include "ip.h"
#include "in_pcb.h"
#include "in_var.h"
#include "ip_var.h"

#include "igmp.h"
#include "igmp_var.h"
#include "ip_mroute.h"

/* Static forwards */
static	int ip_mrouter_init __P((struct socket *));
static	int add_vif __P((struct vifctl *));
static	int del_vif __P((vifi_t *vifip));
static	int add_lgrp __P((struct lgrplctl *));
static	int del_lgrp __P((struct lgrplctl *));
static	int grplst_member __P((struct vif *, struct in_addr));
static	u_long nethash __P((struct in_addr in));
static	int add_mrt __P((struct mrtctl *));
static	int del_mrt __P((struct in_addr *));
static	struct mrt *mrtfind __P((struct in_addr));
static	void phyint_send __P((struct mbuf *, struct vif *));
static	void tunnel_send __P((struct mbuf *, struct vif *));

#define INSIZ sizeof(struct in_addr)
#define	same(a1, a2) (bcmp((caddr_t)(a1), (caddr_t)(a2), INSIZ) == 0)
#define	satosin(sa)	((struct sockaddr_in *)(sa))

/*
 * Globals.  All but ip_mrouter and ip_mrtproto could be static,
 * except for netstat or debugging purposes.
 */
struct	socket *ip_mrouter = NULL;
int	ip_mrtproto = IGMP_DVMRP;		/* for netstat only */

struct	mrt *mrttable[MRTHASHSIZ];
struct	vif viftable[MAXVIFS];
struct	mrtstat	mrtstat;

/*
 * Private variables.
 */
static	vifi_t numvifs = 0;
static	struct mrt *cached_mrt = NULL;
static	u_long cached_origin;
static	u_long cached_originmask;

/*
 * Handle DVMRP setsockopt commands to modify the multicast routing tables.
 */
int
ip_mrouter_cmd(cmd, so, m)
	register int cmd;
	register struct socket *so;
	register struct mbuf *m;
{
    return 0;
}

/*
 * Enable multicast routing
 */
static int
ip_mrouter_init(so)
	register struct socket *so;
{
    return 0;
}

/*
 * Disable multicast routing
 */
int
ip_mrouter_done()
{
    return 0;
}

/*
 * Add a vif to the vif table
 */
static int
add_vif(vifcp)
	register struct vifctl *vifcp;
{
    return 0;
}

/*
 * Delete a vif from the vif table
 */
static int
del_vif(vifip)
	register vifi_t *vifip;
{
    return 0;
}

/*
 * Add the multicast group in the lgrpctl to the list of local multicast
 * group memberships associated with the vif indexed by gcp->lgc_vifi.
 */
static int
add_lgrp(gcp)
	register struct lgrplctl *gcp;
{
    return 0;
}

/*
 * Delete the the local multicast group associated with the vif
 * indexed by gcp->lgc_vifi.
 */

static int
del_lgrp(gcp)
	register struct lgrplctl *gcp;
{
    return 0;
}

/*
 * Return 1 if gaddr is a member of the local group list for vifp.
 */
static int
grplst_member(vifp, gaddr)
	register struct vif *vifp;
	struct in_addr gaddr;
{
    return 0;
}

/*
 * A simple hash function: returns MRTHASHMOD of the low-order octet of
 * the argument's network or subnet number.
 */
static u_long
nethash(in)
	struct in_addr in;
{
    return 0;
}

/*
 * Add an mrt entry
 */
static int
add_mrt(mrtcp)
	register struct mrtctl *mrtcp;
{
    return 0;
}

/*
 * Delete an mrt entry
 */
static int
del_mrt(origin)
	register struct in_addr *origin;
{
    return 0;
}

/*
 * Find a route for a given origin IP address.
 */
static struct mrt *
mrtfind(origin)
	struct in_addr origin;
{
    return NULL;
}

/*
 * IP multicast forwarding function. This function assumes that the packet
 * pointed to by "ip" has arrived on (or is about to be sent to) the interface
 * pointed to by "ifp", and the packet is to be relayed to other networks
 * that have members of the packet's destination IP multicast group.
 *
 * The packet is returned unscathed to the caller, unless it is tunneled
 * or erroneous, in which case a non-zero return value tells the caller to
 * discard it.
 */

#define IP_HDR_LEN  20	/* # bytes of fixed IP header (excluding options) */
#define TUNNEL_LEN  12  /* # bytes of IP option for tunnel encapsulation  */

int
ip_mforward(m, ifp)
	register struct mbuf *m;
	register struct ifnet *ifp;
{
    return 0;
}

static void
phyint_send(m, vifp)
	register struct mbuf *m;
	register struct vif *vifp;
{
}

static void
tunnel_send(m, vifp)
	register struct mbuf *m;
	register struct vif *vifp;
{
}
#endif
