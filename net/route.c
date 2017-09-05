#include "../sys/mbuf.h"
#include "../sys/socket.h"
/*#include "../sys/socketvar.h"*/
#include "../sys/domain.h"
#include "../sys/protosw.h"
/*#include "../sys/ioctl.h"*/

#include "if.h"
#include "route.h"
/*#include "raw_cb.h"*/

#include "../netinet/in.h"
#include "../netinet/in_var.h"


/*#include <sys/param.h>*/
/*#include <sys/systm.h>*/
/*#include <sys/proc.h>*/
/*#include <sys/mbuf.h>*/
/*#include <sys/socket.h>*/
/*#include <sys/socketvar.h>*/
/*#include <sys/domain.h>*/
/*#include <sys/protosw.h>*/
/*#include <sys/ioctl.h>*/

/*#include <net/if.h>*/
/*#include <net/route.h>*/
/*#include <net/raw_cb.h>*/

/*#include <netinet/in.h>*/
/*#include <netinet/in_var.h>*/

/*#ifdef NS*/
/*#include <netns/ns.h>*/
/*#endif*/

#define	SA(p) ((struct sockaddr *)(p))

int	rttrash;		/* routes not in table but not freed */
struct	sockaddr wildcard;	/* zero valued cookie for wildcard searches */

void
rtable_init(table)
	void **table;
{
}

void
route_init()
{
}

/*
 * Packet routing routines.
 */
void
rtalloc(ro)
	struct route *ro;
{
}

struct rtentry *
rtalloc1(dst, report)
	struct sockaddr *dst;
	int report;
{
    return NULL;
}

void
rtfree(rt)
	register struct rtentry *rt;
{
}

void
ifafree(ifa)
	register struct ifaddr *ifa;
{
}

/*
 * Force a routing table entry to the specified
 * destination to go through the given gateway.
 * Normally called as a result of a routing redirect
 * message from the network layer.
 *
 * N.B.: must be called at splnet
 *
 */
int
rtredirect(dst, gateway, netmask, flags, src, rtp)
	struct sockaddr *dst, *gateway, *netmask, *src;
	int flags;
	struct rtentry **rtp;
{
    return 0;
}

/*
* Routing table ioctl interface.
*/
int
rtioctl(req, data, p)
	int req;
	caddr_t data;
	struct proc *p;
{
    return 0;
}

struct ifaddr *
ifa_ifwithroute(int flags, struct sockaddr *dst, struct sockaddr *gateway)
{
    extern struct ifnet *ifnet;
    struct ifnet *ifp = NULL;
    struct ifaddr *ifa = NULL;

    for (ifp = ifnet; ifp; ifp = ifp->if_next)
    {
        for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
        {
            //if ()
            //{
            //    return ifa;
            //}
        }
    }

    return NULL;
}

#define ROUNDUP(a) (a>0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

int
rtrequest(req, dst, gateway, netmask, flags, ret_nrt)
	int req, flags;
	struct sockaddr *dst, *gateway, *netmask;
	struct rtentry **ret_nrt;
{
    return 0;
}

int
rt_setgate(rt0, dst, gate)
	struct rtentry *rt0;
	struct sockaddr *dst, *gate;
{
    return 0;
}

void
rt_maskedcopy(src, dst, netmask)
	struct sockaddr *src, *dst, *netmask;
{
}

/*
 * Set up a routing table entry, normally
 * for an interface.
 */
int
rtinit(ifa, cmd, flags)
	register struct ifaddr *ifa;
	int cmd, flags;
{
    return 0;
}

void rt_ifmsg(struct ifnet *ifp)
{
}
