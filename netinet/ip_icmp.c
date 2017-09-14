#include "../sys/param.h"
#include "../sys/systm.h"
#include "../sys/malloc.h"
#include "../sys/mbuf.h"
#include "../sys/protosw.h"
#include "../sys/socket.h"
#include "../sys/time.h"
#include "../sys/kernel.h"

#include "../net/if.h"
#include "../net/route.h"

#include "in.h"
#include "in_systm.h"
#include "in_var.h"
#include "ip.h"
#include "ip_icmp.h"
#include "icmp_var.h"

/*
 * ICMP routines: error generation, receive packet processing, and
 * routines to turnaround packets back to the originator, and
 * host table maintenance routines.
 */

int	icmpmaskrepl = 0;
#ifdef ICMPPRINTFS
int	icmpprintfs = 0;
#endif

extern	struct protosw inetsw[];

/*
 * Generate an error packet of type error
 * in response to bad packet ip.
 */
void
icmp_error(n, type, code, dest, destifp)
	struct mbuf *n;
	int type, code;
	n_long dest;
	struct ifnet *destifp;
{
}

static struct sockaddr_in icmpsrc = { sizeof (struct sockaddr_in), AF_INET };
static struct sockaddr_in icmpdst = { sizeof (struct sockaddr_in), AF_INET };
static struct sockaddr_in icmpgw = { sizeof (struct sockaddr_in), AF_INET };
struct sockaddr_in icmpmask = { 8, 0 };

/*
 * Process a received ICMP message.
 */
void
icmp_input(m, hlen)
	register struct mbuf *m;
	int hlen;
{
}

/*
 * Reflect the ip packet back to the source
 */
void
icmp_reflect(m)
	struct mbuf *m;
{
}

/*
 * Send an icmp packet back to the ip level,
 * after supplying a checksum.
 */
void
icmp_send(m, opts)
	register struct mbuf *m;
	struct mbuf *opts;
{
}

n_time
iptime()
{
    return 0;
}

int
icmp_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
{
    return 0;
}
