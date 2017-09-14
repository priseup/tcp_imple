#include "../sys/param.h"
#include "../sys/malloc.h"
#include "../sys/mbuf.h"
#include "../sys/protosw.h"
#include "../sys/socket.h"
#include "../sys/socketvar.h"
#include "../sys/errno.h"
#include "../sys/stat.h"

#include "../net/if.h"
#include "../net/route.h"

#include "in.h"
#include "in_systm.h"
#include "ip.h"
#include "in_pcb.h"
#include "ip_var.h"
#include "ip_icmp.h"
#include "udp.h"
#include "udp_var.h"

/*
 * UDP protocol implementation.
 * Per RFC 768, August, 1980.
 */
#ifndef	COMPAT_42
int	udpcksum = 1;
#else
int	udpcksum = 0;		/* XXX */
#endif

struct	sockaddr_in udp_in = { sizeof(udp_in), AF_INET };
struct	inpcb *udp_last_inpcb = &udb;

static	void udp_detach __P((struct inpcb *));
static	void udp_notify __P((struct inpcb *, int));
static	struct mbuf *udp_saveopt __P((caddr_t, int, int));

void
udp_init()
{
}

void
udp_input(m, iphlen)
	register struct mbuf *m;
	int iphlen;
{
}

/*
 * Create a "control" mbuf containing the specified data
 * with the specified type for presentation with a datagram.
 */
struct mbuf *
udp_saveopt(p, size, type)
	caddr_t p;
	register int size;
	int type;
{
    return NULL;
}

/*
 * Notify a udp user of an asynchronous error;
 * just wake up so that he can collect error status.
 */
static void
udp_notify(inp, err)
	register struct inpcb *inp;
	int err;
{
}

void
udp_ctlinput(cmd, sa, ip)
	int cmd;
	struct sockaddr *sa;
	register struct ip *ip;
{
}

int
udp_output(inp, m, addr, control)
	register struct inpcb *inp;
	register struct mbuf *m;
	struct mbuf *addr, *control;
{
    return 0;
}

u_long	udp_sendspace = 9216;		/* really max datagram size */
u_long	udp_recvspace = 40 * (1024 + sizeof(struct sockaddr_in));
					/* 40 1K datagrams */

/*ARGSUSED*/
int
udp_usrreq(so, req, m, addr, control)
	struct socket *so;
	int req;
	struct mbuf *m, *addr, *control;
{
    return 0;
}

static void
udp_detach(inp)
	struct inpcb *inp;
{
}

/*
 * Sysctl for udp variables.
 */
udp_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
{
    return 0;
}
