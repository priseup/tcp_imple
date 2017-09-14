#include "../sys/param.h"
#include "../sys/malloc.h"
#include "../sys/mbuf.h"
#include "../sys/socket.h"
#include "../sys/protosw.h"
#include "../sys/socketvar.h"
#include "../sys/errno.h"
#include "../sys/systm.h"

#include "../net/if.h"
#include "../net/route.h"

#include "in.h"
#include "in_systm.h"
#include "ip.h"
#include "ip_var.h"
#include "ip_mroute.h"
#include "in_pcb.h"

struct inpcb rawinpcb;

/*
 * Nominal space allocated to a raw ip socket.
 */
#define	RIPSNDQ		8192
#define	RIPRCVQ		8192

/*
 * Raw interface to IP protocol.
 */

/*
 * Initialize raw connection block q.
 */
void
rip_init()
{
}

struct	sockaddr_in ripsrc = { sizeof(ripsrc), AF_INET };
/*
 * Setup generic address and protocol structures
 * for raw_input routine, then pass them along with
 * mbuf chain.
 */
void
rip_input(m)
	struct mbuf *m;
{
}

/*
 * Generate IP header and pass packet to ip_output.
 * Tack on options user may have setup with control call.
 */
int
rip_output(m, so, dst)
	register struct mbuf *m;
	struct socket *so;
	u_long dst;
{
}

/*
 * Raw IP socket option processing.
 */
int
rip_ctloutput(op, so, level, optname, m)
	int op;
	struct socket *so;
	int level, optname;
	struct mbuf **m;
{
}

u_long	rip_sendspace = RIPSNDQ;
u_long	rip_recvspace = RIPRCVQ;

/*ARGSUSED*/
int
rip_usrreq(so, req, m, nam, control)
	register struct socket *so;
	int req;
	struct mbuf *m, *nam, *control;
{
}
