#include "../sys/param.h"
#include "../sys/systm.h"
#include "../sys/malloc.h"
#include "../sys/mbuf.h"
#include "../sys/socket.h"
#include "../sys/socketvar.h"
#include "../sys/protosw.h"
#include "../sys/errno.h"
#include "../sys/stat.h"

#include "../net/if.h"
#include "../net/route.h"

#include "in.h"
#include "in_systm.h"
#include "ip.h"
#include "in_pcb.h"
#include "ip_var.h"
#include "tcp.h"
#include "tcp_fsm.h"
#include "tcp_seq.h"
#include "tcp_timer.h"
#include "tcp_var.h"
#include "tcpip.h"
#include "tcp_debug.h"

/*
 * TCP protocol interface to socket abstraction.
 */
extern	char *tcpstates[];

/*
 * Process a TCP user request for TCP tb.  If this is a send request
 * then m is the mbuf chain of send data.  If this is a timer expiration
 * (called from the software clock routine), then timertype tells which timer.
 */
/*ARGSUSED*/
int
tcp_usrreq(so, req, m, nam, control)
	struct socket *so;
	int req;
	struct mbuf *m, *nam, *control;
{
    return 0;
}

int
tcp_ctloutput(op, so, level, optname, mp)
	int op;
	struct socket *so;
	int level, optname;
	struct mbuf **mp;
{
    return 0;
}

u_long	tcp_sendspace = 1024*8;
u_long	tcp_recvspace = 1024*8;

/*
 * Attach TCP protocol to socket, allocating
 * internet protocol control block, tcp control block,
 * bufer space, and entering LISTEN state if to accept connections.
 */
int
tcp_attach(so)
	struct socket *so;
{
    return 0;
}

/*
 * Initiate (or continue) disconnect.
 * If embryonic state, just send reset (once).
 * If in ``let data drain'' option and linger null, just drop.
 * Otherwise (hard), mark socket disconnecting and drop
 * current input data; switch states based on user close, and
 * send segment to peer (with FIN).
 */
struct tcpcb *
tcp_disconnect(tp)
	register struct tcpcb *tp;
{
    return NULL;
}

/*
 * User issued close, and wish to trail through shutdown states:
 * if never received SYN, just forget it.  If got a SYN from peer,
 * but haven't sent FIN, then go to FIN_WAIT_1 state to send peer a FIN.
 * If already got a FIN from peer, then almost done; go to LAST_ACK
 * state.  In all other cases, have already sent FIN to peer (e.g.
 * after PRU_SHUTDOWN), and just have to play tedious game waiting
 * for peer to send FIN or not respond to keep-alives, etc.
 * We can let the user exit from the close as soon as the FIN is acked.
 */
struct tcpcb *
tcp_usrclosed(tp)
	register struct tcpcb *tp;
{
    return NULL;
}
