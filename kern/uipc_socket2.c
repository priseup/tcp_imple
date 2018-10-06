/*
 * Copyright (c) 1982, 1986, 1988, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)uipc_socket2.c	8.1 (Berkeley) 6/10/93
 */

#include "sys/param.h"
#include "sys/systm.h"
#include "sys/proc.h"
#include "sys/file.h"
#include "sys/buf.h"
#include "sys/malloc.h"
#include "sys/mbuf.h"
#include "sys/protosw.h"
#include "sys/socket.h"
#include "sys/socketvar.h"
#include "sys/errno.h"

/*
 * Primitive routines for operating on sockets and socket buffers
 */

/* strings for sleep message: */
char	netio[] = "netio";
char	netcon[] = "netcon";
char	netcls[] = "netcls";

u_long	sb_max = SB_MAX;		/* patchable */

/*
 * Procedures to manipulate state flags of socket
 * and do appropriate wakeups.  Normal sequence from the
 * active (originating) side is that soisconnecting() is
 * called during processing of connect() call,
 * resulting in an eventual call to soisconnected() if/when the
 * connection is established.  When the connection is torn down
 * soisdisconnecting() is called during processing of disconnect() call,
 * and soisdisconnected() is called when the connection to the peer
 * is totally severed.  The semantics of these routines are such that
 * connectionless protocols can call soisconnected() and soisdisconnected()
 * only, bypassing the in-progress calls when setting up a ``connection''
 * takes no time.
 *
 * From the passive side, a socket is created with
 * two queues of sockets: so_q0 for connections in progress
 * and so_q for connections already made and awaiting user acceptance.
 * As a protocol is preparing incoming connections, it creates a socket
 * structure queued on so_q0 by calling sonewconn().  When the connection
 * is established, soisconnected() is called, and transfers the
 * socket structure to so_q, making it available to accept().
 * 
 * If a socket is closed with sockets on either
 * so_q0 or so_q, these sockets are dropped.
 *
 * If higher level protocols are implemented in
 * the kernel, the wakeups done here will sometimes
 * cause software-interrupt process scheduling.
 */

soisconnecting(so)
	register struct socket *so;
{
}

soisconnected(so)
	register struct socket *so;
{
    struct socket *head = so->so_head;
    if (head && soqremque(so))
    {
        sorwakeup(so);
    }

    if (!head && !soqremque(so))
    {
        int channel = 0;
        wakeup(&channel);
        sorwakeup(so);
        sowwakeup(so);
    }

}

soisdisconnecting(so)
	register struct socket *so;
{
}

soisdisconnected(so)
	register struct socket *so;
{
}

/*
 * When an attempt at a new connection is noted on a socket
 * which accepts connections, sonewconn is called.  If the
 * connection is possible (subject to space constraints, etc.)
 * then we allocate a new structure, propoerly linked into the
 * data structure of the original socket, and return this.
 * Connstatus may be 0, or SO_ISCONFIRMING, or SO_ISCONNECTED.
 *
 * Currently, sonewconn() is defined as sonewconn1() in socketvar.h
 * to catch calls that are missing the (new) second parameter.
 */
struct socket *
sonewconn1(head, connstatus)
	register struct socket *head;
	int connstatus;
{
    int soqueue = connstatus ? 1 : 0;
    int error = 0;

    if (2 * (head->so_qlen + head->so_q0len) >
        3 * head->so_qlimit)
        return NULL;

    struct socket *so = malloc(sizeof (*so));
    memset(so, 0, sizeof (*so));
    so->so_options = head->so_options;
    so->so_linger = head->so_linger;
    so->so_pgid = head->so_pgid;
    //so->sb_hiwat = head->sb_hiwat;
    soqinsque(head, so, soqueue);
    if (error = (so->so_proto->pr_usrreq)(so, PRU_ATTACH,
        NULL, so, NULL))
    {
        soqremque(so, soqueue);
        return NULL;
    }

    if (connstatus)
    {
        sorwakeup(so);
        so->so_state |= connstatus;
    }
    else
    {
    }

	return (so);
}

soqinsque(head, so, q)
	register struct socket *head, *so;
	int q;
{
}

soqremque(so, q)
	register struct socket *so;
	int q;
{
	return (1);
}

/*
 * Socantsendmore indicates that no more data will be sent on the
 * socket; it would normally be applied to a socket when the user
 * informs the system that no more data is to be sent, by the protocol
 * code (in case PRU_SHUTDOWN).  Socantrcvmore indicates that no more data
 * will be received, and will normally be applied to the socket by a
 * protocol when it detects that the peer will send no more data.
 * Data queued for reading in the socket may yet be read.
 */

socantsendmore(so)
	struct socket *so;
{
}

socantrcvmore(so)
	struct socket *so;
{
}

/*
 * Wait for data to arrive at/drain from a socket buffer.
 */
sbwait(sb)
	struct sockbuf *sb;
{
}

/* 
 * Lock a sockbuf already known to be locked;
 * return any error returned from sleep (EINTR).
 */
sb_lock(sb)
	register struct sockbuf *sb;
{
    return 0;
}

/*
 * Wakeup processes waiting on a socket buffer.
 * Do asynchronous notification via SIGIO
 * if the socket has the SS_ASYNC flag set.
 */
sowakeup(so, sb)
	register struct socket *so;
	register struct sockbuf *sb;
{
}

/*
 * Socket buffer (struct sockbuf) utility routines.
 *
 * Each socket contains two socket buffers: one for sending data and
 * one for receiving data.  Each buffer contains a queue of mbufs,
 * information about the number of mbufs and amount of data in the
 * queue, and other fields allowing select() statements and notification
 * on data availability to be implemented.
 *
 * Data stored in a socket buffer is maintained as a list of records.
 * Each record is a list of mbufs chained together with the m_next
 * field.  Records are chained together with the m_nextpkt field. The upper
 * level routine soreceive() expects the following conventions to be
 * observed when placing information in the receive buffer:
 *
 * 1. If the protocol requires each message be preceded by the sender's
 *    name, then a record containing that name must be present before
 *    any associated data (mbuf's must be of type MT_SONAME).
 * 2. If the protocol supports the exchange of ``access rights'' (really
 *    just additional data associated with the message), and there are
 *    ``rights'' to be received, then a record containing this data
 *    should be present (mbuf's must be of type MT_RIGHTS).
 * 3. If a name or rights record exists, then it must be followed by
 *    a data record, perhaps of zero length.
 *
 * Before using a new socket structure it is first necessary to reserve
 * buffer space to the socket, by calling sbreserve().  This should commit
 * some of the available buffer space in the system buffer pool for the
 * socket (currently, it does nothing but enforce limits).  The space
 * should be released by calling sbrelease() when the socket is destroyed.
 */

soreserve(so, sndcc, rcvcc)
	register struct socket *so;
	u_long sndcc, rcvcc;
{
	return (ENOBUFS);
}

/*
 * Allot mbufs to a sockbuf.
 * Attempt to scale mbmax so that mbcnt doesn't become limiting
 * if buffering efficiency is near the normal case.
 */
sbreserve(sb, cc)
	struct sockbuf *sb;
	u_long cc;
{
    return 0;
}

/*
 * Free mbufs held by a socket, and reserved mbuf space.
 */
sbrelease(sb)
	struct sockbuf *sb;
{
}

/*
 * Routines to add and remove
 * data from an mbuf queue.
 *
 * The routines sbappend() or sbappendrecord() are normally called to
 * append new mbufs to a socket buffer, after checking that adequate
 * space is available, comparing the function sbspace() with the amount
 * of data to be added.  sbappendrecord() differs from sbappend() in
 * that data supplied is treated as the beginning of a new record.
 * To place a sender's address, optional access rights, and data in a
 * socket receive buffer, sbappendaddr() should be used.  To place
 * access rights and data in a socket receive buffer, sbappendrights()
 * should be used.  In either case, the new data begins a new record.
 * Note that unlike sbappend() and sbappendrecord(), these routines check
 * for the caller that there will be enough space to store the data.
 * Each fails if there is not enough space, or if it cannot find mbufs
 * to store additional information in.
 *
 * Reliable protocols may use the socket send buffer to hold data
 * awaiting acknowledgement.  Data is normally copied from a socket
 * send buffer in a protocol with m_copy for output to a peer,
 * and then removing the data from the socket buffer with sbdrop()
 * or sbdroprecord() when the data is acknowledged by the peer.
 */

/*
 * Append mbuf chain m to the last record in the
 * socket buffer sb.  The additional space associated
 * the mbuf chain is recorded in sb.  Empty mbufs are
 * discarded and mbufs are compacted where possible.
 */
sbappend(sb, m)
	struct sockbuf *sb;
	struct mbuf *m;
{
}

#ifdef SOCKBUF_DEBUG
sbcheck(sb)
	register struct sockbuf *sb;
{
}
#endif

/*
 * As above, except the mbuf chain
 * begins a new record.
 */
sbappendrecord(sb, m0)
	register struct sockbuf *sb;
	register struct mbuf *m0;
{
}

/*
 * As above except that OOB data
 * is inserted at the beginning of the sockbuf,
 * but after any other OOB data.
 */
sbinsertoob(sb, m0)
	register struct sockbuf *sb;
	register struct mbuf *m0;
{
}

/*
 * Append address and data, and optionally, control (ancillary) data
 * to the receive queue of a socket.  If present,
 * m0 must include a packet header with total length.
 * Returns 0 if no space in sockbuf or insufficient mbufs.
 */
sbappendaddr(sb, asa, m0, control)
	register struct sockbuf *sb;
	struct sockaddr *asa;
	struct mbuf *m0, *control;
{
    return 0;
}

sbappendcontrol(sb, m0, control)
	struct sockbuf *sb;
	struct mbuf *control, *m0;
{
    return 0;
}

/*
 * Compress mbuf chain m into the socket
 * buffer sb following mbuf n.  If n
 * is null, the buffer is presumed empty.
 */
sbcompress(sb, m, n)
	register struct sockbuf *sb;
	register struct mbuf *m, *n;
{
}

/*
 * Free all mbufs in a sockbuf.
 * Check that all resources are reclaimed.
 */
sbflush(sb)
	register struct sockbuf *sb;
{
}

/*
 * Drop data from (the front of) a sockbuf.
 */
sbdrop(sb, len)
	register struct sockbuf *sb;
	register int len;
{
}

/*
 * Drop a record off the front of a sockbuf
 * and move the next record to the front.
 */
sbdroprecord(sb)
	register struct sockbuf *sb;
{
}
