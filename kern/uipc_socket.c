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
 *	@(#)uipc_socket.c	8.3 (Berkeley) 4/15/94
 */

#include "sys/param.h"
#include "sys/systm.h"
#include "sys/proc.h"
#include "sys/file.h"
#include "sys/malloc.h"
#include "sys/mbuf.h"
#include "sys/domain.h"
#include "sys/kernel.h"
#include "sys/protosw.h"
#include "sys/socket.h"
#include "sys/socketvar.h"
#include "sys/resourcevar.h"
#include "sys/errno.h"

/*
 * Socket operation routines.
 * These routines are called by the routines in
 * sys_socket.c or from a system process, and
 * implement the semantics of socket operations by
 * switching out to the protocol specific routines.
 */
/*ARGSUSED*/
socreate(dom, aso, type, proto)
	int dom;
	struct socket **aso;
	register int type;
	int proto;
{
    struct proc *proc = curproc;
    struct protosw *pp = NULL;
    if (proto != 0)
    {
        pp = pffindproto(PF_INET, proto, type);
    }
    else
    {
        pp = pffindtype(PF_INET, type);
    }
    if (!pp)
    {
        return 0;
    }

    struct socket *s = malloc(sizeof (*s));
    if (s == NULL)
        return ENOBUFS;

    memset(s, 0, sizeof(*s));

    if (proc->p_ucred->cr_uid > 0)
    {
        s->so_state |= SS_PRIV;
    }

    pp->pr_usrreq(s, PRU_ATTACH,
        (struct mbuf *)NULL,
        (struct mbuf *)proto, 
        (struct mbuf *)NULL);

    return 0;
}

sobind(so, nam)
	struct socket *so;
	struct mbuf *nam;
{
    so->so_proto->pr_usrreq(so, PRU_BIND, NULL, nam, NULL);

    return 0;
}

solisten(so, backlog)
	register struct socket *so;
	int backlog;
{
    int error = 0;

    error = so->so_proto->pr_usrreq(so, PRU_LISTEN, NULL, NULL, NULL);
    if (so->so_q == NULL)
        so->so_state |= SO_ACCEPTCONN;

    backlog = max(0, backlog);
    so->so_qlimit = min(backlog, SOMAXCONN);

    return 0;
}

sofree(so)
	register struct socket *so;
{
    return 0;
}

/*
 * Close a socket on last file table reference removal.
 * Initiate disconnect if connected.
 * Free socket when disconnect complete.
 */
soclose(so)
	register struct socket *so;
{
    return 0;
}

/*
 * Must be called at splnet...
 */
soabort(so)
	struct socket *so;
{
    return 0;
}

soaccept(so, nam)
	register struct socket *so;
	struct mbuf *nam;
{
    if ((so->so_state & SS_NOFDREF) == 0)
        return 0;

    return (so->so_proto->pr_usrreq)(so, PRU_ACCEPT,
        NULL, mtod(nam, struct sockaddr*), NULL);
}

soconnect(so, nam)
	register struct socket *so;
	struct mbuf *nam;
{
    return 0;
}

soconnect2(so1, so2)
	register struct socket *so1;
	struct socket *so2;
{
    return 0;
}

sodisconnect(so)
	register struct socket *so;
{
    return 0;
}

#define	SBLOCKWAIT(f)	(((f) & MSG_DONTWAIT) ? M_NOWAIT : M_WAITOK)
/*
 * Send on a socket.
 * If send must go all at once and message is larger than
 * send buffering, then hard error.
 * Lock against other senders.
 * If must go all at once and not enough room now, then
 * inform user that this would block and do nothing.
 * Otherwise, if nonblocking, send as much as possible.
 * The data to be sent is described by "uio" if nonzero,
 * otherwise by the mbuf chain "top" (which must be null
 * if uio is not).  Data provided in mbuf chain must be small
 * enough to send all at once.
 *
 * Returns nonzero on error, timeout or signal; callers
 * must check for short counts if EINTR/ERESTART are returned.
 * Data and control buffers are freed on return.
 */
sosend(so, addr, uio, top, control, flags)
	register struct socket *so;
	struct mbuf *addr;
	struct uio *uio;
	struct mbuf *top;
	struct mbuf *control;
	int flags;
{
    return 0;
}

/*
 * Implement receive operations on a socket.
 * We depend on the way that records are added to the sockbuf
 * by sbappend*.  In particular, each record (mbufs linked through m_next)
 * must begin with an address if the protocol so specifies,
 * followed by an optional mbuf or mbufs containing ancillary data,
 * and then zero or more mbufs of data.
 * In order to avoid blocking network interrupts for the entire time here,
 * we splx() while doing the actual copy to user space.
 * Although the sockbuf is locked, new data may still be appended,
 * and thus we must maintain consistency of the sockbuf during that time.
 *
 * The caller may receive the data as a single mbuf chain by supplying
 * an mbuf **mp0 for use in returning the chain.  The uio is then used
 * only for the count in uio_resid.
 */
soreceive(so, paddr, uio, mp0, controlp, flagsp)
	register struct socket *so;
	struct mbuf **paddr;
	struct uio *uio;
	struct mbuf **mp0;
	struct mbuf **controlp;
	int *flagsp;
{
    return 0;
}

soshutdown(so, how)
	register struct socket *so;
	register int how;
{
    return 0;
}

sorflush(so)
	register struct socket *so;
{
    return 0;
}

sosetopt(so, level, optname, m0)
	register struct socket *so;
	int level, optname;
	struct mbuf *m0;
{
    return 0;
}

sogetopt(so, level, optname, mp)
	register struct socket *so;
	int level, optname;
	struct mbuf **mp;
{
    return 0;
}

sohasoutofband(so)
	register struct socket *so;
{
    return 0;
}
