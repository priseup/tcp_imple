/*
 * Copyright (c) 1982, 1986, 1989, 1990, 1993
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
 *	@(#)uipc_syscalls.c	8.4 (Berkeley) 2/21/94
 */

#include "sys/param.h"
#include "sys/filedesc.h"
#include "sys/proc.h"
#include "sys/file.h"
#include "sys/buf.h"
#include "sys/malloc.h"
#include "sys/mbuf.h"
#include "sys/protosw.h"
#include "sys/socket.h"
#include "sys/socketvar.h"
#include "sys/errno.h"
#ifdef KTRACE
#include "sys/ktrace.h"
#endif

/*
 * System call interface to the socket abstraction.
 */
#if defined(COMPAT_43) || defined(COMPAT_SUNOS)
#define COMPAT_OLDSOCK
#endif

extern	struct fileops socketops;

struct socket_args {
	int	domain;
	int	type;
	int	protocol;
};
socket(p, uap, retval)
	struct proc *p;
	register struct socket_args *uap;
	int *retval;
{
    int fd;
    struct file *fp;
    int error = 0;
    
    falloc(p, &fp, &fd);
    fp->f_flag = O_RDWR;
    fp->f_ops = &socketops;

    if ((error = socreate(uap->domain, (struct socket **)(&fp->f_data), uap->type, uap->protocol)) != 0)
    {
        free(fp);
        p->p_fd->fd_ofiles[fd] = NULL;
        return error;
    }

    if (retval)
        *retval = fd;

    return 0;
}

struct bind_args {
	int	s;
	caddr_t	name;
	int	namelen;
};
/* ARGSUSED */
bind(p, uap, retval)
	struct proc *p;
	register struct bind_args *uap;
	int *retval;
{
    struct file *fp = NULL;
    struct mbuf *m = NULL;
    int error = 0;
    
    getsock(p->p_fd, uap->s, &fp);
    sockargs(&m, uap->name, uap->namelen, MT_SONAME);

    sobind((struct socket*)fp->f_data, m);

    m_free(m);

    return 0;
}

struct listen_args {
	int	s;
	int	backlog;
};
/* ARGSUSED */
listen(p, uap, retval)
	struct proc *p;
	register struct listen_args *uap;
	int *retval;
{
    struct file *fp = NULL;
   
    sockargs(p->p_fd, uap->s, &fp);
    solisten((struct socket*)fp->f_data, uap->backlog);

    return 0;
}

struct accept_args {
	int	s;
	caddr_t	name;
	int	*anamelen;
#ifdef COMPAT_OLDSOCK
	int	compat_43;	/* pseudo */
#endif
};

#ifdef COMPAT_OLDSOCK
accept(p, uap, retval)
	struct proc *p;
	struct accept_args *uap;
	int *retval;
{
    return 0;
}

oaccept(p, uap, retval)
	struct proc *p;
	struct accept_args *uap;
	int *retval;
{
    return 0;
}
#else /* COMPAT_OLDSOCK */

#define	accept1	accept
#endif

accept1(p, uap, retval)
	struct proc *p;
	register struct accept_args *uap;
	int *retval;
{
    int namelen = uap->anamelen;
    int error = 0;

    struct file *f = NULL;
    getsock(p->p_fd, uap->s, &f);

    if (f == NULL)
        return EINVAL;

    struct socket *socket = (struct socket*)(f->f_data);
    if ((socket->so_options & SO_ACCEPTCONN) == 0)
        return EINVAL;
    if ((socket->so_state & SS_NBIO)
        && socket->so_qlen == 0)
        return EWOULDBLOCK;

    int chain = 0;
    while (socket->so_qlen == 0 ||
        (socket->so_state & SS_CANTRCVMORE) ||
        socket->so_error
        )
    {
        if (error = tsleep(&chain, PSOCK | PCATCH, NULL, socket->so_timeo))
        {
            if (socket->so_state & SS_NBIO)
                return EWOULDBLOCK;
            else
                return EINTR;
        }

        error = socket->so_error;
        socket->so_error = 0;
    }

    struct file *fp;
    int fd = 0;
    error = falloc(p, &fp, &fd);

    fp->f_type = FWRITE | FREAD;
    fp->f_ops = &socketops;
    soqremque(socket, 0);
    fp->f_data = (caddr_t)socket;

    struct mbuf *m = m_get(0, MT_SONAME);
    error = soaccept(socket, m);

    int len = min(uap->anamelen, MSIZE - sizeof(*m));
    memcpy(mtod(m, caddr_t), uap->name, len);
    m->m_len = len;

    return 0;
}

struct connect_args {
	int	s;
	caddr_t	name;
	int	namelen;
};
/* ARGSUSED */
connect(p, uap, retval)
	struct proc *p;
	register struct connect_args *uap;
	int *retval;
{
    return 0;
}

struct socketpair_args {
	int	domain;
	int	type;
	int	protocol;
	int	*rsv;
};
socketpair(p, uap, retval)
	struct proc *p;
	register struct socketpair_args *uap;
	int retval[];
{
    return 0;
}

struct sendto_args {
	int	s;
	caddr_t	buf;
	size_t	len;
	int	flags;
	caddr_t	to;
	int	tolen;
};
sendto(p, uap, retval)
	struct proc *p;
	register struct sendto_args *uap;
	int *retval;
{
    return 0;
}

#ifdef COMPAT_OLDSOCK
struct osend_args {
	int	s;
	caddr_t	buf;
	int	len;
	int	flags;
};
osend(p, uap, retval)
	struct proc *p;
	register struct osend_args *uap;
	int *retval;
{
    return 0;
}

#define MSG_COMPAT	0x8000
struct osendmsg_args {
	int	s;
	caddr_t	msg;
	int	flags;
};
osendmsg(p, uap, retval)
	struct proc *p;
	register struct osendmsg_args *uap;
	int *retval;
{
    return 0;
}
#endif

struct sendmsg_args {
	int	s;
	caddr_t	msg;
	int	flags;
};
sendmsg(p, uap, retval)
	struct proc *p;
	register struct sendmsg_args *uap;
	int *retval;
{
    return 0;
}

sendit(p, s, mp, flags, retsize)
	register struct proc *p;
	int s;
	register struct msghdr *mp;
	int flags, *retsize;
{
    return 0;
}

struct recvfrom_args {
	int	s;
	caddr_t	buf;
	size_t	len;
	int	flags;
	caddr_t	from;
	int	*fromlenaddr;
};

#ifdef COMPAT_OLDSOCK
orecvfrom(p, uap, retval)
	struct proc *p;
	struct recvfrom_args *uap;
	int *retval;
{
    return 0;
}
#endif

recvfrom(p, uap, retval)
	struct proc *p;
	register struct recvfrom_args *uap;
	int *retval;
{
    return 0;
}

#ifdef COMPAT_OLDSOCK
struct orecv_args {
	int	s;
	caddr_t	buf;
	int	len;
	int	flags;
};
orecv(p, uap, retval)
	struct proc *p;
	register struct orecv_args *uap;
	int *retval;
{
    return 0;
}

/*
 * Old recvmsg.  This code takes advantage of the fact that the old msghdr
 * overlays the new one, missing only the flags, and with the (old) access
 * rights where the control fields are now.
 */
struct orecvmsg_args {
	int	s;
	struct	omsghdr *msg;
	int	flags;
};
orecvmsg(p, uap, retval)
	struct proc *p;
	register struct orecvmsg_args *uap;
	int *retval;
{
    return 0;
}
#endif

struct recvmsg_args {
	int	s;
	struct	msghdr *msg;
	int	flags;
};
recvmsg(p, uap, retval)
	struct proc *p;
	register struct recvmsg_args *uap;
	int *retval;
{
    return 0;
}

recvit(p, s, mp, namelenp, retsize)
	register struct proc *p;
	int s;
	register struct msghdr *mp;
	caddr_t namelenp;
	int *retsize;
{
    return 0;
}

struct shutdown_args {
	int	s;
	int	how;
};
/* ARGSUSED */
shutdown(p, uap, retval)
	struct proc *p;
	register struct shutdown_args *uap;
	int *retval;
{
    return 0;
}

struct setsockopt_args {
	int	s;
	int	level;
	int	name;
	caddr_t	val;
	int	valsize;
};
/* ARGSUSED */
setsockopt(p, uap, retval)
	struct proc *p;
	register struct setsockopt_args *uap;
	int *retval;
{
    return 0;
}

struct getsockopt_args {
	int	s;
	int	level;
	int	name;
	caddr_t	val;
	int	*avalsize;
};
/* ARGSUSED */
getsockopt(p, uap, retval)
	struct proc *p;
	register struct getsockopt_args *uap;
	int *retval;
{
    return 0;
}

struct pipe_args {
	int	dummy;
};
/* ARGSUSED */
pipe(p, uap, retval)
	struct proc *p;
	struct pipe_args *uap;
	int retval[];
{
    return 0;
}

/*
 * Get socket name.
 */
struct getsockname_args {
	int	fdes;
	caddr_t	asa;
	int	*alen;
#ifdef COMPAT_OLDSOCK
	int	compat_43;	/* pseudo */
#endif
};
#ifdef COMPAT_OLDSOCK
getsockname(p, uap, retval)
	struct proc *p;
	struct getsockname_args *uap;
	int *retval;
{
    return 0;
}

ogetsockname(p, uap, retval)
	struct proc *p;
	struct getsockname_args *uap;
	int *retval;
{
    return 0;
}
#else /* COMPAT_OLDSOCK */

#define	getsockname1	getsockname
#endif

/* ARGSUSED */
getsockname1(p, uap, retval)
	struct proc *p;
	register struct getsockname_args *uap;
	int *retval;
{
    return 0;
}

/*
 * Get name of peer for connected socket.
 */
struct getpeername_args {
	int	fdes;
	caddr_t	asa;
	int	*alen;
#ifdef COMPAT_OLDSOCK
	int	compat_43;	/* pseudo */
#endif
};

#ifdef COMPAT_OLDSOCK
getpeername(p, uap, retval)
	struct proc *p;
	struct getpeername_args *uap;
	int *retval;
{
    return 0;
}

ogetpeername(p, uap, retval)
	struct proc *p;
	struct getpeername_args *uap;
	int *retval;
{
    return 0;
}
#else /* COMPAT_OLDSOCK */

#define	getpeername1	getpeername
#endif

/* ARGSUSED */
getpeername1(p, uap, retval)
	struct proc *p;
	register struct getpeername_args *uap;
	int *retval;
{
    return 0;
}

sockargs(mp, buf, buflen, type)
	struct mbuf **mp;
	caddr_t buf;
	int buflen, type;
{
    if (buflen > MLEN)
    {
        return EINVAL;
    }
    struct mbuf *m = malloc(sizeof (*m));
    if (m == NULL)
        return ENOBUFS;

    // should be copyin()......
    memcpy(mtod(m, caddr_t), buf, buflen);
    
    m->m_len = buflen;
    if (type == MT_SONAME)
    {
        mtod(m, struct sockaddr*)->sa_len = buflen;
    }

    return 0;
}

getsock(fdp, fdes, fpp)
	struct filedesc *fdp;
	int fdes;
	struct file **fpp;
{
    if (fdp->fd_nfiles < fdes)
        return 0;
    if ((fdp->fd_ofiles[fdes]->f_type & DTYPE_SOCKET) == 0)
        return 0;

    fpp = &fdp->fd_ofiles[fdes];

    return 0;
}
