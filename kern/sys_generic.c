/*
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)sys_generic.c	8.5 (Berkeley) 1/21/94
 */

#include "sys/param.h"
#include "sys/systm.h"
#include "sys/filedesc.h"
#include "sys/ioctl.h"
#include "sys/file.h"
#include "sys/proc.h"
#include "sys/socketvar.h"
#include "sys/uio.h"
#include "sys/kernel.h"
#include "sys/stat.h"
#include "sys/malloc.h"
#ifndef KTRACE
#include "sys/ktrace.h"
#endif

/*
 * Read system call.
 */
struct read_args {
	int	fd;
	char	*buf;
	u_int	nbyte;
};
/* ARGSUSED */
read(p, uap, retval)
	struct proc *p;
	register struct read_args *uap;
	int *retval;
{
    return 0;
}

/*
 * Scatter read system call.
 */
struct readv_args {
	int	fdes;
	struct	iovec *iovp;
	u_int	iovcnt;
};
readv(p, uap, retval)
	struct proc *p;
	register struct readv_args *uap;
	int *retval;
{
    return 0;
}

/*
 * Write system call
 */
struct write_args {
	int	fd;
	char	*buf;
	u_int	nbyte;
};
write(p, uap, retval)
	struct proc *p;
	register struct write_args *uap;
	int *retval;
{
    return 0;
}

/*
 * Gather write system call
 */
struct writev_args {
	int	fd;
	struct	iovec *iovp;
	u_int	iovcnt;
};
writev(p, uap, retval)
	struct proc *p;
	register struct writev_args *uap;
	int *retval;
{
    return 0;
}

/*
 * Ioctl system call
 */
struct ioctl_args {
	int	fd;
	int	com;
	caddr_t	data;
};
/* ARGSUSED */
ioctl(p, uap, retval)
	struct proc *p;
	register struct ioctl_args *uap;
	int *retval;
{
    return 0;
}

int	selwait, nselcoll;

/*
 * Select system call.
 */
struct select_args {
	u_int	nd;
	fd_set	*in, *ou, *ex;
	struct	timeval *tv;
};
select(p, uap, retval)
	register struct proc *p;
	register struct select_args *uap;
	int *retval;
{
    return 0;
}

selscan(p, ibits, obits, nfd, retval)
	struct proc *p;
	fd_set *ibits, *obits;
	int nfd, *retval;
{
    return 0;
}

/*ARGSUSED*/
seltrue(dev, flag, p)
	dev_t dev;
	int flag;
	struct proc *p;
{

	return (1);
}

/*
 * Record a select request.
 */
void
selrecord(selector, sip)
	struct proc *selector;
	struct selinfo *sip;
{
}

/*
 * Do a wakeup when a selectable event occurs.
 */
void
selwakeup(sip)
	register struct selinfo *sip;
{
}
