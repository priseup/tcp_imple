/*
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
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
 *	@(#)kern_descrip.c	8.6 (Berkeley) 4/19/94
 */

#include "sys/param.h"
#include "sys/systm.h"
#include "sys/filedesc.h"
#include "sys/kernel.h"
//#include "sys/vnode.h"
#include "sys/proc.h"
#include "sys/file.h"
#include "sys/socket.h"
#include "sys/socketvar.h"
#include "sys/stat.h"
#include "sys/ioctl.h"
#include "sys/fcntl.h"
#include "sys/malloc.h"
#include "sys/syslog.h"
#include "sys/unistd.h"
#include "sys/resourcevar.h"
#include "sys/errno.h"

/*
 * Descriptor management.
 */
struct file *filehead;	/* head of list of open files */
int nfiles;		/* actual number of open files */
/*
 * System calls on descriptors.
 */
struct getdtablesize_args {
	int	dummy;
};
/* ARGSUSED */
getdtablesize(p, uap, retval)
	struct proc *p;
	struct getdtablesize_args *uap;
	int *retval;
{
    return 0;
}

/*
 * Duplicate a file descriptor.
 */
struct dup_args {
	u_int	fd;
};
/* ARGSUSED */
dup(p, uap, retval)
	struct proc *p;
	struct dup_args *uap;
	int *retval;
{
    return 0;
}

/*
 * Duplicate a file descriptor to a particular value.
 */
struct dup2_args {
	u_int	from;
	u_int	to;
};
/* ARGSUSED */
dup2(p, uap, retval)
	struct proc *p;
	struct dup2_args *uap;
	int *retval;
{
    return 0;
}

/*
 * The file control system call.
 */
struct fcntl_args {
	int	fd;
	int	cmd;
	int	arg;
};
/* ARGSUSED */
fcntl(p, uap, retval)
	struct proc *p;
	register struct fcntl_args *uap;
	int *retval;
{
    return 0;
}

/*
 * Common code for dup, dup2, and fcntl(F_DUPFD).
 */
int
finishdup(fdp, old, new, retval)
	register struct filedesc *fdp;
	register int old, new, *retval;
{
    return 0;
}

/*
 * Close a file descriptor.
 */
struct close_args {
	int	fd;
};
/* ARGSUSED */
close(p, uap, retval)
	struct proc *p;
	struct close_args *uap;
	int *retval;
{
    return 0;
}

#if defined(COMPAT_43) || defined(COMPAT_SUNOS)
/*
 * Return status information about a file descriptor.
 */
struct ofstat_args {
	int	fd;
	struct	ostat *sb;
};
/* ARGSUSED */
ofstat(p, uap, retval)
	struct proc *p;
	register struct ofstat_args *uap;
	int *retval;
{
    return 0;
}
#endif /* COMPAT_43 || COMPAT_SUNOS */

/*
 * Return status information about a file descriptor.
 */
struct fstat_args {
	int	fd;
	struct	stat *sb;
};
/* ARGSUSED */
fstat(p, uap, retval)
	struct proc *p;
	register struct fstat_args *uap;
	int *retval;
{
    return 0;
}

/*
 * Return pathconf information about a file descriptor.
 */
struct fpathconf_args {
	int	fd;
	int	name;
};
/* ARGSUSED */
fpathconf(p, uap, retval)
	struct proc *p;
	register struct fpathconf_args *uap;
	int *retval;
{
    return 0;
}

/*
 * Allocate a file descriptor for the process.
 */
int fdexpand;

int fdalloc(p, want, result)
	struct proc *p;
	int want;
	int *result;
{
    struct filedesc *fdp = p->p_fd;
    int i;
    int lim, last, nfiles;
    struct file **newofile;
    char *newofileflags;

    //search for a free descriptor starting at the higher
    //of want or fd_freefile. if that fails, consider 
    //expanding the ofile aray
    if ((int)p->p_rlimit[RLIMIT_NOFILE].rlim_cur < maxfiles)
        lim = (int)p->p_rlimit[RLIMIT_NOFILE].rlim_cur;
    else
        lim = maxfiles;
    for (; ;)
    {
        if (fdp->fd_nfiles < lim)
            last = fdp->fd_nfiles;
        else
            last = lim;

        //last = min(fdp->fd_nfiles, lim);
        if ((i = want) < fdp->fd_freefile)
            i = fdp->fd_freefile;
        for (; i < last; i++)
        {
            if (fdp->fd_ofiles[i] == NULL)
            {
                fdp->fd_ofileflags[i] = 0;
                if (i > fdp->fd_lastfile)
                    fdp->fd_lastfile = i;
                if (want <= fdp->fd_freefile)
                    fdp->fd_freefile = i;
               
                *result = i;

                return 0;
            }
        }
    }

    // no space in current array, expand
    if (fdp->fd_nfiles >= lim)
        return EMFILE;
    if (fdp->fd_nfiles < NDEXTENT)
        nfiles = NDEXTENT;
    else
        nfiles = 2 * fdp->fd_nfiles;

    *result = fdp->fd_nfiles;
    newofile = malloc(nfiles * OFILESIZE);
    newofileflags = (char*)&newofile[nfiles];

    // copy the existing ofile and ofileflags arrays
    // and zero the new portion of each array
    i = sizeof(struct file *) * fdp->fd_nfiles;
    memcpy(newofile, fdp->fd_ofiles, i);
    memset((char *)newofile + i, 0, 
        nfiles * sizeof (struct file*) - i);
    
    i = sizeof(char) * fdp->fd_nfiles;
    memcpy(newofileflags, fdp->fd_ofileflags, i);
    memset(newofileflags + i, 0, nfiles * sizeof (char) -i);
    free(fdp->fd_ofiles);
    fdp->fd_ofiles = newofile;
    fdp->fd_ofileflags = newofileflags;
    fdp->fd_nfiles = nfiles;

    fdexpand++;

    return 0;
}

/*
 * Check to see whether n user file descriptors
 * are available to the process p.
 */
fdavail(p, n)
	struct proc *p;
	register int n;
{
    return 0;
}

/*
 * Create a new open file structure and allocate
 * a file decriptor for the process that refers to it.
 */
falloc(p, resultfp, resultfd)
	register struct proc *p;
	struct file **resultfp;
	int *resultfd;
{
    struct file *fp, *fq, **fpp;
    int error, i;

    if (error = fdalloc(p, 0, &i))
        return error;
    if (nfiles >= maxfiles)
    {
        printf("file table is full\n");
        return ENFILE;
    }

    nfiles++;
    fp = malloc(sizeof (*fp));
    memset(fp, 0, sizeof(*fp));
    if (fq = p->p_fd->fd_ofiles[0])
        fpp = &fq->f_filef;
    else
        fpp = &filehead;
    p->p_fd->fd_ofiles[i] = fp;
    if (fq = *fpp)
        fq->f_fileb = &fp->f_filef;
    fp->f_filef = fq;
    fp->f_fileb = fpp;
    *fpp = fp;
    fp->f_count = 1;
    fp->f_cred = p->p_cred;
    crhold(fp->f_cred);
    if (resultfp)
        *resultfp = fp;
    if (resultfd)
        *resultfd = i;

    return 0;
}

/*
 * Free a file descriptor.
 */
ffree(fp)
	register struct file *fp;
{
}

/*
 * Copy a filedesc structure.
 */
struct filedesc *
fdcopy(p)
	struct proc *p;
{
    return NULL;
}

/*
 * Release a filedesc structure.
 */
void
fdfree(p)
	struct proc *p;
{
}

/*
 * Internal form of close.
 * Decrement reference count on file structure.
 * Note: p may be NULL when closing a file
 * that was being passed in a message.
 */
closef(fp, p)
	register struct file *fp;
	register struct proc *p;
{
    return 0;
}

/*
 * Apply an advisory lock on a file descriptor.
 *
 * Just attempt to get a record lock of the requested type on
 * the entire file (l_whence = SEEK_SET, l_start = 0, l_len = 0).
 */
struct flock_args {
	int	fd;
	int	how;
};
/* ARGSUSED */
flock(p, uap, retval)
	struct proc *p;
	register struct flock_args *uap;
	int *retval;
{
    return 0;
}

/*
 * File Descriptor pseudo-device driver (/dev/fd/).
 *
 * Opening minor device N dup()s the file (if any) connected to file
 * descriptor N belonging to the calling process.  Note that this driver
 * consists of only the ``open()'' routine, because all subsequent
 * references to this file will be direct to the other driver.
 */
/* ARGSUSED */
fdopen(dev, mode, type, p)
	dev_t dev;
	int mode, type;
	struct proc *p;
{

	/*
	 * XXX Kludge: set curproc->p_dupfd to contain the value of the
	 * the file descriptor being sought for duplication. The error 
	 * return ensures that the vnode for this device will be released
	 * by vn_open. Open will detect this special error and take the
	 * actions in dupfdopen below. Other callers of vn_open or VOP_OPEN
	 * will simply report the error.
	 */
	p->p_dupfd = minor(dev);
	return (ENODEV);
}

/*
 * Duplicate the specified descriptor to a free descriptor.
 */
dupfdopen(fdp, indx, dfd, mode, error)
	register struct filedesc *fdp;
	register int indx, dfd;
	int mode;
	int error;
{
    return 0;
}
