#ifndef SYS_PARAM_H
#define SYS_PARAM_H

#include "types.h"
#include "syslimits.h"
#include "ucred.h"
#include "signal.h"
#include "time.h"
#include "cdefs.h"

#define	BSD	199306		/* System version (year & month). */
#define BSD4_3	1
#define BSD4_4	1

#ifndef NULL
#define	NULL	0
#endif


/*
 * Machine-independent constants (some used in following include files).
 * Redefined constants are from POSIX 1003.1 limits file.
 *
 * MAXCOMLEN should be >= sizeof(ac_comm) (see <acct.h>)
 * MAXLOGNAME should be >= UT_NAMESIZE (see <utmp.h>)
 */

#define	MAXCOMLEN	16		/* max command name remembered */
#define	MAXINTERP	32		/* max interpreter file name length */
#define	MAXLOGNAME	12		/* max login name length */
#define	MAXUPRC		CHILD_MAX	/* max simultaneous processes */
#define	NCARGS		ARG_MAX		/* max bytes for an exec function */
 //#define	NGROUPS		16	/* max number groups */
#define	NGROUPS		NGROUPS_MAX	/* max number groups */
#define	NOFILE		OPEN_MAX	/* max open files per process */
#define	NOGROUP		65535		/* marker for empty group set member */
#define MAXHOSTNAMELEN	256		/* max hostname size */

/* More types and definitions used throughout the kernel. */
#ifdef KERNEL
#include "errno.h"
#include "uio.h"
#include "resource.h"
#endif


/* Machine type dependent parameters. */
//#include <machine/param.h>
//#include <machine/limits.h>

/*
 * Priorities.  Note that with 32 run queues, differences less than 4 are
 * insignificant.
 */
#define	PSWP	0
#define	PVM	4
#define	PINOD	8
#define	PRIBIO	16
#define	PVFS	20
#define	PZERO	22		/* No longer magic, shouldn't be here.  XXX */
#define	PSOCK	24
#define	PWAIT	32
#define	PLOCK	36
#define	PPAUSE	40
#define	PUSER	50
#define	MAXPRI	127		/* Priorities range from 0 through MAXPRI. */

#define	PRIMASK	0x0ff
#define	PCATCH	0x100		/* OR'd with pri for tsleep to check signals */

#define	NZERO	0		/* default "nice" */

#define	NBPW	sizeof(int)	/* number of bytes per word (integer) */

#define	CMASK	022		/* default file mask: S_IWGRP|S_IWOTH */
#define	NODEV	(dev_t)(-1)	/* non-existent device */

/*
 * Clustering of hardware pages on machines with ridiculously small
 * page sizes is done here.  The paging subsystem deals with units of
 * CLSIZE pte's describing NBPG (from machine/machparam.h) pages each.
 */
#define	CLBYTES		(CLSIZE*NBPG)
#define	CLOFSET		(CLSIZE*NBPG-1)	/* for clusters, like PGOFSET */
#define	claligned(x)	((((int)(x))&CLOFSET)==0)
#define	CLOFF		CLOFSET
#define	CLSHIFT		(PGSHIFT+CLSIZELOG2)

#if CLSIZE==1
#define	clbase(i)	(i)
#define	clrnd(i)	(i)
#else
/* Give the base virtual address (first of CLSIZE). */
#define	clbase(i)	((i) &~ (CLSIZE-1))
/* Round a number of clicks up to a whole cluster. */
#define	clrnd(i)	(((i) + (CLSIZE-1)) &~ (CLSIZE-1))
#endif

#define	CBLOCK	64		/* Clist block size, must be a power of 2. */
#define CBQSIZE	(CBLOCK/NBBY)	/* Quote bytes/cblock - can do better. */
				/* Data chars/clist. */
#define	CBSIZE	(CBLOCK - sizeof(struct cblock *) - CBQSIZE)
#define	CROUND	(CBLOCK - 1)	/* Clist rounding. */

/*
 * File system parameters and macros.
 *
 * The file system is made out of blocks of at most MAXBSIZE units, with
 * smaller units (fragments) only in the last direct block.  MAXBSIZE
 * primarily determines the size of buffers in the buffer pool.  It may be
 * made larger without any effect on existing file systems; however making
 * it smaller make make some file systems unmountable.
 */
#define	MAXBSIZE	MAXPHYS
#define MAXFRAG 	8

/*
 * MAXPATHLEN defines the longest permissable path length after expanding
 * symbolic links. It is used to allocate a temporary buffer from the buffer
 * pool in which to do the name expansion, hence should be a power of two,
 * and must be less than or equal to MAXBSIZE.  MAXSYMLINKS defines the
 * maximum number of symbolic links that may be expanded in a path name.
 * It should be set high enough to allow all legitimate uses, but halt
 * infinite loops reasonably quickly.
 */
#define	MAXPATHLEN	PATH_MAX
#define MAXSYMLINKS	8

/* Bit map related macros. */
#define	setbit(a,i)	((a)[(i)/NBBY] |= 1<<((i)%NBBY))
#define	clrbit(a,i)	((a)[(i)/NBBY] &= ~(1<<((i)%NBBY)))
#define	isset(a,i)	((a)[(i)/NBBY] & (1<<((i)%NBBY)))
#define	isclr(a,i)	(((a)[(i)/NBBY] & (1<<((i)%NBBY))) == 0)

/* Macros for counting and rounding. */
#ifndef howmany
#define	howmany(x, y)	(((x)+((y)-1))/(y))
#endif
#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))
#define powerof2(x)	((((x)-1)&(x))==0)

///* Macros for min/max. */
//#ifndef KERNEL
//#define	MIN(a,b) (((a)<(b))?(a):(b))
//#define	MAX(a,b) (((a)>(b))?(a):(b))
//#endif

/*
 * Constants for setting the parameters of the kernel memory allocator.
 *
 * 2 ** MINBUCKET is the smallest unit of memory that will be
 * allocated. It must be at least large enough to hold a pointer.
 *
 * Units of memory less or equal to MAXALLOCSAVE will permanently
 * allocate physical memory; requests for these size pieces of
 * memory are quite fast. Allocations greater than MAXALLOCSAVE must
 * always allocate and free physical memory; requests for these
 * size allocations should be done infrequently as they will be slow.
 *
 * Constraints: CLBYTES <= MAXALLOCSAVE <= 2 ** (MINBUCKET + 14), and
 * MAXALLOCSIZE must be a power of two.
 */
#define MINBUCKET	4		/* 4 => min allocation of 16 bytes */
#define MAXALLOCSAVE	(2 * CLBYTES)

/*
 * Scale factor for scaled integers used to count %cpu time and load avgs.
 *
 * The number of CPU `tick's that map to a unique `%age' can be expressed
 * by the formula (1 / (2 ^ (FSHIFT - 11))).  The maximum load average that
 * can be calculated (assuming 32 bits) can be closely approximated using
 * the formula (2 ^ (2 * (16 - FSHIFT))) for (FSHIFT < 15).
 *
 * For the scheduler to maintain a 1:1 mapping of CPU `tick' to `%age',
 * FSHIFT must be at least 11; this gives us a maximum load avg of ~1024.
 */
#define	FSHIFT	11		/* bits to right of fixed binary point */
#define FSCALE	(1<<FSHIFT)


#endif  // SYS_PARAM_H
