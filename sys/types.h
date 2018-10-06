#ifndef TYPES_H
#define TYPES_H

typedef	unsigned long long u_quad_t;	/* quads */

#define	WCOREFLAG	0200

#ifdef  _WIN64
typedef	long	quad_t;
typedef unsigned short ino_t;
typedef	unsigned long	uid_t;		/* user id */
#else
typedef	long long	quad_t;
typedef	unsigned long	ino_t;		/* inode number */
typedef	unsigned long	uid_t;		/* user id */
#endif


typedef	quad_t *	qaddr_t;

typedef char* caddr_t;
typedef	long		daddr_t;	/* disk address */
typedef	unsigned long	dev_t;		/* device number */
typedef unsigned long	fixpt_t;	/* fixed point number */
typedef	unsigned long	gid_t;		/* group id */
typedef	unsigned short	mode_t;		/* permissions */
typedef	unsigned short	nlink_t;	/* link count */
typedef	quad_t		off_t;		/* file offset */
typedef	long		pid_t;		/* process id */
typedef	long		segsz_t;	/* segment size */
typedef	long		swblk_t;	/* swap offset */

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;

typedef long mytime_t;

#define	__P(protos)	protos		/* traditional C preprocessor */


typedef	unsigned long	vm_offset_t;
typedef	unsigned long	vm_size_t;


/*
 * Forward structure declarations for function prototypes.  We include the
 * common structures that cross subsystem boundaries here; others are mostly
 * used in the same place that the structure is defined.
 */
struct	proc;
struct	pgrp;
struct	ucred;
struct	rusage;
struct	file;
struct	buf;
struct	tty;
struct	uio;

/*
 * Types which are fundamental to the implementation and may appear in
 * more than one standard header are defined here.  Standard headers
 * then use:
 *	#ifdef	_BSD_SIZE_T_
 *	typedef	_BSD_SIZE_T_ size_t;
 *	#undef	_BSD_SIZE_T_
 *	#endif
 */
#define	_BSD_CLOCK_T_	long		/* clock() */
#define	_BSD_PTRDIFF_T_	int			/* ptr1 - ptr2 */
#define	_BSD_SIZE_T_	int		/* sizeof() */
#define	_BSD_SSIZE_T_	int			/* byte count or error */
#define	_BSD_TIME_T_	__int64			/* time() */
#define	_BSD_VA_LIST_	char *			/* va_list */

/*
 * Runes (wchar_t) is declared to be an ``int'' instead of the more natural
 * ``unsigned long'' or ``long''.  Two things are happening here.  It is not
 * unsigned so that EOF (-1) can be naturally assigned to it and used.  Also,
 * it looks like 10646 will be a 31 bit standard.  This means that if your
 * ints cannot hold 32 bits, you will be in trouble.  The reason an int was
 * chosen over a long is that the is*() and to*() routines take ints (says
 * ANSI C), but they use _RUNE_T_ instead of int.  By changing it here, you
 * lose a bit of ANSI conformance, but your programs will still work.
 *    
 * Note that _WCHAR_T_ and _RUNE_T_ must be of the same type.  When wchar_t
 * and rune_t are typedef'd, _WCHAR_T_ will be undef'd, but _RUNE_T remains
 * defined for ctype.h.
 */
#define	_BSD_WCHAR_T_	int			/* wchar_t */
#define	_BSD_RUNE_T_	int			/* rune_t */

#ifndef _POSIX_SOURCE
#define	major(x)	((int)(((u_int)(x) >> 8)&0xff))	/* major number */
#define	minor(x)	((int)((x)&0xff))		/* minor number */
#define	makedev(x,y)	((dev_t)(((x)<<8) | (y)))	/* create dev_t */
#endif

// just to substiute, simplify the code
#define bcopy(src, dst, size) memcpy((dst), (src), (size))
#define bzero(src, size) memset((src), 0, (size))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define panic printf 

#define splsoftclock()	0
#define splnet()	0
#define splbio()	0
#define splimp()	0
#define spltty()	0
#define splclock()	0
#define splstatclock()	0
#define splvm()		0
#define splhigh()	0
#define splsched()	0
#define splx(s)     0

//#include <machine/ansi.h>
//#include <machine/types.h>

#ifdef	_BSD_CLOCK_T_
typedef	_BSD_CLOCK_T_	clock_t;
#undef	_BSD_CLOCK_T_
#endif


#ifdef	_BSD_SSIZE_T_
typedef	_BSD_SSIZE_T_	ssize_t;
#undef	_BSD_SSIZE_T_
#endif

#ifdef	_BSD_TIME_T_
typedef	_BSD_TIME_T_	time_t;
#undef	_BSD_TIME_T_
#endif

#ifndef _POSIX_SOURCE
#define	NBBY	8		/* number of bits in a byte */
#endif

/*
 * Select uses bit masks of file descriptors in longs.  These macros
 * manipulate such bit fields (the filesystem macros use chars).
 * FD_SETSIZE may be defined by the user, but the default here should
 * be enough for most uses.
 */
#ifndef	FD_SETSIZE
#define	FD_SETSIZE	256
#endif

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#ifndef howmany
#define	howmany(x, y)	(((x)+((y)-1))/(y))
#endif

typedef	struct fd_set {
	fd_mask	fds_bits[howmany(FD_SETSIZE, NFDBITS)];
} fd_set;

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define	FD_COPY(f, t)	bcopy(f, t, sizeof(*(f)))
#define	FD_ZERO(p)	bzero(p, sizeof(*(p)))

#endif  // TYPES_H
