#ifndef _SYS_RESOURCE_H_
#define	_SYS_RESOURCE_H_

#include "cdefs.h"
#include "types.h"
#include "time.h"

/*
 * Process priority specifications to get/setpriority.
 */
#define	PRIO_MIN	-20
#define	PRIO_MAX	20

#define	PRIO_PROCESS	0
#define	PRIO_PGRP	1
#define	PRIO_USER	2

/*
 * Resource utilization information.
 */

#define	RUSAGE_SELF	0
#define	RUSAGE_CHILDREN	-1

struct	rusage {
	struct timeval ru_utime;	/* user time used */
	struct timeval ru_stime;	/* system time used */
	long	ru_maxrss;		/* max resident set size */
#define	ru_first	ru_ixrss
	long	ru_ixrss;		/* integral shared memory size */
	long	ru_idrss;		/* integral unshared data " */
	long	ru_isrss;		/* integral unshared stack " */
	long	ru_minflt;		/* page reclaims */
	long	ru_majflt;		/* page faults */
	long	ru_nswap;		/* swaps */
	long	ru_inblock;		/* block input operations */
	long	ru_oublock;		/* block output operations */
	long	ru_msgsnd;		/* messages sent */
	long	ru_msgrcv;		/* messages received */
	long	ru_nsignals;		/* signals received */
	long	ru_nvcsw;		/* voluntary context switches */
	long	ru_nivcsw;		/* involuntary " */
#define	ru_last		ru_nivcsw
};

/*
 * Resource limits
 */
#define	RLIMIT_CPU	0		/* cpu time in milliseconds */
#define	RLIMIT_FSIZE	1		/* maximum file size */
#define	RLIMIT_DATA	2		/* data size */
#define	RLIMIT_STACK	3		/* stack size */
#define	RLIMIT_CORE	4		/* core file size */
#define	RLIMIT_RSS	5		/* resident set size */
#define	RLIMIT_MEMLOCK	6		/* locked-in-memory address space */
#define	RLIMIT_NPROC	7		/* number of processes */
#define	RLIMIT_NOFILE	8		/* number of open files */

#define	RLIM_NLIMITS	9		/* number of resource limits */

#define	RLIM_INFINITY	(((u_quad_t)1 << 63) - 1)

struct orlimit {
	long	rlim_cur;		/* current (soft) limit */
	long	rlim_max;		/* maximum value for rlim_cur */
};

struct rlimit {
	quad_t	rlim_cur;		/* current (soft) limit */
	quad_t	rlim_max;		/* maximum value for rlim_cur */
};

/* Load average structure. */
struct loadavg {
	fixpt_t ldavg[3];
	long fscale;
};

#ifdef KERNEL
extern struct loadavg averunnable;

#else

__BEGIN_DECLS
int	getpriority __P((int, int));
int	getrlimit __P((int, struct rlimit *));
int	getrusage __P((int, struct rusage *));
int	setpriority __P((int, int, int));
int	setrlimit __P((int, const struct rlimit *));
__END_DECLS

#endif	/* KERNEL */
#endif	/* !_SYS_RESOURCE_H_ */
