#ifndef	_SYS_RESOURCEVAR_H_
#define	_SYS_RESOURCEVAR_H_

#include "resource.h"
#include "time.h"

/*
 * Kernel per-process accounting / statistics
 * (not necessarily resident except when running).
 */
struct pstats {
#define	pstat_startzero	p_ru
	struct	rusage p_ru;		/* stats for this proc */
	struct	rusage p_cru;		/* sum of stats for reaped children */
#define	pstat_endzero	pstat_startcopy

#define	pstat_startcopy	p_timer
	struct	itimerval p_timer[3];	/* virtual-time timers */

	struct uprof {			/* profile arguments */
		caddr_t	pr_base;	/* buffer base */
		u_long	pr_size;	/* buffer size */
		u_long	pr_off;		/* pc offset */
		u_long	pr_scale;	/* pc scaling */
		u_long	pr_addr;	/* temp storage for addr until AST */
		u_long	pr_ticks;	/* temp storage for ticks until AST */
	} p_prof;
#define	pstat_endcopy	p_start
	struct	timeval p_start;	/* starting time */
};

/*
 * Kernel shareable process resource limits.  Because this structure
 * is moderately large but changes infrequently, it is normally
 * shared copy-on-write after forks.  If a group of processes
 * ("threads") share modifications, the PL_SHAREMOD flag is set,
 * and a copy must be made for the child of a new fork that isn't
 * sharing modifications to the limits.
 */
struct plimit {
	struct	rlimit pl_rlimit[RLIM_NLIMITS];
#define	PL_SHAREMOD	0x01		/* modifications are shared */
	int	p_lflags;
	int	p_refcnt;		/* number of references */
};

/* add user profiling from AST */
#define	ADDUPROF(p)							\
	addupc_task(p,							\
	    (p)->p_stats->p_prof.pr_addr, (p)->p_stats->p_prof.pr_ticks)

#ifdef KERNEL
void	 addupc_intr __P((struct proc *p, u_long pc, u_int ticks));
void	 addupc_task __P((struct proc *p, u_long pc, u_int ticks));
struct plimit
	*limcopy __P((struct plimit *lim));
#endif
#endif	/* !_SYS_RESOURCEVAR_H_ */
