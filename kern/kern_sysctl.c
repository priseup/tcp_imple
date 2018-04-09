#include "../sys/param.h"
#include "../sys/systm.h"
#include "../sys/kernel.h"
#include "../sys/malloc.h"
#include "../sys/proc.h"
#include "../sys/file.h"
//#include "../sys/vnode.h"
#include "../sys/unistd.h"
#include "../sys/buf.h"
#include "../sys/ioctl.h"
#include "../sys/tty.h"
#include "../sys/sysctl.h"
#include "../sys/errno.h"
#include <stddef.h>
/*#include "../vm/vm.h"*/

sysctlfn kern_sysctl;
sysctlfn hw_sysctl;
#ifdef DEBUG
sysctlfn debug_sysctl;
#endif
extern sysctlfn vm_sysctl;
extern sysctlfn fs_sysctl;
extern sysctlfn net_sysctl;
extern sysctlfn cpu_sysctl;

/*
 * Locking and stats
 */
static struct sysctl_lock {
	int	sl_lock;
	int	sl_want;
	int	sl_locked;
} memlock;

struct sysctl_args {
	int	*name;
	u_int	namelen;
	void	*old;
	size_t	*oldlenp;
	void	*new;
	size_t	newlen;
};

int
__sysctl(p, uap, retval)
	struct proc *p;
	register struct sysctl_args *uap;
	int *retval;
{
    return 0;
}

/*
 * Attributes stored in the kernel.
 */
char hostname[MAXHOSTNAMELEN];
int hostnamelen;
long hostid;
int securelevel;

/*
 * kernel related system variables.
 */
kern_sysctl(name, namelen, oldp, oldlenp, newp, newlen, p)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	struct proc *p;
{
    return 0;
}

/*
 * hardware related system variables.
 */
hw_sysctl(name, namelen, oldp, oldlenp, newp, newlen, p)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	struct proc *p;
{
    return 0;
}

#ifdef DEBUG
/*
 * Debugging related system variables.
 */
struct ctldebug debug0, debug1, debug2, debug3, debug4;
struct ctldebug debug5, debug6, debug7, debug8, debug9;
struct ctldebug debug10, debug11, debug12, debug13, debug14;
struct ctldebug debug15, debug16, debug17, debug18, debug19;
static struct ctldebug *debugvars[CTL_DEBUG_MAXID] = {
	&debug0, &debug1, &debug2, &debug3, &debug4,
	&debug5, &debug6, &debug7, &debug8, &debug9,
	&debug10, &debug11, &debug12, &debug13, &debug14,
	&debug15, &debug16, &debug17, &debug18, &debug19,
};
int
debug_sysctl(name, namelen, oldp, oldlenp, newp, newlen, p)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	struct proc *p;
{
    return 0;
}
#endif /* DEBUG */

int
copyout(from, to, len)
void *from;
void *to;
u_int len;
{
    return 0;
}
int
copyin(from, to, len)
void *from;
void *to;
u_int len;
{
    return 0;
}

/*
 * Validate parameters and get old / set new parameters
 * for an integer-valued sysctl function.
 */
sysctl_int(oldp, oldlenp, newp, newlen, valp)
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	int *valp;
{
	int error = 0;

	if (oldp && *oldlenp < sizeof(int))
		return (ENOMEM);
	if (newp && newlen != sizeof(int))
		return (EINVAL);
	*oldlenp = sizeof(int);
	if (oldp)
		error = copyout(valp, oldp, sizeof(int));
	if (error == 0 && newp)
		error = copyin(newp, valp, sizeof(int));
	return (error);
}

/*
 * As above, but read-only.
 */
sysctl_rdint(oldp, oldlenp, newp, val)
	void *oldp;
	size_t *oldlenp;
	void *newp;
	int val;
{
    return 0;
}

/*
 * Validate parameters and get old / set new parameters
 * for a string-valued sysctl function.
 */
sysctl_string(oldp, oldlenp, newp, newlen, str, maxlen)
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	char *str;
	int maxlen;
{
    return 0;
}

/*
 * As above, but read-only.
 */
sysctl_rdstring(oldp, oldlenp, newp, str)
	void *oldp;
	size_t *oldlenp;
	void *newp;
	char *str;
{
    return 0;
}

/*
 * Validate parameters and get old / set new parameters
 * for a structure oriented sysctl function.
 */
sysctl_struct(oldp, oldlenp, newp, newlen, sp, len)
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	void *sp;
	int len;
{
    return 0;
}

/*
 * Validate parameters and get old parameters
 * for a structure oriented sysctl function.
 */
sysctl_rdstruct(oldp, oldlenp, newp, sp, len)
	void *oldp;
	size_t *oldlenp;
	void *newp, *sp;
	int len;
{
    return 0;
}

/*
 * Get file structures.
 */
sysctl_file(where, sizep)
	char *where;
	size_t *sizep;
{
    return 0;
}

/*
 * try over estimating by 5 procs
 */
#define KERN_PROCSLOP	(5 * sizeof (struct kinfo_proc))

sysctl_doproc(name, namelen, where, sizep)
	int *name;
	u_int namelen;
	char *where;
	size_t *sizep;
{
    return 0;
}

/*
 * Fill in an eproc structure for the specified process.
 */
void
fill_eproc(p, ep)
	register struct proc *p;
	register struct eproc *ep;
{
    return 0;
}

#ifdef COMPAT_43
#include <sys/socket.h>
#define	KINFO_PROC		(0<<8)
#define	KINFO_RT		(1<<8)
#define	KINFO_VNODE		(2<<8)
#define	KINFO_FILE		(3<<8)
#define	KINFO_METER		(4<<8)
#define	KINFO_LOADAVG		(5<<8)
#define	KINFO_CLOCKRATE		(6<<8)

struct getkerninfo_args {
	int	op;
	char	*where;
	int	*size;
	int	arg;
};

ogetkerninfo(p, uap, retval)
	struct proc *p;
	register struct getkerninfo_args *uap;
	int *retval;
{
    return 0;
}
#endif /* COMPAT_43 */
