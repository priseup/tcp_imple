#ifndef SYS_UCRED_H_
#define	SYS_UCRED_H_

#include "types.h"
#include "param.h"
#include "syslimits.h"

#define NGROUPS 16
/*
 * Credentials.
 */
struct ucred {
	u_short	cr_ref;			/* reference count */
	uid_t	cr_uid;			/* effective user id */
	short	cr_ngroups;		/* number of groups */
	gid_t	cr_groups[NGROUPS];	/* groups */
};
#define cr_gid cr_groups[0]
#define NOCRED ((struct ucred *)-1)	/* no credential available */
#define FSCRED ((struct ucred *)-2)	/* filesystem credential */

//#ifdef KERNEL
#define	crhold(cr)	(cr)->cr_ref++
struct ucred *crget();
struct ucred *crcopy();
struct ucred *crdup();
//#endif /* KERNEL */

#endif /* !SYS_UCRED_H_ */
