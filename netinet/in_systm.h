#ifndef NETINET_IN_SYSTM_H
#define NETINET_IN_SYSTM_H

#include "..\sys\types.h"
/*
 * Miscellaneous internetwork
 * definitions for kernel.
 */

/*
 * Network types.
 *
 * Internally the system keeps counters in the headers with the bytes
 * swapped so that VAX instructions will work on them.  It reverses
 * the bytes before transmission at each protocol level.  The n_ types
 * represent the types with the bytes in ``high-ender'' order.
 */
typedef u_short n_short;		/* short as received from the net */
typedef u_long	n_long;			/* long as received from the net */

typedef	u_long	n_time;			/* ms since 00:00 GMT, byte rev */

#ifndef KERNEL
n_time	 iptime(void);
#endif

#endif  // NETINET_IN_SYSTM_H
