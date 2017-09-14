/* Internet Group Management Protocol (IGMP) routines. */

#include "../sys/param.h"
#include "../sys/mbuf.h"
#include "../sys/socket.h"
#include "../sys/protosw.h"

#include "../net/if.h"
#include "../net/route.h"

#include "in.h"
#include "in_var.h"
#include "in_systm.h"
#include "ip.h"
#include "ip_var.h"
#include "igmp.h"
#include "igmp_var.h"

extern struct ifnet loif;

static int igmp_timers_are_running = 0;
static u_long igmp_all_hosts_group;

static void igmp_sendreport __P((struct in_multi *));

void
igmp_init()
{
}

void
igmp_input(m, iphlen)
	register struct mbuf *m;
	register int iphlen;
{
}

void
igmp_joingroup(inm)
	struct in_multi *inm;
{
}

void
igmp_leavegroup(inm)
	struct in_multi *inm;
{
}

void
igmp_fasttimo()
{
}

static void
igmp_sendreport(inm)
	register struct in_multi *inm;
{
}
