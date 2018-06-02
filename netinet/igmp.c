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
    register struct igmp *igmp;
    register struct ip *ip;
    register int igmplen;
    register struct ifnet *ifp = m->m_pkthdr.rcvif;
    register int minlen;
    register struct in_multi *inm;
    register struct in_ifaddr *ia;
    struct in_multistep step;

    ++igmpstat.igps_rcv_total;

    ip = mtod(m, struct ip *);
    igmplen = ip->ip_len;

    /*
    * Validate lengths
    */
    if (igmplen < IGMP_MINLEN) {
        ++igmpstat.igps_rcv_tooshort;
        m_freem(m);
        return;
    }
    minlen = iphlen + IGMP_MINLEN;
    if ((m->m_flags & M_EXT || m->m_len < minlen) &&
        (m = m_pullup(m, minlen)) == 0) {
        ++igmpstat.igps_rcv_tooshort;
        return;
    }

    /*
    * Validate checksum
    */
    m->m_data += iphlen;
    m->m_len -= iphlen;
    igmp = mtod(m, struct igmp *);
    if (in_cksum(m, igmplen)) {
        ++igmpstat.igps_rcv_badsum;
        m_freem(m);
        return;
    }
    m->m_data -= iphlen;
    m->m_len += iphlen;
    ip = mtod(m, struct ip *);

    switch (igmp->igmp_type) {

        //���ܲ�ѯ���Ĳ�������������I G M P��Ա���档�෴�� i g m p _ i n p u tΪ����ղ�ѯ�Ľӿ���
        //    �صĸ����鶨ʱ������һ�������ֵ I G M P _ R A N D O M _ D E L A Y����ĳ��Ķ�ʱ����ʱ����
        //    i g m p _ f a s t t i m o����һ����Ա��ϵ���棬���ͬʱ�����������յ���ѯ������Ҳ����ͬһ������
        //    һ��ĳ�������ϵ�ĳ���ض���������ʱ����ʱ���������ಥһ�����档������潫ȡ����
        //    �������ϵĶ�ʱ������ֻ֤��һ�������������϶ಥ
    case IGMP_HOST_MEMBERSHIP_QUERY:
        ++igmpstat.igps_rcv_queries;

        if (ifp == &loif)
            break;

        if (ip->ip_dst.s_addr != igmp_all_hosts_group) {
            ++igmpstat.igps_rcv_badqueries;
            m_freem(m);
            return;
        }

        /*
        * Start the timers in all of our membership records for
        * the interface on which the query arrived, except those
        * that are already running and those that belong to the
        * "all-hosts" group.
        */
        IN_FIRST_MULTI(step, inm);
        while (inm != NULL) {
            if (inm->inm_ifp == ifp && inm->inm_timer == 0 &&
                inm->inm_addr.s_addr != igmp_all_hosts_group) {
                inm->inm_timer =
                    IGMP_RANDOM_DELAY(inm->inm_addr);
                igmp_timers_are_running = 1;
            }
            IN_NEXT_MULTI(step, inm);
        }

        break;

        //������սӿ����ڱ�������飬�Ͱ���صı��涨ʱ��������� 0���Ӷ�ʹ��������ĵ�
        //    һ�������ܹ���ֹ���������������档·����ֻ��֪��������������һ���ӿ�����ĳ�Ա��
        //    ������ά��һ����ȷ�����Ա����������
    case IGMP_HOST_MEMBERSHIP_REPORT:
        ++igmpstat.igps_rcv_reports;

        if (ifp == &loif)
            break;

        if (!IN_MULTICAST(ntohl(igmp->igmp_group.s_addr)) ||
            igmp->igmp_group.s_addr != ip->ip_dst.s_addr) {
            ++igmpstat.igps_rcv_badreports;
            m_freem(m);
            return;
        }

        /*
        * KLUDGE: if the IP source address of the report has an
        * unspecified (i.e., zero) subnet number, as is allowed for
        * a booting host, replace it with the correct subnet number
        * so that a process-level multicast routing demon can
        * determine which subnet it arrived from.  This is necessary
        * to compensate for the lack of any way for a process to
        * determine the arrival interface of an incoming packet.
        */
        if ((ntohl(ip->ip_src.s_addr) & IN_CLASSA_NET) == 0) {
            IFP_TO_IA(ifp, ia);
            if (ia) ip->ip_src.s_addr = htonl(ia->ia_subnet);
        }

        /*
        * If we belong to the group being reported, stop
        * our timer for that group.
        */
        IN_LOOKUP_MULTI(igmp->igmp_group, ifp, inm);
        if (inm != NULL) {
            inm->inm_timer = 0;
            ++igmpstat.igps_rcv_ourreports;
        }

        break;
    }

    /*
    * Pass all valid IGMP packets up to any process(es) listening
    * on a raw IGMP socket.
    */
    rip_input(m);
}

void
igmp_joingroup(inm)
	struct in_multi *inm;
{
    if (inm->inm_addr.s_addr == igmp_all_hosts_group
        || inm->inm_ifp == &loif)
        inm->inm_timer = 0;
    else
    {
        igmp_sendreport(inm);
        inm->inm_timer = IGMP_RANDOM_DELAY(inm->inm_addr);
        igmp_timers_are_running = 1;
    }
}

void
igmp_leavegroup(inm)
	struct in_multi *inm;
{
    // no action required on leaving a group
}

void
igmp_fasttimo()
{
    register struct in_multi *inm;
    struct in_multistep step;

    /*
    * Quick check to see if any work needs to be done, in order
    * to minimize the overhead of fasttimo processing.
    */
    if (!igmp_timers_are_running)
        return;

    igmp_timers_are_running = 0;
    IN_FIRST_MULTI(step, inm);
    while (inm != NULL) {
        if (inm->inm_timer == 0) {
            /* do nothing */
        }
        else if (--inm->inm_timer == 0) {
            igmp_sendreport(inm);
        }
        else {
            igmp_timers_are_running = 1;
        }
        IN_NEXT_MULTI(step, inm);
    }

}

static void
igmp_sendreport(inm)
	register struct in_multi *inm;
{
    register struct mbuf *m;
    register struct igmp *igmp;
    register struct ip *ip;
    register struct ip_moptions *imo;
    struct ip_moptions simo;

    MGETHDR(m, M_DONTWAIT, MT_HEADER);
    if (m == NULL)
        return;
    /*
    * Assume max_linkhdr + sizeof(struct ip) + IGMP_MINLEN
    * is smaller than mbuf size returned by MGETHDR.
    */
    m->m_data += max_linkhdr;
    m->m_len = sizeof(struct ip) + IGMP_MINLEN;
    m->m_pkthdr.len = sizeof(struct ip) + IGMP_MINLEN;

    ip = mtod(m, struct ip *);
    ip->ip_tos = 0;
    ip->ip_len = sizeof(struct ip) + IGMP_MINLEN;
    ip->ip_off = 0;
    ip->ip_p = IPPROTO_IGMP;
    ip->ip_src.s_addr = INADDR_ANY;
    ip->ip_dst = inm->inm_addr;

    igmp = (struct igmp *)(ip + 1);
    igmp->igmp_type = IGMP_HOST_MEMBERSHIP_REPORT;
    igmp->igmp_code = 0;
    igmp->igmp_group = inm->inm_addr;
    igmp->igmp_cksum = 0;
    igmp->igmp_cksum = in_cksum(m, IGMP_MINLEN);

    imo = &simo;
    memset(imo, 0, sizeof(*imo));
    imo->imo_multicast_ifp = inm->inm_ifp;
    imo->imo_multicast_ttl = 1;
    /*
    * Request loopback of the report if we are acting as a multicast
    * router, so that the process-level routing demon can hear it.
    */
#ifdef MROUTING
    {
        extern struct socket *ip_mrouter;
        imo->imo_multicast_loop = (ip_mrouter != NULL);
    }
#endif
    ip_output(m, NULL, NULL, 0, imo);

    ++igmpstat.igps_snd_reports;
}
