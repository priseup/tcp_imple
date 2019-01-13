
/*
 * Ethernet address resolution protocol.
 * TODO:
 *	add "inuse/lock" bit (or ref. count) along with valid bit
 */

#include "../sys/param.h"
// #include "../sys/systm.h"
#include "../sys/malloc.h"
#include "../sys/mbuf.h"
#include "../sys/socket.h"
#include "../sys/time.h"
#include "../sys/kernel.h"
#include "../sys/errno.h"
// #include "../sys/ioctl.h"
// #include "../sys/syslog.h"

#include "../net/if.h"
#include "../net/if_dl.h"
#include "../net/route.h"

#include "in.h"
#include "in_systm.h"
#include "in_var.h"
#include "ip.h"
#include "if_ether.h"

#define SIN(s) ((struct sockaddr_in *)s)
#define SDL(s) ((struct sockaddr_dl *)s)
#define SRP(s) ((struct sockaddr_inarp *)s)

/*
 * ARP trailer negotiation.  Trailer protocol is not IP specific,
 * but ARP request/response use IP addresses.
 */
#define ETHERTYPE_IPTRAILERS ETHERTYPE_TRAIL


/* timer values */
int	arpt_prune = (5*60*1);	/* walk list every 5 minutes */
int	arpt_keep = (20*60);	/* once resolved, good for 20 more minutes */
int	arpt_down = 20;		/* once declared down, don't send for 20 secs */
#define	rt_expire rt_rmx.rmx_expire

static	void arprequest __P((struct arpcom *, u_long *, u_long *, u_char *));
static	void arptfree __P((struct llinfo_arp *));
static	void arptimer __P((void *));
static	struct llinfo_arp *arplookup __P((u_long, int, int));
static	void in_arpinput __P((struct mbuf *));

extern	struct ifnet loif;
extern	struct timeval time;
struct	llinfo_arp llinfo_arp = {&llinfo_arp, &llinfo_arp};
struct	ifqueue arpintrq = {0, 0, 0, 50};
int	arp_inuse, arp_allocated, arp_intimer;
int	arp_maxtries = 5;
int	useloopback = 1;	/* use loopback interface for local traffic */
int	arpinit_done = 0;

/*
 * Timeout routine.  Age arp_tab entries periodically.
 */
/* ARGSUSED */
static void
arptimer(ignored_arg)
	void *ignored_arg;
{
    // the following part that is commented is written by myself
 /*   arpt_prune;
    struct llinfo_arp *arp = NULL;
    
    for (arp = &llinfo_arp; arp; )
    {
        if (arp->la_timer && arp->la_timer < arp->la_rt->rt_expire)
        {
            arptfree(arp);
            arp = arp->la_next
        }
    }
*/
    struct llinfo_arp *la = llinfo_arp.la_next;
    timeout(arptimer, (caddr_t)0, arpt_prune * hz);
    while (la != &llinfo_arp)
    {
        struct rtentry *rt = la->la_rt;
        la = la->la_next;
        if (rt->rt_expire && rt->rt_expire <= time.tv_sec)
        {
            arptfree(la->la_prev);  // timer has expired, clear
        }
    }
}

/*
 * Parallel to llc_rtrequest.
 */
void
arp_rtrequest(req, rt, sa)
	int req;
	register struct rtentry *rt;
	struct sockaddr *sa;
{
    struct sockaddr *gate = rt->rt_gateway;
    struct llinfo_arp *la = (struct llinfo_arp *)rt->rt_llinfo;
    static struct sockaddr_dl null_sdl = {sizeof (null_sdl), AF_LINK};

    struct arpcom *ac = NULL;
    arptimer();

    if (rt->rt_flags & RTF_GATEWAY)
        return;

    switch (req)
    {
    case RTM_ADD:
        // 网络路由，而非主机路由
        if (!(rt->rt_flags & RTF_HOST))
        {

        }
        if (rt->rt_flags & RTF_CLONING)
        {
            rt_setgate(rt, sa, &null_sdl);
        }
        break;
    case RTM_RESOLVE:
        SDL(rt->rt_gateway)->sa_family = AF_INET;
        SDL(rt->rt_gateway)->sa_len = 0;

        if (!la)
            la = malloc(sizeof (*la));
        rt->rt_llinfo = la;
        arp_inuse++;
        arp_allocated++;
        memset(la, 0, sizeof(*la));
        la->la_rt = rt;
        rt->rt_flags &= RTF_LLINFO;
        rt->rt_expire = 0;

        memcpy(LLADDR(SDL(rt->rt_gateway)), ac->ac_enaddr, 6);
        SDL(rt->rt_gateway)->sdl_alen = 6;

        if (usrloopback)
            rt->rt_ifp = &loif;
        break;
    case RTM_DELETE:
        if (!la)
        {
            break;
        }
        arp_inuse--;
        rt->rt_llinfo = NULL;
        rt->rt_flags &= ~RTF_LLINFO;
        remque(la);
        m_freem(la->la_hold);
        free(la);
        break;
    }

}

/*
 * Broadcast an ARP packet, asking who has addr on interface ac.
 */
void
arpwhohas(ac, addr)
	register struct arpcom *ac;
	register struct in_addr *addr;
{
        //arprequest(ac, (u_long*)addr, (u_long*)addr, ac->ac_enaddr);
        arprequest(ac, (u_long*)(&ac->ac_ipaddr), (u_long*)addr, ac->ac_enaddr);
}

/*
 * Broadcast an ARP request. Caller specifies:
 *	- arp header source ip address
 *	- arp header target ip address
 *	- arp header source ethernet address
 */
static void
arprequest(ac, sip, tip, enaddr)
	register struct arpcom *ac;
	register u_long *sip, *tip;
	register u_char *enaddr;
{
    struct mbuf *m = NULL;
    struct ether_header *eh = NULL;
    struct ether_arp *ea;
    struct sockaddr sa;

    m = m_gethdr(0, MT_DATA);
    m->m_flags = M_PKTHDR;
    MH_ALIGN(m, sizeof (*ea));
    m->m_len = sizeof(*ea);
    m->m_pkthdr.len = sizeof(*ea);

    ea = mtod(m, struct ether_arp *);
    memset(ea, 0, sizeof(*ea));

    // 填充以太网帧首部
    eh = (struct ether_header *)sa.sa_data;
    memcpy(eh->ether_dhost, etherbroadcastaddr, 6);
    memcpy(eh->ether_shost, enaddr, 6);// 本机以太网地址
    eh->ether_type = htons(ETHERTYPE_ARP);

    // 填充arp字段
    ea->arp_hrd = htons(ARPHRD_ETHER);
    ea->arp_pro = htons(ETHERTYPE_IP);
    ea->arp_hln = sizeof(ea->arp_sha);
    ea->arp_pln = sizeof(ea->arp_spa);
    ea->arp_op = htons(ARPOP_REQUEST);

    memcpy(ea->arp_sha, enaddr, sizeof(ea->arp_sha));
    memcpy(ea->arp_spa, sip, sizeof(ea->arp_spa));
    memcpy(ea->arp_tpa, sip, sizeof(ea->arp_spa));

    // 填充sockaddr
    sa.sa_family = AF_UNSPEC;
    sa.sa_len = sizeof(sa);

    // 调用接口输出函数
    ac->ac_if.if_output(&ac->ac_if, m, &sa, NULL);
}

/*
 * Resolve an IP address into an ethernet address.  If success,
 * desten is filled in.  If there is no entry in arptab,
 * set one up and broadcast a request for the IP address.
 * Hold onto this mbuf and resend it once the address
 * is finally resolved.  A return value of 1 indicates
 * that desten has been filled in and the packet should be sent
 * normally; a 0 return indicates that the packet has been
 * taken over here, either now or for later transmission.
 */
int
arpresolve(ac, rt, m, dst, desten)
	register struct arpcom *ac;
	register struct rtentry *rt;
	struct mbuf *m;
	register struct sockaddr *dst;
	register u_char *desten;
{
    extern int error;
    struct llinfo_arp *la = NULL;

    if (m->m_flags & M_BCAST)
    {
        memcpy(desten, etherbroadcastaddr, 6);
        return 1;
    }

    if (m->m_flags & M_MCAST)
    {
        // 将D类地址映射为相应的以太网地址
        ETHER_MAP_IP_MULTICAST(etherbroadcastaddr, desten);
        return 1;
    }

    if (rt)
    {
        la = (struct llinfo_arp*)(rt->rt_llinfo);
    }
    else
    {
        la = arplookup(dst->sa_data, 1, 0);
        rt = la->la_rt;
    }
    if (!la)
    {
        error = 0;
        return 0;
    }

    la->la_hold = mbuf;
    rt = la->la_rt;
    if ((rt->rt_expire == 0 || rt->rt_expire <= time.tv_sec)
            && SDL(rt->rt_gateway)->sdl_family == AF_LINK
            && SDL(rt->rt_gateway)->sdl_alen))
    {
        memcpy(desten, LLADDR(SDL(rt->rt_gateway), 6);
        return 1;
    }
    if (rt->rt_expire)
    {
        rt->rt_flags &= ~RTF_REJECT;
    }

    if (rt->rt_expire == 0 || rt->rt_expire < time.tv_sec)
    {
        rt->rt_expire = time.tv_sec;
        if (la->la_asked++ < arp_maxtries)
        {
            arpwhohas(ac, dst->sa_data);
        }
        else
        {
            rt->rt_expire += arpt_down;
            rt->rt_flags |= RTF_REJECT;
            la->la_asked = 0;
        }
    }

    return 0;
}

/*
 * Common length and type checks are done here,
 * then the protocol-specific routine is called.
 */
void
arpintr()
{
    struct mbuf *m;
    struct arphdr *ar;
    int s;
    extern struct ifqueue arpintrq;

    while (arpintrq.ifq_head)
    {
        IF_DEQUEUE(&arpintrq, m);
        if (!m)
            break;
        int min_len = sizeof(*ar) + 2 * (6 + 4);
        ar = mtod(m, struct arphdr *);
        if (ntohs(ar->ar_hrd) == ARPHRD_ETHER
            && m->m_len >= sizeof (*ar)
            && m->m_len >= min_len)
        {
            if (ar->ar_pro == ETHERTYPE_IP
                || ar->ar_pro == ETHERTYPE_IPTRAILERS)
            {
                in_arpinput(m);
                continue;
            }
        }
        m_free(m);    // 不满足各种过滤条件，丢弃该buf
    }
}

/*
 * ARP for Internet protocols on 10 Mb/s Ethernet.
 * Algorithm is that given in RFC 826.
 * In addition, a sanity check is performed on the sender
 * protocol address, to catch impersonators.
 * We no longer handle negotiations for use of trailer protocol:
 * Formerly, ARP replied for protocol type ETHERTYPE_TRAIL sent
 * along with IP replies if we wanted trailers sent to us,
 * and also sent them in response to IP replies.
 * This allowed either end to announce the desire to receive
 * trailer packets.
 * We no longer reply to requests for ETHERTYPE_TRAIL protocol either,
 * but formerly didn't normally send requests.
 */
static void
in_arpinput(m)
	struct mbuf *m;
{
    struct ether_arp *ea = NULL;
    struct arpcom *ac = (struct arpcom *)m->m_pkthdr.rcvif;
    struct ether_header *eh;
    struct rtentry *rt;
    struct in_ifaddr *ia, *maybe_ia = 0;
    struct sockaddr_dl *sdl;
    struct sockaddr sa;
    struct in_addr isaddr, itaddr, myaddr;
    int op;

    ea = mtod(m, struct ether_arp *);
    op = ea->ea_hdr.ar_op;
    memcpy(&isaddr, ea->arp_spa, sizeof(isaddr));
    memcpy(&itaddr, ea->arp_tpa, sizeof(itaddr));

    for (ia = in_ifaddr; ia; ia = ia->ia_next)
    {
        if (ia->ia_ifa.ifa_ifp != m->m_pkthdr.rcvif)
            continue;
        maybe_ia = ia;
        if (!memcmp(&isaddr, &ia->ia_addr.sin_addr, sizeof (isaddr))
            || !memcmp(&itaddr, &ia->ia_addr.sin_addr, sizeof(itaddr)))
        {
            break;
        }
    }

    // 这种情况只发生在收到
    // arp请求的接口虽然已经初始化但还没有分配IP地址时
    if (maybe_ia == NULL)
        goto out;

    // maybe_ia值不为0，但没有一个ip地址与目的方ip
    // 或者发送方ip地址匹配，则设为该接口的最后一个ip地址
    if (maybe_ia->ia_addr.sin_addr.s_addr != isaddr.s_addr
        && maybe_ia->ia_addr.sin_addr.s_addr != itaddr.s_addr)
    {
        myaddr = ia->ia_addr.sin_addr;
    }

    // 发送方硬件地址等于本机接口的硬件地址
    // 收到了本机发出的请求，忽略该分组
    // 本机接口的硬件地址????
    if (memcmp(ea->arp_sha, 
        ((struct arpcom*)(maybe_ia->ia_ifa.ifa_ifp))->ac_enaddr,
        sizeof (ea->arp_sha)) == 0)
        return;

    // 发送方的硬件地址等于以太网的广播地址
    // 说明出了差错，记录该差错并丢弃分组
    if (memcmp(ea->arp_sha, etherbroadcastaddr, sizeof (ea->arp_sha)) == 0)
    {
        int error = 0;
        goto out;
    }

    // 发送方的ip等于myaddr
    // 发送方和本机正在使用同一个IP地址
    // 这也是一个错误，要么是发送方，要么是本机系统配置出了错误
    // 记录该差错，将目的IP地址设为myaddr后，程序转至reply
    if (memcmp(ea->arp_spa, &myaddr.s_addr, sizeof(myaddr)) == 0)
    {
        memcpy(ea->arp_tpa, &myaddr.s_addr, sizeof (myaddr.s_addr));
        goto reply;
    }

    struct llinfo_arp *la = arplookup(isaddr.s_addr, 1, 0);

    if (la && la->la_rt && SDL(la->la_rt->rt_gateway))
    {
        sdl = SDL(la->la_rt->rt_gateway);
        
        // 说明引用的路由表结点
        // 是已存在的而非新创建的
        if (sdl->sdl_alen)
        {
            // 如果不同，则说明
            // 发送方的硬件地址已经改变
            // 这是因为发送方以不同的以太网地址重新启动了系统
            // 而本机的arp结点还没有超时
            if (memcmp(LLADDR(sdl), ea->arp_sha, sizeof (ea->arp_sha)))
            {
                // 记录差错信息后，程序继续执行
                // 更新arp结点的硬件地址
                // ?????
            }
        }
        memcpy(LLADDR(SDL(la->la_rt->rt_gateway)),
            ea->arp_sha, sizeof(ea->arp_sha));
        SDL(la->la_rt->rt_gateway)->sdl_alen = sizeof(ea->arp_sha);

        // 如果时限是非零的
        // 则被复位成arpt_keep
        if (la->la_timer)
            la->la_timer = arpt_keep;
        la->la_rt->rt_flags &= RTF_REJECT;
        la->la_asked = 0;

        if (la->la_hold)
            ether_output(m->m_pkthdr.rcvif, la->la_hold, &sa, la->la_rt);
    }

    if (ea->ea_hdr.ar_op != ARPOP_REQUEST)
    {
        goto out;
    }

    if (itaddr.s_addr == myaddr.s_addr)
    {
        memcpy(ea->arp_tha, ea->arp_sha, sizeof(ea->arp_sha));
        memcpy(ea->arp_sha, ac->ac_enaddr, sizeof(ac->ac_enaddr));
    }
    else
    {
        la = arplookup(isaddr.s_addr, 0, SIN_PROXY);
        if (la == NULL)
        {
            goto out;
        }

        memcpy(ea->arp_tha, ea->arp_sha, sizeof(ea->arp_sha));
        memcpy(ea->arp_sha, ac->ac_enaddr, sizeof(ac->ac_enaddr));
    }
    memcpy(ea->arp_spa, itaddr.s_addr, sizeof (ea->arp_spa));
    memcpy(ea->arp_tpa, isaddr.s_addr, sizeof (ea->arp_tpa));

    ea->ea_hdr.ar_op = ARPOP_REPLY;
    memcpy(sa.sa_data, eh, 14);

reply:
    ether_output(m->m_pkthdr.rcvif, la->la_hold, &sa, la->la_rt);
    return;
out:
    m_freem(m);
}

/*
 * Free an arp entry.
 */
static void
arptfree(la)
	register struct llinfo_arp *la;
{
    struct rtentry *rt = la->la_rt;
    if (rt->rt_refcnt && SDL(rt->rt_gateway))
    {
        SDL(rt->rt_gateway)->sdl_alen = 0;
        la->la_asked = 0;
        rt->rt_flags &= ~RTF_REJECT;

        return;
    }

    rtrequest(RTM_DELETE, rt_key(rt), (struct sockaddr *)0,
            rt_mask(rt), 0, (struct rtentry **)0);
}
/*
 * Lookup or enter a new address in arptab.
 */
static struct llinfo_arp *
arplookup(addr, create, proxy)
	u_long addr;
	int create, proxy;
{
    struct rtentry *rt = NULL;
    static struct sockaddr_inarp sin = {sizeof(sin), AF_INET};
    
    sin.sin_addr.s_addr = addr;
    sin.sin_other = proxy ? SIN_PROXY : 0;

    // by pcrs
    //rt = rtalloc1(NULL, 0);
    //if (rt)
    //{
    //    rt->rt_refcnt--;
    //    if (rt->rt_flags & RTF_GATEWAY
    //        || rt->rt_flags & ~RTF_LLINFO
    //        || SDL(rt->rt_gateway)->sdl_family != AF_LINK)
    //    {
    //        return NULL;
    //    }
    //}

    rt = rtalloc1((struct sockaddr *)&sin, 0);
    if (rt)
    {
        rt->rt_refcnt--;
        if (rt->rt_flags & RTF_GATEWAY
            || rt->rt_flags & ~RTF_LLINFO
            || SDL(rt->rt_gateway)->sdl_family != AF_LINK)
        {
            // 出现了错误
            return NULL;
        }
    }

    return rt;
}

int
arpioctl(cmd, data)
	int cmd;
	caddr_t data;
{
	return (EOPNOTSUPP);
}
