
/*
 * Ethernet address resolution protocol.
 * TODO:
 *	add "inuse/lock" bit (or ref. count) along with valid bit
 */

#include "../sys/param.h"
#include "../sys/systm.h"
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

    if (!arpinit_done)
    {
        arpinit_done = 1;
        timeout(arptimer, NULL, hz);
    }

    if (rt->rt_flags & RTF_GATEWAY)
        return;
    switch (req)
    {
    case RTM_ADD:
        // 网络路由，而非主机路由
        if ((rt->rt_flags & RTF_HOST) == 0
            && SIN(rt_mask(rt))->sin_addr.s_addr != 0xffffffff)
        {
            rt->rt_flags |= RTF_CLONING;
        }
        if (rt->rt_flags & RTF_CLONING)
        {
        // case1: this route should come from a route to a iface
            rt_setgate(rt, rt_key(rt),
                (struct sockaddr *)&null_sdl);
            gate = rt->rt_gateway;
            SDL(gate)->sdl_type = rt->rt_ifp->if_type;
            SDL(gate)->sdl_index = rt->rt_ifp->if_index;
            rt->rt_expire = time.tv_sec;
        }
        // announce a new entry if requested
        if (rt->rt_flags & RTF_ANNOUNCE)
        {
            arprequest((struct arpcom *)rt->rt_ifp,
                &SIN(rt_key(rt))->sin_addr.s_addr,
                &SIN(rt_key(rt))->sin_addr.s_addr,
                (u_char*)LLADDR(SDL(gate)));
//            arprequest(rt->rt_ifp, (u_long*)(&rt->rt_ifp->ac_ipaddr), (u_long*)addr, ac->ac_enaddr);
        }
        break;
    case RTM_RESOLVE:
        if (gate->sa_family != AF_LINK
            || gate->sa_len < sizeof(null_sdl))
        {
            printf("arp_rtrequst: bad gateway\n");
            break;
        }
        SDL(gate)->sdl_type = rt->rt_ifp->if_type;
        SDL(gate)->sdl_index = rt->rt_ifp->if_index;

        // this happens on a route change
        if (la)
            break;

        // case2: this route may come from cloning, 
        // or a manual route add with a LL address
        la = malloc(sizeof (*la));
        rt->rt_llinfo = la;
        if (!la)
        {
            printf("arp_request: malloc failed\n");
            break;
        }
        arp_inuse++; arp_allocated++;
        memset(la, 0, sizeof(*la));
        la->la_rt = rt;
        rt->rt_flags |= RTF_LLINFO;
        if (SIN(rt_key(rt))->sin_addr.s_addr
            == (IA_SIN(rt->rt_ifa))->sin_addr.s_addr)
        {
            rt->rt_expire = 0;
            memcpy(LLADDR(SDL(rt->rt_gateway)), 
                ((struct arpcom *)rt->rt_ifp)->ac_enaddr, 6);
            if (useloopback)
                rt->rt_ifp = &loif;
        }

//        insque(la, &llinfo_arp);
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
    memcpy(ea->arp_tpa, tip, sizeof(ea->arp_spa));

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
    struct sockaddr_dl *sdl = NULL;

    if (m->m_flags & M_BCAST)
    {
        memcpy(desten, etherbroadcastaddr, sizeof (etherbroadcastaddr));
        return 1;
    }

    if (m->m_flags & M_MCAST)
    {
        ETHER_MAP_IP_MULTICAST(&SIN(dst)->sin_addr,
            desten);
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
    if (!la || !rt)
    {
        printf("arpresolve: can't alloate llinfo\n");
        m_freem(m);
        return 0;
    }

    sdl = SDL(rt->rt_gateway);
    if ((rt->rt_expire == 0 || rt->rt_expire > time.tv_sec)
            && SDL(rt->rt_gateway)->sdl_family == AF_LINK
            && SDL(rt->rt_gateway)->sdl_alen)
    {
        memcpy(desten, LLADDR(SDL(rt->rt_gateway)), 6);
        return 1;
    }
    if (la->la_hold)
    {
        m_freem(la->la_hold);
    }
    la->la_hold = m;

    if (rt->rt_expire)
    {
        rt->rt_flags &= ~RTF_REJECT;
        if (la->la_asked == 0 || rt->rt_expire != time.tv_sec)
        {
            rt->rt_expire = time.tv_sec;
            if (la->la_asked++ < arp_maxtries)
            {
                arpwhohas(ac, &(SIN(dst)->sin_addr));
            }
            else
            {
                rt->rt_expire += arpt_down;
                rt->rt_flags |= RTF_REJECT;
                la->la_asked = 0;
            }
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
    extern struct ifqueue arpintrq;

    while (arpintrq.ifq_head)
    {
        IF_DEQUEUE(&arpintrq, m);
        if (!m || (m->m_flags & M_PKTHDR) == 0)
            break;
        ar = mtod(m, struct arphdr *);
        int min_len = sizeof(*ar) + 2 * (ar->ar_hln + ar->ar_pln);
        if (ntohs(ar->ar_hrd) == ARPHRD_ETHER
            && m->m_len >= sizeof (*ar)
            && m->m_len >= min_len)
        {
            if (ar->ar_pro == ETHERTYPE_IP
                || ar->ar_pro == ETHERTYPE_IPTRAILERS)
            {
                in_arpinput(m);
            }
            else
            {
                m_free(m);    // 不满足各种过滤条件，丢弃该buf
            }
        }
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
    struct ether_header *eh = NULL;
    struct rtentry *rt = NULL;
    struct in_ifaddr *ia, *maybe_ia = 0;
    struct sockaddr_dl *sdl = NULL;
    struct sockaddr sa;
    struct in_addr isaddr, itaddr, myaddr;
    int op = 0;

    ea = mtod(m, struct ether_arp *);
    op = ntohs(ea->ea_hdr.ar_op);
    memcpy(&isaddr, ea->arp_spa, sizeof(isaddr));
    memcpy(&itaddr, ea->arp_tpa, sizeof(itaddr));

    for (ia = in_ifaddr; ia; ia = ia->ia_next)
    {
        if (ia->ia_ifp != &ac->ac_if)
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
    myaddr = ia ? ia->ia_addr.sin_addr : maybe_ia->ia_addr.sin_addr;

    // 发送方硬件地址等于本机接口的硬件地址
    // 收到了本机发出的请求，忽略该分组
    // 本机接口的硬件地址????
    if (memcmp(ea->arp_sha,
        ac->ac_enaddr,
        sizeof(ea->arp_sha)) == 0)
    {
        goto out;
    }

    // 发送方的硬件地址等于以太网的广播地址
    // 说明出了差错，记录该差错并丢弃分组
    if (memcmp(ea->arp_sha, etherbroadcastaddr, sizeof (ea->arp_sha)) == 0)
    {
        printf("arp: ether address is broadcast for IP address: %d\n",
            ntohl(isaddr.s_addr));
        goto out;
    }

    // 发送方的ip等于myaddr
    // 发送方和本机正在使用同一个IP地址
    // 这也是一个错误，要么是发送方，要么是本机系统配置出了错误
    // 记录该差错，将目的IP地址设为myaddr后，程序转至reply
    if (memcmp(isaddr.s_addr, &myaddr.s_addr, sizeof(myaddr)) == 0)
    {
        itaddr = myaddr;
        goto reply;
    }

    struct llinfo_arp *la = arplookup(isaddr.s_addr, 1, 0);

    if (la && (rt = la->la_rt) && SDL(la->la_rt->rt_gateway))
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
                printf("arp info overwritten for %x by %s\n",
                    isaddr.s_addr, ether_sprintf(ea->arp_sha));
                memcpy(ea->arp_sha, LLADDR(sdl), sizeof(ea->arp_sha));
                sdl->sdl_alen = sizeof(ea->arp_sha);
            }
        }
        // 如果时限是非零的
        // 则被复位成arpt_keep
        if (rt->rt_expire)
            rt->rt_expire = time.tv_sec + arpt_keep;

        la->la_rt->rt_flags &= ~RTF_REJECT;
        la->la_asked = 0;

        if (la->la_hold)
        {
            ether_output(&ac->ac_if, la->la_hold,
                rt_key(rt), rt);
            la->la_hold = NULL;
        }
    }

reply:
    // 如果arp不是请求操作，那么丢弃接收到的分组并返回
    if (ea->ea_hdr.ar_op != ARPOP_REQUEST)
    {
    out:
        m_freem(m);
        return;
    }

    // i am the target
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
        rt = la->la_rt;

        memcpy(ea->arp_tha, ea->arp_sha, sizeof(ea->arp_sha));
        sdl = SDL(rt->rt_gateway);
        memcpy(ea->arp_sha, LLADDR(sdl), sizeof(ea->arp_sha));
    }
    memcpy(ea->arp_spa, itaddr.s_addr, sizeof (ea->arp_spa));
    memcpy(ea->arp_tpa, isaddr.s_addr, sizeof (ea->arp_tpa));

    ea->arp_op = htons(ARPOP_REPLY);
    ea->arp_pro = htons(ETHERTYPE_IP);
    eh = (struct ether_header *)sa.sa_data;
    memcpy(eh->ether_dhost, ea->arp_tha, sizeof (eh->ether_dhost));
    eh->ether_type = ETHERTYPE_ARP;
    sa.sa_family = AF_UNSPEC;
    sa.sa_len = sizeof(sa);
    ac->ac_if.if_output(&ac->ac_if, m, &sa, NULL);
}

/*
 * Free an arp entry.
 */
static void
arptfree(la)
	register struct llinfo_arp *la;
{
    struct rtentry *rt = la->la_rt;
    if (rt->rt_refcnt > 0 && SDL(rt->rt_gateway)
        && SDL(rt->rt_gateway)->sdl_family == AF_LINK)
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
            if (create)
                printf("arptnew failed on %x\n",
                    ntohl(addr));
            return NULL;
        }
    }

    return (struct llinfo_arp *)rt->rt_llinfo;
}

int
arpioctl(cmd, data)
	int cmd;
	caddr_t data;
{
	return (EOPNOTSUPP);
}
