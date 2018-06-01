#include "if.h"
#include "..\sys\mbuf.h"
#include "..\sys\fcntl.h"
#include "..\sys\tty.h"
#include "..\sys\param.h"
#include "..\net\bpf.h"
#include "..\net\slip.h"
#include "if_slvar.h"
#include "if_types.h"
#include "..\sys\errno.h"
#include "..\sys\time.h"
#include "..\sys\sockio.h"
#include <stddef.h>
#include <string.h>

#define NSL 32
/*
 * SLMAX is a hard limit on input packet size.  To simplify the code
 * and improve performance, we require that packets fit in an mbuf
 * cluster, and if we get a compressed packet, there's enough extra
 * room to expand the header into a max length tcp/ip header (128
 * bytes).  So, SLMAX can be at most
 *	MCLBYTES - 1286
 *
 * SLMTU is a hard limit on output packet size.  To insure good
 * interactive response, SLMTU wants to be the smallest size that
 * amortizes the header cost.  (Remember that even with
 * type-of-service queuing, we have to wait for any in-progress
 * packet to finish.  I.e., we wait, on the average, 1/2 * mtu /
 * cps, where cps is the line speed in characters per second.
 * E.g., 533ms wait for a 1024 byte MTU on a 9600 baud line.  The
 * average compressed header size is 6-8 bytes so any MTU > 90
 * bytes will give us 90% of the line bandwidth.  A 100ms wait is
 * tolerable (500ms is not), so want an MTU around 296.  (Since TCP
 * will send 256 byte segments (to allow for 40 byte headers), the
 * typical packet size on the wire will be around 260 bytes).  In
 * 4.3tahoe+ systems, we can set an MTU in a route so we do that &
 * leave the interface MTU relatively high (so we don't IP fragment
 * when acting as a gateway to someone using a stupid MTU).
 *
 * Similar considerations apply to SLIP_HIWAT:  It's the amount of
 * data that will be queued 'downstream' of us (i.e., in clists
 * waiting to be picked up by the tty output interrupt).  If we
 * queue a lot of data downstream, it's immune to our t.o.s. queuing.
 * E.g., if SLIP_HIWAT is 1024, the interactive traffic in mixed
 * telnet/ftp will see a 1 sec wait, independent of the mtu (the
 * wait is dependent on the ftp window size but that's typically
 * 1k - 4k).  So, we want SLIP_HIWAT just big enough to amortize
 * the cost (in idle time on the wire) of the tty driver running
 * off the end of its clists & having to call back slstart for a
 * new packet.  For a tty interface with any buffering at all, this
 * cost will be zero.  Even with a totally brain dead interface (like
 * the one on a typical workstation), the cost will be <= 1 character
 * time.  So, setting SLIP_HIWAT to ~100 guarantees that we'll lose
 * at most 1% while maintaining good interactive response.
 */
#if NBPFILTER > 0
#define	BUFOFFSET	(128+sizeof(struct ifnet **)+SLIP_HDRLEN)
#else
#define	BUFOFFSET	(128+sizeof(struct ifnet **))
#endif
#define	SLMAX		(MCLBYTES - BUFOFFSET)
#define	SLBUFSIZE	(SLMAX + BUFOFFSET)
#define	SLMTU		296
#define	SLIP_HIWAT	roundup(50,CBSIZE)
#define	CLISTRESERVE	1024	/* Can't let clists get too low */

/*
 * SLIP ABORT ESCAPE MECHANISM:
 *	(inspired by HAYES modem escape arrangement)
 *	1sec escape 1sec escape 1sec escape { 1sec escape 1sec escape }
 *	within window time signals a "soft" exit from slip mode by remote end
 *	if the IFF_DEBUG flag is on.
 */
#define	ABT_ESC		'\033'	/* can't be t_intr - distant host must know it*/
#define	ABT_IDLE	1	/* in seconds - idle before an escape */
#define	ABT_COUNT	3	/* count of escapes for abort */
#define	ABT_WINDOW	(ABT_COUNT*2+2)	/* in seconds - time to count */

#define FRAME_END	 	0xc0		/* Frame End */
#define FRAME_ESCAPE		0xdb		/* Frame Esc */
#define TRANS_FRAME_END	 	0xdc		/* transposed frame end */
#define TRANS_FRAME_ESCAPE 	0xdd		/* transposed frame esc */

struct sl_softc sl_softc[NSL];

#define FRAME_END	 	0xc0		/* Frame End */
#define FRAME_ESCAPE		0xdb		/* Frame Esc */
#define TRANS_FRAME_END	 	0xdc		/* transposed frame end */
#define TRANS_FRAME_ESCAPE 	0xdd		/* transposed frame esc */

extern int ifqmaxlen;

static int slinit(struct sl_softc *sc);
static struct mbuf *sl_btom(struct sl_softc *sc, int len);

void slattach()
{
    int i = 0;
	struct sl_softc *sc;

    for (sc = sl_softc; i < NSL; sc++)
    {
        sc->sc_if.if_name = "sl";
		sc->sc_if.if_next = NULL;
		sc->sc_if.if_unit = i++;
        sc->sc_if.if_flags = IFF_POINTOPOINT | IFF_MULTICAST | SC_AUTOCOMP;
        sc->sc_if.if_snd.ifq_maxlen = ifqmaxlen;

        sc->sc_if.if_mtu = SLMTU;
        sc->sc_if.if_type = IFT_SLIP;
        sc->sc_if.if_metric = 0;
        sc->sc_if.if_baudrate = 0;

        sc->sc_fastq.ifq_maxlen = 32;
        sc->sc_flags = SC_AUTOCOMP | SC_NOICMP;

        sc->sc_if.if_output = sloutput;
        sc->sc_if.if_ioctl = slioctl;

		if_attach(&sc->sc_if);
        bpfattach(sc->sc_bpf, &sc->sc_if, DLT_SLIP, SLIP_HDRLEN);
    }
}

int slopen(dev_t dev, struct tty *tp)
{
    if (tp->t_line == SLIPDISC)
        return 0;

    for (struct sl_softc *sl = sl_softc; sl < sl_softc + NSL; sl++)
    {
        if (sl->sc_ttyp == NULL)
        {
            slinit(sl);

            tp->t_sc = sl;
            sl->sc_ttyp = tp;
            sl->sc_if.if_baudrate = tp->t_ospeed;

            ttyflush(tp, FREAD|FWRITE);

            return 0;
        }
    }

    return ENXIO;
}

static int slinit(struct sl_softc *sc)
{
    if (sc->sc_ep == NULL)
        sc->sc_ep = (caddr_t)malloc(MCLBYTES) + MCLBYTES;

    sc->sc_buf = sc->sc_ep - SLMAX;
    sc->sc_mp = sc->sc_buf;

    sl_compress_init(&sc->sc_comp);
    return 1;
}

static struct mbuf *sl_btom(struct sl_softc *sc, int len)
{
    struct mbuf *m;

    MGETHDR(m, M_WAITOK, 0);
    m->m_len = len;
    if (len < MCLBYTES)
    {
        m->m_pkthdr.len = m->m_len;
        memcpy(mtod(m, caddr_t), sc->sc_buf, len);
    }
    else
    {
        char *p = malloc(MCLBYTES * sizeof (char));
        m->m_flags |= M_EXT;
		m->m_data = m->m_ext.ext_buf = p + MCLBYTES;
    }

	return m;
}

void slinput(int c, struct tty *tp)
{
    extern long tk_nin;
    extern struct timeval time;
    extern struct ifqueue ipintrq;

    struct sl_softc *sc = tp->t_sc;
    struct ifnet *ifp = NULL;
    struct mbuf *m = NULL;
    struct ifqueue *ifq = NULL;
    int len;
    u_char chdr[CHDR_LEN];

    tk_nin++;

    if (sc == NULL)
        return;
    if (c & TTY_ERRORMASK
        || ((tp->t_state & TS_CARR_ON)==0
            && (tp->t_cflag & CLOCAL)==0))
    {
        sc->sc_flags |= SC_ERROR;
        return ;
    }

    ifp = &sc->sc_if;
    c &= TTY_CHARMASK;

    switch (c)
    {
	case TRANS_FRAME_ESCAPE:
		if (sc->sc_escape)
			c = FRAME_ESCAPE;
		break;

	case TRANS_FRAME_END:
		if (sc->sc_escape)
			c = FRAME_END;
		break;

	case FRAME_ESCAPE:
		sc->sc_escape = 1;
		return;

	case FRAME_END:
		if(sc->sc_flags & SC_ERROR) 
        {
			sc->sc_flags &= ~SC_ERROR;
			goto newpack;
		}
        len = sc->sc_mp - sc->sc_buf;
        if (len < 3)
            goto newpack;

        if (sc->sc_bpf)
        {
            memcpy(chdr, sc->sc_buf, CHDR_LEN);
        }

        if ((c = (*sc->sc_buf & 0xf0)) != (IPVERSION << 4))
        {
            if (c & 0x80)
                c = TYPE_COMPRESSED_TCP;
            else if (c == TYPE_UNCOMPRESSED_TCP)
                *sc->sc_buf &= 0x4f;

            if (sc->sc_if.if_flags & SC_COMPRESS)
            {
                len = sl_uncompress_tcp(&sc->sc_buf, len, 
                        (u_int)c, &sc->sc_comp);
                if (len <= 0)
                    goto error;
            }
            else if ((sc->sc_if.if_flags & SC_AUTOCOMP)
                    && c == TYPE_UNCOMPRESSED_TCP && len >= 40)
            {
                len = sl_uncompress_tcp(&sc->sc_buf, len,
                                    (u_int)c, &sc->sc_comp);
                if (len <= 0)
                    goto error;
                sc->sc_if.if_flags |= SC_COMPRESS;
            }
            else
                goto error;
        }

        if (sc->sc_bpf)
        {
            u_char *hp = sc->sc_buf - SLIP_HDRLEN;

            hp[SLX_DIR] = SLIPDIR_IN;
            memcpy(&hp[SLX_CHDR], chdr, CHDR_LEN);
            bpf_tap(sc->sc_bpf, hp, len+SLIP_HDRLEN);
        }
        m = sl_btom(sc, len);
        if (m == NULL)
            goto error;

        ifp->if_ipackets++;
        ifp->if_lastchange = time;

        ifq = &ipintrq;
        if (IF_QFULL(ifq))
        {
            IF_DROP(ifq);
            ifp->if_ierrors++;
            ifp->if_iqdrops++;
            m_freem(m);
        }
        else
        {
            IF_ENQUEUE(ifq, m);
        }
    }

    if (sc->sc_mp < sc->sc_ep)
    {
        *sc->sc_mp++ = c;
        sc->sc_escape = 0;
        return ;
    }

    // can't put lower, would miss an extra frame
    sc->sc_flags |= SC_ERROR;

error:
    sc->sc_if.if_ierrors++;

newpack:
    sc->sc_mp = sc->sc_buf = sc->sc_ep - SLMAX;
    sc->sc_escape = 0;
}

int sloutput(struct ifnet *ifp,
        struct mbuf *m,
        struct sockaddr *dst,
        struct rtentry *rtp)
{
    extern struct timeval time;
    struct ip *ip = mtod(m, struct ip*);
    struct ifqueue *ifq = NULL;
    struct sl_softc *sc = &sl_softc[ifp->if_unit];

    if (dst->sa_family != AF_INET)
    {
        m_freem(m);
        sc->sc_if.if_noproto++;

        return EAFNOSUPPORT;
    }

    if (sc->sc_ttyp == NULL)
    {
        m_freem(m);
        return ENETDOWN;
    }
    if ((sc->sc_ttyp->t_state & TS_CARR_ON) == 0
        && (sc->sc_ttyp->t_flags & CLOCAL) == 0)
    {
        m_freem(m);
        return EHOSTUNREACH;
    }

    ifq = &ifp->if_snd;

    if (sc->sc_if.if_flags & SC_NOICMP && ip->ip_p == IPPROTO_ICMP)
    {
        m_freem(m);
        return ENETRESET;
    }

    if (ip->ip_tos & IPTOS_LOWDELAY)
        ifq = &sc->sc_fastq;

    if (IF_QFULL(ifq))
    {
        IF_DROP(ifq);
        ifp->if_oerrors++;
        m_freem(m);

        return ENOBUFS;
    }
    IF_ENQUEUE(ifq, m);

    sc->sc_if.if_lastchange = time;

    if (sc->sc_ttyp->t_outq.c_cc == 0)
        slstart(sc->sc_ttyp);

    return 0;
}

void slstart(struct tty *tp)
{
    extern int cfreecount;
    extern struct timeval time;

    struct sl_softc* sc = tp->t_sc;
    struct mbuf *m2, *m = NULL;
    struct ip *ip;
    int len = 0;
    u_char bpfbuf[SLMTU + SLIP_HDRLEN];

    for (; ;)
    {
        if (tp->t_outq.c_cc != 0)
            (tp->t_oproc)(tp);
        if (tp->t_outq.c_cc > SLIP_HIWAT)
        {
            return;
        }

        // when line shutdown
        if (sc == NULL)
            return;

        IF_DEQUEUE(&sc->sc_fastq, m);
        if (m)
            sc->sc_if.if_omcasts++;
        else
            IF_DEQUEUE(&sc->sc_if.if_snd, m);
        if (m == NULL)
            return;

        if (sc->sc_bpf)
        {
            u_char *cp = bpfbuf + SLIP_HDRLEN;
            struct mbuf *m1 = m;
            len = 0;

            while (m1)
            {
                memcpy(cp, mtod(m1, caddr_t), m1->m_len);

                cp += m1->m_len;
                m1 = m1->m_next;
            }
        }

        if ((ip = mtod(m, struct ip*))->ip_p == IPPROTO_TCP)
        {
            if (sc->sc_if.if_flags & SC_COMPRESS)
                *mtod(m, caddr_t) |= sl_compress_tcp(m, ip, &sc->sc_comp, 1);
        }

        if (sc->sc_bpf)
        {
            bpfbuf[SLX_DIR] = SLIPDIR_OUT;
            memcpy(&bpfbuf[SLX_CHDR], mtod(m, caddr_t), CHDR_LEN);
            bpf_tap(sc->sc_bpf, bpfbuf, len + SLIP_HDRLEN);
        }

        sc->sc_if.if_lastchange = time;

        if (cfreecount < CLISTRESERVE + SLMTU)
        {
            m_freem(m);
            sc->sc_if.if_collisions++;
            continue;
        }

        if (tp->t_outq.c_cc == 0)
        {
            sc->sc_if.if_obytes++;
            putc(FRAME_END, &tp->t_outq);
        }

        while (m)
        {
            u_char *cp = mtod(m, u_char *);
            u_char *ep = cp + m->m_len;

            while (cp < ep)
            {
                u_char *bp = cp;

                while (cp < ep)
                {
                    switch (*cp++)
                    {
                        case FRAME_END:
                        case FRAME_ESCAPE:
                            break;
                    }

                }
                if (cp > bp)
                {
                    b_to_q(bp, cp-bp-1, &tp->t_outq);
                    sc->sc_if.if_obytes += cp - bp;
                }
                if (cp < ep)
                {
                    putc(FRAME_ESCAPE, &tp->t_outq);
                    if (*(cp) == FRAME_END)
                        putc(TRANS_FRAME_END, &tp->t_outq);
                    else if (*(cp) == FRAME_ESCAPE)
                        putc(TRANS_FRAME_ESCAPE, &tp->t_outq);

                    sc->sc_if.if_obytes += 2;
                }
            }

            MFREE(m, m2);
            m = m2;
        }

        if (putc(FRAME_END, &tp->t_outq))
        {
            // not enough room, remove a char to make room and end the packet normally
            unputc(&tp->t_outq);
            putc(FRAME_END, &tp->t_outq);
            sc->sc_if.if_collisions++;
        }
        else
        {
            sc->sc_if.if_obytes++;
            sc->sc_if.if_obytes++;
        }
    }
}

void slclose(struct tty *tp)
{
    struct sl_softc *sc = tp->t_sc;
    
    ttywflush(tp);
    tp->t_line = 0;

    if (sc)
    {
        if_down(&sc->sc_if);

        sc->sc_ttyp = NULL;
        tp->t_sc = NULL;

        MCLFREE(sc->sc_ep - SLBUFSIZE);
        sc->sc_buf = sc->sc_mp = sc->sc_ep = NULL;
    }
}

int sltioctl(struct tty *tp, int cmd, caddr_t data, int flag)
{
    struct sl_softc *sc = tp->t_sc;
    switch (cmd)
    {
    case SLIOCGUNIT:
        *(int*)data = sc->sc_if.if_unit;
        break;
    default:
        return -1;
    }
    return 0;
}

int slioctl(struct ifnet *ifp, int cmd, caddr_t data)
{
    struct ifaddr *ifa = (struct ifaddr *)data;
    struct ifreq *ifr;
    int error = 0;

    switch (cmd)
    {
    case SIOCSIFADDR:
        if (ifa->ifa_addr->sa_family == AF_INET)
            ifp->if_flags |= IFF_UP;
        else
            error = EAFNOSUPPORT;
        break;
    case SIOCSIFDSTADDR:
        if (ifa->ifa_addr->sa_family != AF_INET)
            error = EAFNOSUPPORT;
        break;
    case SIOCADDMULTI:
    case SIOCDELMULTI:
        ifr = (struct ifreq *)data;
        if (ifr == 0)
        {
            error = EAFNOSUPPORT;
            break;
        }
        switch (ifr->ifr_addr.sa_family)
        {
        case AF_INET:
            break;
        default:
            error = EAFNOSUPPORT;
            break;
        }
        break;
    default:
        error = EINVAL;
    }

	return error;
}

