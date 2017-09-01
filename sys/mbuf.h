#ifndef M_BUF_H
#define M_BUF_H

#include "types.h"
#include "malloc.h"
#include "../hp300/include/param.h"
#include <stdlib.h>

#define	MSIZE		128		/* size of an mbuf */

#define	MLEN		(MSIZE - sizeof(struct m_hdr))	/* normal data len */
#define	MHLEN		(MLEN - sizeof(struct pkthdr))	/* data len w/pkthdr */

#define	MINCLSIZE	(MHLEN + MLEN)	/* smallest amount to put in cluster */
#define	M_MAXCOMPRESS	(MHLEN / 2)	/* max amount to copy for compression */

/* mbuf±êÊ¶*/
#define M_EXT       0x0001    /* has associated external storage */
#define M_PKTHDR    0x0002    /* start of record */
#define M_EOR       0x0004    /* end of record */
#define M_BCAST     0x0100 /* send/received as link-level broadcast */
#define M_MCAST     0x0200 /* send/received as link-level multicast */
#define M_COPYFLAGS (M_PKTHDR|M_EOR|M_BCAST|M_MCAST)    /* flags copied when copying m_pkthdr */

/*
* Mbuf cluster macros.
* MCLALLOC(caddr_t p, int how) allocates an mbuf cluster.
* MCLGET adds such clusters to a normal mbuf;
* the flag M_EXT is set upon success.
* MCLFREE releases a reference to a cluster allocated by MCLALLOC,
* freeing the cluster if the reference count has reached 0.
*
* Normal mbuf clusters are normally treated as character arrays
* after allocation, but use the first word of the buffer as a free list
* pointer while on the free list.
*/
union mcluster {
    union	mcluster *mcl_next;
    char	mcl_buf[MCLBYTES];
};

struct mbuf;
/* header at beginning of each mbuf: */
struct m_hdr
{
    struct mbuf *mh_next;  /* next buffer in chain */
    struct mbuf *mh_nextpkt; /* next chain in queue/record */
    int         mh_len;   /* amount of data in this mbuf */
    caddr_t     mh_data;  /* location of data */
    short       mh_type;  /* type of data in this mbuf */
    short       mh_flags;  /* flags; see below */
};

struct ifnet; // forward declaring
/* record/packet header in first mbuf of chain; valid if M_PKTHDR set */
struct pkthdr
{
    int len;  /* total packet length */
    struct ifnet *rcvif; /* rcv interface */
};

/* description of external storage mapped into mbuf, valid if M_EXT set */
struct m_ext
{
    caddr_t ext_buf;  /* start of buffer */
    void (*ext_free)();  /* free routine if not the usual */
    u_int ext_size;  /* size of buffer, for ext_free */
};

struct mbuf
{
    struct m_hdr m_hdr;
    union
    {
        struct
        {
            struct pkthdr MH_pkthdr; /* M_PKTHDR set */
            union
            {
                struct m_ext MH_ext; /* M_EXT set */
                char MH_databuf[MHLEN];
            } MH_dat;
        } MH;
        char M_databuf[MLEN];  /* !M_PKTHDR, !M_EXT */
    } M_dat;
};

#define    m_next           m_hdr.mh_next
#define    m_len            m_hdr.mh_len
#define    m_data           m_hdr.mh_data
#define    m_type           m_hdr.mh_type
#define    m_flags          m_hdr.mh_flags
#define    m_nextpkt        m_hdr.mh_nextpkt
#define    m_act            m_nextpkt
#define    m_pkthdr         M_dat.MH.MH_pkthdr
#define    m_ext            M_dat.MH.MH_dat.MH_ext
#define    m_pktdat         M_dat.MH.MH_dat.MH_databuf
#define    m_dat            M_dat.M_databuf

/* mbuf types */
#define MT_FREE   0 /* should be on free list */
#define MT_DATA   1 /* dynamic (data) allocation */
#define MT_HEADER 2 /* packet header */
#define MT_SOCKET 3 /* socket structure */
#define MT_PCB    4 /* protocol control block */
#define MT_RTABLE 5 /* routing tables */
#define MT_HTABLE 6 /* IMP host tables */
#define MT_ATABLE 7 /* address resolution tables */
#define MT_SONAME 8 /* socket name */
#define MT_SOOPTS 10 /* socket options */
#define MT_FTABLE 11 /* fragment reassembly header */
#define MT_RIGHTS 12 /* access rights */XZv

/*
* Macros for type conversion
* mtod(m,t) -	convert mbuf pointer to data pointer of correct type
* dtom(x) -	convert data pointer within mbuf to mbuf pointer (XXX)
* mtocl(x) -	convert pointer within cluster to cluster index #
* cltom(x) -	convert cluster # to ptr to beginning of cluster
*/
#define mtod(m,t)	((t)((m)->m_data))
#define	dtom(x)		((struct mbuf *)((int)(x) & ~(MSIZE-1)))
#define	mtocl(x)	(((u_int)(x) - (u_int)mbutl) >> MCLSHIFT)
#define	cltom(x)	((caddr_t)((u_int)mbutl + ((u_int)(x) << MCLSHIFT)))

#define MGET(m, how, type) \
{ \
    (m) = (struct mbuf*)malloc(sizeof(struct mbuf));  \
    /*MALLOC((m), struct mbuf *, MSIZE, mbtypes[type], (how));   */\
    if (m)  \
    { \
        (m)->m_type = (type);   \
        /*MBUFLOCK(mbstat.m_mtypes[type]++;) */\
        (m)->m_next = NULL; \
        (m)->m_nextpkt = NULL; \
        (m)->m_data = (m)->m_dat; \
        (m)->m_flags = 0; \
        (m)->m_len = 0; \
    }   \
    else    \
        (m) = m_retry((how), (type));    \
}

#define MCLALLOC(p, how) \
{   \
    if (mclfree == NULL)    \
        m_clalloc(1, (how));    \
    if ((p) = (caddr_t)mclfree) \
    {   \
        ++mclrefcnt[mtocl(p)];  \
        mbstat.m_clfree--;  \
        mclfree = ((union mcluster *)(p))->mcl_next;    \
    }   \
}

#define MCLFREE(p)  \
{   \
    if (--mclrefcnt[mtocl(p)] == 0) \
    {   \
        ((union mcluster *)(p))->mcl_next = mclfree;    \
        mclfree = (union mcluster *)(p);    \
        mbstat.m_clfree++;  \
    }   \
}

#define MCLGET(m, how) \
{   \
    (m)->m_ext.ext_buf = (caddr_t)malloc(MCLBYTES * sizeof(char));  \
    /*MALLOC((m)->m_ext.ext_buf, caddr_t, MCLBYTES, mbtypes[(m)->m_type], (how));   */\
    if ((m)->m_ext.ext_buf)   \
    {   \
        (m)->data = (m)->m_ext.ext_buf;   \
        (m)->m_flags |= M_EXT;   \
    }   \
}

#define MFREE(m, n) \
{   \
    (n) = (m)->m_next;   \
    (n)->m_type = (m)->m_type;   \
    (n)->m_flags = (m)->m_flags & ~M_EXT;\
    int ref = 2;   \
    ref--;   \
    if ((m)->m_flags & M_EXT)   \
    {   \
        if (ref == 0)   \
        {   \
            free((m)->m_ext.ext_buf);   \
        }   \
        free((m));  \
        /*FREE((m)->m_ext.ext.buf);   */\
        /*FREE((m));   */\
        (n)->m_flags |= M_PKTHDR;   \
    }   \
}

#define MGETHDR(m, how, type)   \
{   \
    (m) = (struct mbuf*)malloc(sizeof(struct mbuf));  \
    /*MALLOC((m), struct mbuf *, MSIZE, mbtypes[type], (how));   */\
    if (m)  \
    { \
        (m)->m_type = (type);   \
        /*MBUFLOCK(mbstat.m_mtypes[type]++;) */\
        (m)->m_next = NULL; \
        (m)->m_nextpkt = NULL; \
        (m)->m_data = (m)->m_pktdat; \
        (m)->m_flags = M_PKTHDR; \
        (m)->m_pkthdr.len = (m)->m_len = 0; \
        (m)->m_pkthdr.rcvif = NULL; \
    }   \
  /*else    */\
   /*(m) = m_retry((how), (type));    */\
}

#define MH_ALIGN(m, length)    \
{   \
    (m)->m_data += MHLEN - (length);   \
    (m)->m_len += (length);   \
    (m)->m_pkthdr.len += (length);   \
}

#define M_PREPEND(m, length, how)   \
{   \
    if (MHLEN - (m)->m_len >= (length))   \
    {   \
        (m)->m_data -= (length);   \
        (m)->m_len += (length);   \
        (m)->m_pkthdr.len += (length);   \
    }   \
    else if (MHLEN - (m)->m_len < (length))   \
    {   \
        struct mbuf *n;   \
        MGETHDR(n, how, (m)->m_type);   \
        n->m_type = (m)->m_type;   \
        n->m_flags = (m)->m_flags & ~M_EXT;   \
        n->m_nextpkt = (m)->m_nextpkt;   \
        n->m_pkthdr = (m)->m_pkthdr;   \
        MH_ALIGN(n, (length));   \
        n->m_next = (m);   \
    }   \
}



void m_adj(struct mbuf *m, int len);
void m_cat(struct mbuf *m, struct mbuf *n);

struct mbuf *m_copy(struct mbuf *m, int offset, int len);
void m_copydata(struct mbuf *m, int offset, int len, caddr_t cp);
void m_copyback(struct mbuf *m, int offset, int len, caddr_t cp);
struct mbuf *m_copym(struct mbuf *m, int offset, int len, int nowait);
struct mbuf *m_devget(char *buf, int len, int off, struct ifnet *ifp,
        void (*copy)(const void *, void *, u_int));
struct mbuf *m_free(struct mbuf *m);
void m_freem(struct mbuf *m);
struct mbuf *m_get(int nowait, int type);
struct mbuf *m_getclr(int nowait, int type);
struct mbuf *m_gethdr(int nowait, int type);
struct mbuf *m_pullup(struct mbuf *m, int len);

void m_reclaim();
struct mbuf *m_retry(int i, int t);

/* flags to m_get/MGET */
#define	M_DONTWAIT	M_NOWAIT
#define	M_WAIT		M_WAITOK

/* change mbuf to new type */
#define MCHTYPE(m, t) { \
	MBUFLOCK(mbstat.m_mtypes[(m)->m_type]--; mbstat.m_mtypes[t]++;) \
	(m)->m_type = t;\
}

/* length to m_copy to copy all */
#define	M_COPYALL	1000000000

/*
* Mbuf statistics.
*/
struct mbstat {
	u_long	m_mbufs;	/* mbufs obtained from page pool */
	u_long	m_clusters;	/* clusters obtained from page pool */
	u_long	m_spare;	/* spare field */
	u_long	m_clfree;	/* free clusters */
	u_long	m_drops;	/* times failed to find space */
	u_long	m_wait;		/* times waited for space */
	u_long	m_drain;	/* times drained protocols for space */
	u_short	m_mtypes[256];	/* type specific mbuf allocations */
};

extern	struct mbuf *mbutl;		/* virtual address of mclusters */
extern	char *mclrefcnt;		/* cluster reference counts */
struct	mbstat mbstat;
extern	int nmbclusters;
union	mcluster *mclfree;
int	max_linkhdr;			/* largest link-level header */
int	max_protohdr;			/* largest protocol header */
int	max_hdr;			/* largest link+protocol header */
int	max_datalen;			/* MHLEN - max_hdr */
extern	int mbtypes[];			/* XXX */

#endif  // M_BUF_H
