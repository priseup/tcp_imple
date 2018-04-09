#ifndef SYS_MSGBUF_H
#define SYS_MSGBUF_H

#define	MSG_BSIZE	(4096 - 3 * sizeof(long))
struct	msgbuf {
#define	MSG_MAGIC	0x063061
	long	msg_magic;
	long	msg_bufx;		/* write pointer */
	long	msg_bufr;		/* read pointer */
	char	msg_bufc[MSG_BSIZE];	/* buffer */
};
#ifdef KERNEL
struct	msgbuf *msgbufp;
#endif

#endif  // SYS_MSGBUF_H
