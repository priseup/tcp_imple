#ifndef _SYS_UIO_H_
#define	_SYS_UIO_H_

#include "cdefs.h"

/*
 * XXX
 * iov_base should be a void *.
 */
struct iovec {
	char	*iov_base;	/* Base address. */
	size_t	 iov_len;	/* Length. */
};

enum	uio_rw { UIO_READ, UIO_WRITE };

/* Segment flag values. */
enum uio_seg {
	UIO_USERSPACE,		/* from user data space */
	UIO_SYSSPACE,		/* from system space */
	UIO_USERISPACE		/* from user I space */
};

#ifdef KERNEL
struct uio {
	struct	iovec *uio_iov;
	int	uio_iovcnt;
	off_t	uio_offset;
	int	uio_resid;
	enum	uio_seg uio_segflg;
	enum	uio_rw uio_rw;
	struct	proc *uio_procp;
};

/*
 * Limits
 */
#define UIO_MAXIOV	1024		/* max 1K of iov's */
#define UIO_SMALLIOV	8		/* 8 on stack, else malloc */
#endif /* KERNEL */


__BEGIN_DECLS
ssize_t	readv __P((int, const struct iovec *, int));
ssize_t	writev __P((int, const struct iovec *, int));
__END_DECLS

#endif /* !_SYS_UIO_H_ */
