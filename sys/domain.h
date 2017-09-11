#ifndef SYS_DOMAIN_H
#define SYS_DOMAIN_H

#include "cdefs.h"
#include "../sys/types.h"
#include "protosw.h"


struct mbuf;
struct	domain {
    int	dom_family;		/* AF_xxx */
    char	*dom_name;
    void(*dom_init)		/* initialize domain data structures */
        __P((void));
    int(*dom_externalize)	/* externalize access rights */
        __P((struct mbuf *));
    int(*dom_dispose)		/* dispose of internalized rights */
        __P((struct mbuf *));
    struct	protosw *dom_protosw, *dom_protoswNPROTOSW;
    struct	domain *dom_next;
    int(*dom_rtattach)		/* initialize routing table */
        __P((void **, int));
    int	dom_rtoffset;		/* an arg to rtattach, in bits */
    int	dom_maxrtkey;		/* for routing layer */
};

struct domain *domains;

#endif  // SYS_DOMAIN_H
