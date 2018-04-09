#include "radix.h"
#include "../sys/domain.h"
#include "../sys/systm.h"
#include "../sys/param.h"

/*
 * Routines to build and maintain radix trees for routing lookups.
 */
/*#ifndef RNF_NORMAL*/
/*#include <sys/param.h>*/
/*#include <sys/systm.h>*/
/*#include <sys/malloc.h>*/
/*#define	M_DONTWAIT M_NOWAIT*/
/*#ifdef	KERNEL*/
/*#include <sys/domain.h>*/
/*#endif*/
/*#endif*/

/*#include <net/radix.h>*/

int	max_keylen;
struct radix_mask *rn_mkfreelist;
struct radix_node_head *mask_rnhead;
static int gotOddMasks;
static char *maskedKey;
static char *rn_zeros, *rn_ones;

#define rn_masktop (mask_rnhead->rnh_treetop)
#undef Bcmp
#define Bcmp(a, b, l) (l == 0 ? 0 : bcmp((caddr_t)(a), (caddr_t)(b), (u_long)l))
/*
 * The data structure for the keys is a radix tree with one way
 * branching removed.  The index rn_b at an internal node n represents a bit
 * position to be tested.  The tree is arranged so that all descendants
 * of a node n have keys whose bits all agree up to position rn_b - 1.
 * (We say the index of n is rn_b.)
 *
 * There is at least one descendant which has a one bit at position rn_b,
 * and at least one with a zero there.
 *
 * A route is determined by a pair of key and mask.  We require that the
 * bit-wise logical and of the key and mask to be the key.
 * We define the index of a route to associated with the mask to be
 * the first bit number in the mask where 0 occurs (with bit number 0
 * representing the highest order bit).
 * 
 * We say a mask is normal if every bit is 0, past the index of the mask.
 * If a node n has a descendant (k, m) with index(m) == index(n) == rn_b,
 * and m is a normal mask, then the route applies to every descendant of n.
 * If the index(m) < rn_b, this implies the trailing last few bits of k
 * before bit b are all 0, (and hence consequently true of every descendant
 * of n), so the route applies to all descendants of the node as well.
 *
 * The present version of the code makes no use of normal routes,
 * but similar logic shows that a non-normal mask m such that
 * index(m) <= index(n) could potentially apply to many children of n.
 * Thus, for each non-host route, we attach its mask to a list at an internal
 * node as high in the tree as we can go. 
 */

struct radix_node *
rn_search(v_arg, head)
	void *v_arg;
	struct radix_node *head;
{
    return NULL;
};

struct radix_node *
rn_search_m(v_arg, head, m_arg)
	struct radix_node *head;
	void *v_arg, *m_arg;
{
    return NULL;
};

int
rn_refines(m_arg, n_arg)
	void *m_arg, *n_arg;
{
    return 0;
}


struct radix_node *
rn_match(v_arg, head)
	void *v_arg;
	struct radix_node_head *head;
{
    return NULL;
};
		
#ifdef RN_DEBUG
int	rn_nodenum;
struct	radix_node *rn_clist;
int	rn_saveinfo;
int	rn_debug =  1;
#endif

struct radix_node *
rn_newpair(v, b, nodes)
	void *v;
	int b;
	struct radix_node nodes[2];
{
    return NULL;
}

struct radix_node *
rn_insert(v_arg, head, dupentry, nodes)
	void *v_arg;
	struct radix_node_head *head;
	int *dupentry;
	struct radix_node nodes[2];
{
    return NULL;
}

struct radix_node *
rn_addmask(n_arg, search, skip)
	int search, skip;
	void *n_arg;
{
    return NULL;
}

struct radix_node *
rn_addroute(v_arg, n_arg, head, treenodes)
	void *v_arg, *n_arg;
	struct radix_node_head *head;
	struct radix_node treenodes[2];
{
    return NULL;
}

struct radix_node *
rn_delete(v_arg, netmask_arg, head)
	void *v_arg, *netmask_arg;
	struct radix_node_head *head;
{
    return NULL;
}

int
rn_walktree(h, f, w)
	struct radix_node_head *h;
	register int (*f)();
	void *w;
{
    return 0;
}

int
rn_inithead(head, off)
	void **head;
	int off;
{
    return 0;
}

void
rn_init()
{

}
