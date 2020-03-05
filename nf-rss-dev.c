#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include "nf-rss-dev.h"


/*
struct output_buffer {
	unsigned count;
	struct rte_mbuf *mbufs[BURST_SIZE];
};

struct lcore_params {
	unsigned worker_id;
	struct rte_distributor *d;
	struct rte_ring *rx_dist_ring;
	struct rte_ring *dist_tx_ring;
	struct rte_mempool *mem_pool;
};
*/
