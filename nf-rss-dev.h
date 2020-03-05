#pragma once

#include <inttypes.h>
// DPDK uses these but doesn't include them. :|
#include <linux/limits.h>
#include <sys/types.h>

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>
#include <rte_log.h>
#include <rte_mempool.h>

#define FLAGS 0;
#define RING_SIZE 64;
#define POOL_SIZE 1024;
#define POOL_CACHE 32;
#define PRIV_DATA_SIZE 0;

#define RSS_HASH_KEY_LENGTH 40
static uint8_t hash_key[RSS_HASH_KEY_LENGTH] = {
    0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
    0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
    0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
    0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
    0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa
};

struct rte_eth_rss_conf rss_conf;

struct lcore_ring {
    struct rte_ring *send;
    struct rte_ring *recv;
};

static const char *_MSG_POOL = "MSG_POOL";
static const char *_SEC_2_PRI = "SEC_2_PRI";
static const char *_PRI_2_SEC = "PRI_2_SEC";

static struct lcore_rings *rings;
static struct rte_mempool *message_pool;

static inline void virtual_rss_init(void) {
    unsigned int lcores = rte_lcore_count();

    rings = (struct lcore_rings*) malloc(sizeof(struct lcore_rings) * lcores);

    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		send_ring = rte_ring_create(_PRI_2_SEC, RING_SIZE, rte_socket_id(), FLAGS);
		recv_ring = rte_ring_create(_SEC_2_PRI, RING_SIZE, rte_socket_id(), FLAGS);
		message_pool = rte_mempool_create(_MSG_POOL, pool_size,
				STR_TOKEN_SIZE, POOL_CACHE, PRIV_DATA_SIZE,
				NULL, NULL, NULL, NULL,
				rte_socket_id(), FLAGS);
	} else {
		recv_ring = rte_ring_lookup(_PRI_2_SEC);
		send_ring = rte_ring_lookup(_SEC_2_PRI);
		message_pool = rte_mempool_lookup(_MSG_POOL);
	}
}

static inline void lcore_distributor_main(void) {

}

static inline void lcore_slave_main(void) {
    unsigned lcore_id = rte_lcore_id();

	printf("Starting core %u\n", lcore_id);
	
    while (1) {
		void *msg;

		if (rte_ring_dequeue(recv_ring, &msg) < 0)
			continue;
		
		printf("core %u: Received '%s'\n", lcore_id, (char *)msg);
		rte_mempool_put(message_pool, msg);
	}
}
