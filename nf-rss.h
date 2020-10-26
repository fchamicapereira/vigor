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
#include <rte_malloc.h>
#include <rte_mempool.h>

#define MBUF_CACHE_SIZE 256
#define RSS_HASH_KEY_LENGTH 52

extern struct rte_eth_rss_conf rss_conf;

struct lcore_conf {
  struct rte_mempool* mbuf_pool;
  uint16_t queue_id;
};

struct lcore_conf lcores_conf[RTE_MAX_LCORE];
