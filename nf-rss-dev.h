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

#include "nf-log.h"

#include "libvig/verified/vigor-time.h"

#define FLAGS 0
#define RING_SIZE 64
#define RING_NAME_SIZE 8
#define POOL_SIZE 1024
#define POOL_CACHE 32
#define PRIV_DATA_SIZE 0
#define STR_TOKEN_SIZE 128

#define RSS_HASH_KEY_LENGTH 40
static uint8_t hash_key[RSS_HASH_KEY_LENGTH] = {
  0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
  0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
  0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
  0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
  0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa
};

struct rte_eth_rss_conf rss_conf;

static const char *_MSG_POOL = "MSG_POOL";

struct lcore_ring {
  struct rte_ring *ring;
  char name[RING_NAME_SIZE];
  unsigned int lcore;
};

// lcore message
struct lcm {
  struct rte_mbuf *mbuf;

  uint16_t device;
  uint8_t* packet;
  uint16_t packet_length;
  vigor_time_t now;
};

static inline void print_message(struct lcm* msg) {
  NF_DEBUG("****MESSAGE****");
  NF_DEBUG("mbug %p", msg->mbuf);
  NF_DEBUG("device %d", msg->device);
  NF_DEBUG("packet %p", msg->packet);
  NF_DEBUG("packet length %d", msg->packet_length);
  NF_DEBUG("now %ld", msg->now);
}

static inline struct lcm* build_message(
  struct rte_mbuf *mbuf, uint16_t device, uint8_t* packet,
  uint16_t packet_length, vigor_time_t now) {

  NF_DEBUG("**** BUILDING MESSAGE ****");
  NF_DEBUG("mbug %p", mbuf);
  NF_DEBUG("device %d", device);
  NF_DEBUG("packet %p", packet);
  NF_DEBUG("packet length %d", packet_length);

  struct lcm *msg = (struct lcm*) rte_malloc(NULL, sizeof(struct lcm), 0);

  if (!msg) {
    rte_panic("malloc failure\n");
  }

  msg->mbuf = mbuf;
  msg->device = device;

  msg->packet = malloc(sizeof(uint8_t) * msg->packet_length);
  if (!msg->packet) {
    rte_panic("malloc failure on msg->packet\n");
  }

  memcpy(msg->packet, packet, sizeof(uint8_t) * msg->packet_length);
  msg->packet_length = packet_length;
  msg->now = now;

  NF_DEBUG("**** BUILT MESSAGE ****");
  NF_DEBUG("mbug %p", msg->mbuf);
  NF_DEBUG("device %d", msg->device);
  NF_DEBUG("packet %p", msg->packet);
  NF_DEBUG("packet length %d", msg->packet_length);
  NF_DEBUG("now %ld", msg->now);

  return msg;
}

static struct lcore_ring *rings;

static inline void virtual_rss_init(void) {
  unsigned int lcores = rte_lcore_count();
  unsigned int lcore;

  rings = (struct lcore_ring*) malloc(sizeof(struct lcore_ring) * lcores);

  for (unsigned int lcore = 0; lcore < lcores; lcore++) {
    snprintf(rings[lcore].name, RING_NAME_SIZE, "RING_%d", lcore);
    rings[lcore].lcore = lcore;
    rings[lcore].ring = rte_ring_create(rings[lcore].name, RING_SIZE, rte_socket_id(), FLAGS);
  }
}

static inline void lcore_distributor_process(
  struct rte_mbuf* mbuf,
  uint16_t device, uint8_t* buffer, uint16_t buffer_length,
  vigor_time_t now) {
  
  unsigned lcore_id = rte_lcore_id();

  NF_DEBUG("[MASTER] %d -> %d slave", lcore_id, 1);

  if (rte_ring_enqueue(rings[1].ring, build_message(mbuf, device, buffer, buffer_length, now)) < 0) {
    rte_exit(EXIT_FAILURE, "Failed to send message - message discarded\n");
  }
}

static inline struct lcm* lcore_slave_process(void) {
  unsigned lcore_id = rte_lcore_id();
  void* msg;

  if (rte_ring_dequeue(rings[lcore_id].ring, msg) < 0)
    return NULL;

  NF_DEBUG("[SLAVE] %d <- MASTER", lcore_id);
  print_message(msg);

  return (struct lcm*)msg;
}
