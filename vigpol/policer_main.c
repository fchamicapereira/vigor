#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "nf.h"
#include "nf-util.h"
#include "nf-log.h"
#include "policer_config.h"
#include "state.h"

#include "libvig/verified/double-chain.h"
#include "libvig/verified/map.h"
#include "libvig/verified/vector.h"
#include "libvig/verified/expirator.h"

#include "nf-rss.h"

#define CHECK_WRITE_ATTEMPT(write_attempt_ptr, write_state_ptr) ({if (*(write_attempt_ptr) && !*(write_state_ptr)) { return 1; }})
#define WRITE_ATTEMPT(write_attempt_ptr, write_state_ptr) ({if (!*(write_state_ptr)) { *(write_attempt_ptr) = true; return 1; }})

struct nf_config config;

uint8_t hash_key[RSS_HASH_KEY_LENGTH] = {
  0xf2, 0xb8, 0x5f, 0xb0, 0x71, 0x0e, 0x98, 0xf5, 
  0x54, 0x15, 0x99, 0xa1, 0x0f, 0xf5, 0x56, 0xfa, 
  0x97, 0xa4, 0x76, 0xbc, 0xe2, 0x83, 0x5e, 0xce, 
  0xc1, 0xa2, 0x05, 0xa1, 0x2b, 0x3d, 0xf1, 0x1d, 
  0xf5, 0x50, 0xce, 0x67, 0x5e, 0x66, 0x5c, 0xb3, 
  0x7b, 0xf5, 0x54, 0x8b, 0xea, 0xab, 0x85, 0x81, 
  0x4f, 0xfb, 0x3d, 0x31
};

struct rte_eth_rss_conf rss_conf[MAX_NUM_DEVICES] = {
  {
    .rss_key = hash_key,
    .rss_key_len = RSS_HASH_KEY_LENGTH,
    .rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP
  },
  {
    .rss_key = hash_key,
    .rss_key_len = RSS_HASH_KEY_LENGTH,
    .rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP
  }
};

struct State *dynamic_ft;

int policer_expire_entries(vigor_time_t time) {
  assert(time >= 0); // we don't support the past
  vigor_time_t exp_time =
      VIGOR_TIME_SECONDS_MULTIPLIER * (config.burst / config.rate);
  uint64_t time_u = (uint64_t)time;
  // OK because time >= config.burst / config.rate >= 0
  vigor_time_t min_time = time_u - exp_time;

  return expire_items_single_map(dynamic_ft->dyn_heap,
                                 dynamic_ft->dyn_keys,
                                 dynamic_ft->dyn_map,
                                 min_time);
}

bool policer_check_tb(uint32_t dst, uint16_t size, vigor_time_t time) {
  bool* write_attempt = &RTE_PER_LCORE(write_attempt);
  bool* write_state = &RTE_PER_LCORE(write_state);

  int index = -1;
  int present = map_get(dynamic_ft->dyn_map, &dst, &index);
  if (present) {
    dchain_rejuvenate_index(dynamic_ft->dyn_heap, index, time);

    struct DynamicValue *value = 0;
    vector_borrow(dynamic_ft->dyn_vals, index, (void **)&value);

    assert(0 <= time);
    uint64_t time_u = (uint64_t)time;
    assert(sizeof(vigor_time_t) == sizeof(int64_t));
    assert(value->bucket_time >= 0);
    assert(value->bucket_time <= time_u);
    uint64_t time_diff = time_u - value->bucket_time;
    if (time_diff <
        config.burst * VIGOR_TIME_SECONDS_MULTIPLIER / config.rate) {
      uint64_t added_tokens =
          time_diff * config.rate / VIGOR_TIME_SECONDS_MULTIPLIER;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtautological-compare"
      vigor_note(0 <= time_diff * config.rate / VIGOR_TIME_SECONDS_MULTIPLIER);
#pragma GCC diagnostic pop
      assert(value->bucket_size <= config.burst);
      value->bucket_size += added_tokens;
      if (value->bucket_size > config.burst) {
        value->bucket_size = config.burst;
      }
    } else {
      value->bucket_size = config.burst;
    }
    value->bucket_time = time_u;

    bool fwd = false;
    if (value->bucket_size > size) {
      value->bucket_size -= size;
      fwd = true;
    }

    vector_return(dynamic_ft->dyn_vals, index, value);

    return fwd;
  } else {
    if (size > config.burst) {
      //NF_DEBUG("  Unknown flow with packet larger than burst size. Dropping.");
      return false;
    }

    WRITE_ATTEMPT(write_attempt, write_state);

    int allocated =
        dchain_allocate_new_index(dynamic_ft->dyn_heap, &index, time);
    if (!allocated) {
      //NF_DEBUG("No more space in the policer table");
      return false;
    }
    uint32_t *key;
    struct DynamicValue *value = 0;
    vector_borrow(dynamic_ft->dyn_keys, index, (void **)&key);
    vector_borrow(dynamic_ft->dyn_vals, index, (void **)&value);
    *key = dst;
    value->bucket_size = config.burst - size;
    value->bucket_time = time;
    map_put(dynamic_ft->dyn_map, key, index);
    // the other half of the key is in the map
    vector_return(dynamic_ft->dyn_keys, index, key);
    vector_return(dynamic_ft->dyn_vals, index, value);

    //NF_DEBUG("  New flow. Forwarding.");
    return true;
  }
}

bool nf_init(void) {
  unsigned capacity = config.dyn_capacity;
  dynamic_ft = alloc_state(capacity, rte_eth_dev_count());

  if (dynamic_ft == NULL) {
    return false;
  }

  return true;
}

int nf_process(uint16_t device, uint8_t* buffer, uint16_t buffer_length, vigor_time_t now) {
  bool* write_attempt = &RTE_PER_LCORE(write_attempt);
  bool* write_state = &RTE_PER_LCORE(write_state);

  struct ether_hdr *ether_header = nf_then_get_ether_header(buffer);
  uint8_t *ip_options;
  struct ipv4_hdr *ipv4_header =
      nf_then_get_ipv4_header(ether_header, buffer, &ip_options);
  if (ipv4_header == NULL) {
    NF_DEBUG("Not IPv4, dropping");
    return device;
  }

  policer_expire_entries(now);

  CHECK_WRITE_ATTEMPT(write_attempt, write_state);

  if (device == config.lan_device) {
    // Simply forward outgoing packets.
    //NF_DEBUG("Outgoing packet. Not policing.");
    return config.wan_device;
  } else if (device == config.wan_device) {
    // Police incoming packets.
    bool fwd = policer_check_tb(ipv4_header->dst_addr, buffer_length, now);

    CHECK_WRITE_ATTEMPT(write_attempt, write_state);

    if (fwd) {
      //NF_DEBUG("Incoming packet within policed rate. Forwarding.");
      return config.lan_device;
    } else {
      //NF_DEBUG("Incoming packet outside of policed rate. Dropping.");
      return config.wan_device;
    }
  } else {
    // Drop any other packets.
    //NF_DEBUG("Unknown port. Dropping.");
    return device;
  }
}
