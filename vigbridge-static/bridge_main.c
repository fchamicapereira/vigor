#ifdef KLEE_VERIFICATION
#  include "libvig/models/verified/map-control.h" //for map_reset
#endif                                                  // KLEE_VERIFICATION
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
// DPDK uses these but doesn't include them. :|
#include <linux/limits.h>
#include <sys/types.h>
#include <unistd.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <cmdline_parse_etheraddr.h>

#include "libvig/verified/double-chain.h"
#include "libvig/verified/map.h"
#include "libvig/verified/vector.h"
#include "libvig/verified/expirator.h"
#include "libvig/verified/ether.h"

#include "nf.h"
#include "nf-util.h"
#include "nf-log.h"
#include "bridge_config.h"
#include "state.h"
#include "nf-rss.h"

struct nf_config config;

uint8_t hash_key_0[RSS_HASH_KEY_LENGTH] = {
  0xb1, 0xa9, 0x17, 0x04, 0x5d, 0xd9, 0x72, 0xa7,
  0x97, 0x30, 0xdf, 0x62, 0x8f, 0xd9, 0xd3, 0x83,
  0xc7, 0xc3, 0x33, 0x0f, 0xcf, 0x5e, 0xf5, 0xb9,
  0x9e, 0xb8, 0x72, 0x19, 0x77, 0x99, 0x71, 0x29,
  0x42, 0x88, 0x2d, 0x9f, 0x62, 0x9f, 0x47, 0xf9,
  0xcf, 0x26, 0x5b, 0x5e, 0xff, 0x2e, 0xe1, 0xc6,
  0xf1, 0x14, 0xd5, 0xc0
};

uint8_t hash_key_1[RSS_HASH_KEY_LENGTH] = {
  0xe8, 0x68, 0x06, 0x61, 0x6d, 0x0a, 0xd7, 0xf6,
  0x70, 0x19, 0x8f, 0xe3, 0x7d, 0xa0, 0x8e, 0x79,
  0x85, 0x6a, 0x14, 0x24, 0xf2, 0x21, 0xd3, 0x21,
  0x78, 0xf1, 0x08, 0x45, 0xca, 0x49, 0x58, 0xb2,
  0xb1, 0x5e, 0x13, 0x1f, 0x69, 0xea, 0x15, 0xd9,
  0x03, 0xa4, 0xbc, 0x80, 0x44, 0x4b, 0xfa, 0xca,
  0xb5, 0x0e, 0xee, 0xa7
};

struct rte_eth_rss_conf rss_conf[MAX_NUM_DEVICES] = {
  {
    .rss_key = hash_key_0,
    .rss_key_len = RSS_HASH_KEY_LENGTH,
    .rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP
  },
  {
    .rss_key = hash_key_1,
    .rss_key_len = RSS_HASH_KEY_LENGTH,
    .rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP
  }
};

RTE_DEFINE_PER_LCORE(struct State *, mac_tables);

int bridge_expire_entries(vigor_time_t time) {
  assert(time >= 0); // we don't support the past
  assert(sizeof(vigor_time_t) <= sizeof(uint64_t));
  uint64_t time_u = (uint64_t)time; // OK because of the two asserts
  vigor_time_t last_time = time_u - config.expiration_time * 1000; // us to ns
  return expire_items_single_map(RTE_PER_LCORE(mac_tables)->dyn_heap,
                                 RTE_PER_LCORE(mac_tables)->dyn_keys,
                                 RTE_PER_LCORE(mac_tables)->dyn_map,
                                 last_time);
}

int bridge_get_device(struct ether_addr *dst, uint16_t src_device) {
  int device = -1;
  struct StaticKey k;
  memcpy(&k.addr, dst, sizeof(struct ether_addr));
  k.device = src_device;
  int present = map_get(RTE_PER_LCORE(mac_tables)->st_map, &k, &device);
  if (present) {
    return device;
  }
#ifdef KLEE_VERIFICATION
  map_reset(RTE_PER_LCORE(mac_tables)->dyn_map); // simplify the traces for easy validation
#endif                            // KLEE_VERIFICATION
  return -1;
}

// File parsing, is not really the kind of code we want to verify.
#ifdef KLEE_VERIFICATION
void read_static_ft_from_file(struct Map *stat_map, struct Vector *stat_keys,
                              uint32_t stat_capacity) {}

static void read_static_ft_from_array(struct Map *stat_map,
                                      struct Vector *stat_keys,
                                      uint32_t stat_capacity) {}

#else // KLEE_VERIFICATION

#  ifndef NFOS
static void read_static_ft_from_file(struct Map *stat_map,
                                     struct Vector *stat_keys,
                                     uint32_t stat_capacity) {
  if (config.static_config_fname[0] == '\0') {
    // No static config
    return;
  }

  FILE *cfg_file = fopen(config.static_config_fname, "r");
  if (cfg_file == NULL) {
    rte_exit(EXIT_FAILURE, "Error opening the static config file: %s",
             config.static_config_fname);
  }

  unsigned number_of_lines = 0;
  char ch;
  do {
    ch = fgetc(cfg_file);
    if (ch == '\n')
      number_of_lines++;
  } while (ch != EOF);

  // Make sure the hash table is occupied only by 50%
  unsigned capacity = number_of_lines * 2;
  rewind(cfg_file);
  if (stat_capacity <= capacity) {
    rte_exit(EXIT_FAILURE, "Too many static rules (%d), max: %d",
             number_of_lines, stat_capacity / 2);
  }
  int count = 0;

  while (1) {
    char mac_addr_str[20];
    char source_str[10];
    char target_str[10];
    int result = fscanf(cfg_file, "%18s", mac_addr_str);
    if (result != 1) {
      if (result == EOF)
        break;
      else {
        NF_INFO("Cannot read MAC address from file: %s", strerror(errno));
        goto finally;
      }
    }

    result = fscanf(cfg_file, "%9s", source_str);
    if (result != 1) {
      if (result == EOF) {
        NF_INFO("Incomplete config string: %s, skip", mac_addr_str);
        break;
      } else {
        NF_INFO("Cannot read the filtering target for MAC %s: %s", mac_addr_str,
                strerror(errno));
        goto finally;
      }
    }

    result = fscanf(cfg_file, "%9s", target_str);
    if (result != 1) {
      if (result == EOF) {
        NF_INFO("Incomplete config string: %s, skip", mac_addr_str);
        break;
      } else {
        NF_INFO("Cannot read the filtering target for MAC %s: %s", mac_addr_str,
                strerror(errno));
        goto finally;
      }
    }

    int device_from;
    int device_to;
    char *temp;
    struct StaticKey *key = 0;
    vector_borrow(stat_keys, count, (void **)&key);

    // Ouff... the strings are extracted, now let's parse them.
    result = cmdline_parse_etheraddr(NULL, mac_addr_str, &key->addr,
                                     sizeof(struct ether_addr));
    if (result < 0) {
      NF_INFO("Invalid MAC address: %s, skip", mac_addr_str);
      continue;
    }

    device_from = strtol(source_str, &temp, 10);
    if (temp == source_str || *temp != '\0') {
      NF_INFO("Non-integer value for the forwarding rule: %s (%s), skip",
              mac_addr_str, target_str);
      continue;
    }

    device_to = strtol(target_str, &temp, 10);
    if (temp == target_str || *temp != '\0') {
      NF_INFO("Non-integer value for the forwarding rule: %s (%s), skip",
              mac_addr_str, target_str);
      continue;
    }

    // Now everything is alright, we can add the entry
    key->device = device_from;
    map_put(stat_map, &key->addr, device_to);
    vector_return(stat_keys, count, key);
    ++count;
    assert(count < capacity);
  }
finally:
  fclose(cfg_file);
}
#  endif // NFOS

struct {
  const char mac_addr[18];
  const int device_from;
  const int device_to;
} static_rules[] = {
  { "00:00:00:00:00:00", 0, 0 },
};

static void read_static_ft_from_array(struct Map *stat_map,
                                      struct Vector *stat_keys,
                                      uint32_t stat_capacity) {
  unsigned number_of_entries = sizeof(static_rules) / sizeof(static_rules[0]);

  // Make sure the hash table is occupied only by 50%
  unsigned capacity = number_of_entries * 2;
  if (stat_capacity <= capacity) {
    rte_exit(EXIT_FAILURE, "Too many static rules (%d), max: %d",
             number_of_entries, CAPACITY_UPPER_LIMIT / 2);
  }
  int count = 0;

  for (int idx = 0; idx < number_of_entries; idx++) {
    struct StaticKey *key = 0;
    vector_borrow(stat_keys, count, (void **)&key);

    int result = cmdline_parse_etheraddr(NULL, static_rules[idx].mac_addr,
                                         &key->addr, sizeof(struct ether_addr));
    if (result < 0) {
      NF_INFO("Invalid MAC address: %s, skip", static_rules[idx].mac_addr);
      continue;
    }

    // Now everything is alright, we can add the entry
    key->device = static_rules[idx].device_from;
    map_put(stat_map, &key->addr, static_rules[idx].device_to);
    vector_return(stat_keys, count, key);
    ++count;
    assert(count < capacity);
  }
}

#endif // KLEE_VERIFICATION

bool nf_init(void) {
  unsigned stat_capacity = 8192; // Has to be power of 2
  unsigned capacity = config.dyn_capacity;
  assert(stat_capacity < CAPACITY_UPPER_LIMIT - 1);
  struct State ** mac_tables_ptr = &RTE_PER_LCORE(mac_tables);
  (*mac_tables_ptr) = alloc_state(capacity, stat_capacity, rte_eth_dev_count());
  if ((*mac_tables_ptr) == NULL) {
    return false;
  }
#ifdef NFOS
  read_static_ft_from_array(RTE_PER_LCORE(mac_tables)->st_map,
                            RTE_PER_LCORE(mac_tables)->st_vec,
                            stat_capacity);
#else
  read_static_ft_from_file(RTE_PER_LCORE(mac_tables)->st_map,
                           RTE_PER_LCORE(mac_tables)->st_vec,
                           stat_capacity);
#endif
  return true;
}

int nf_process(uint16_t device, uint8_t* buffer, uint16_t buffer_length, vigor_time_t now) {
  struct ether_hdr *ether_header = nf_then_get_ether_header(buffer);

  bridge_expire_entries(now);

  int forward_to = bridge_get_device(&ether_header->d_addr, device);

  if (forward_to == -1) {
    return FLOOD_FRAME;
  }

  if (forward_to == -2) {
    NF_DEBUG("filtered frame");
    return device;
  }

  return forward_to;
}
