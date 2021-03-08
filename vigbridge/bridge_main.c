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

#define CHECK_WRITE_ATTEMPT(write_attempt_ptr, write_state_ptr) ({if (*(write_attempt_ptr) && !*(write_state_ptr)) { return 1; }})
#define WRITE_ATTEMPT(write_attempt_ptr, write_state_ptr) ({if (!*(write_state_ptr)) { *(write_attempt_ptr) = true; return; }})

struct nf_config config;

uint8_t hash_key_0[RSS_HASH_KEY_LENGTH] = {
  0xf2, 0xb8, 0x5f, 0xb0, 0x71, 0x0e, 0x98, 0xf5, 
  0x54, 0x15, 0x99, 0xa1, 0x0f, 0xf5, 0x56, 0xfa, 
  0x97, 0xa4, 0x76, 0xbc, 0xe2, 0x83, 0x5e, 0xce, 
  0xc1, 0xa2, 0x05, 0xa1, 0x2b, 0x3d, 0xf1, 0x1d, 
  0xf5, 0x50, 0xce, 0x67, 0x5e, 0x66, 0x5c, 0xb3, 
  0x7b, 0xf5, 0x54, 0x8b, 0xea, 0xab, 0x85, 0x81, 
  0x4f, 0xfb, 0x3d, 0x31
};

uint8_t hash_key_1[RSS_HASH_KEY_LENGTH] = {
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

struct State * mac_tables;

int bridge_expire_entries(vigor_time_t time) {
  assert(time >= 0); // we don't support the past
  assert(sizeof(vigor_time_t) <= sizeof(uint64_t));
  uint64_t time_u = (uint64_t)time; // OK because of the two asserts
  vigor_time_t last_time = time_u - config.expiration_time * 1000; // us to ns
  return expire_items_single_map(mac_tables->dyn_heap, mac_tables->dyn_keys,
                                 mac_tables->dyn_map, last_time);
}

int bridge_get_device(struct ether_addr *dst, uint16_t src_device) {
  int device = -1;
  struct StaticKey k;
  memcpy(&k.addr, dst, sizeof(struct ether_addr));
  k.device = src_device;
  int present = map_get(mac_tables->st_map, &k, &device);
  if (present) {
    return device;
  }
#ifdef KLEE_VERIFICATION
  map_reset(mac_tables->dyn_map); // simplify the traces for easy validation
#endif                            // KLEE_VERIFICATION

  int index = -1;
  present = map_get(mac_tables->dyn_map, dst, &index);
  if (present) {
    struct DynamicValue *value = 0;
    vector_borrow(mac_tables->dyn_vals, index, (void **)&value);
    device = value->device;
    vector_return(mac_tables->dyn_vals, index, value);
    return device;
  }
  return -1;
}

void bridge_put_update_entry(struct ether_addr *src, uint16_t src_device,
                             vigor_time_t time) {
  bool* write_attempt = &RTE_PER_LCORE(write_attempt);
  bool* write_state = &RTE_PER_LCORE(write_state);

  int index = -1;
  int hash = ether_addr_hash(src);
  int present = map_get(mac_tables->dyn_map, src, &index);
  if (present) {
    dchain_rejuvenate_index(mac_tables->dyn_heap, index, time);
  } else {
    WRITE_ATTEMPT(write_attempt, write_state);

    int allocated =
        dchain_allocate_new_index(mac_tables->dyn_heap, &index, time);
    if (!allocated) {
      NF_INFO("No more space in the dynamic table");
      return;
    }
    struct ether_addr *key = 0;
    struct DynamicValue *value = 0;
    vector_borrow(mac_tables->dyn_keys, index, (void **)&key);
    vector_borrow(mac_tables->dyn_vals, index, (void **)&value);
    memcpy(key, src, sizeof(struct ether_addr));
    value->device = src_device;
    map_put(mac_tables->dyn_map, key, index);
    // the other half of the key is in the map
    vector_return(mac_tables->dyn_keys, index, key);
    vector_return(mac_tables->dyn_vals, index, value);
  }
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
  if (rte_get_master_lcore() != rte_lcore_id()) {
    return true;
  }
  
  unsigned stat_capacity = 8192; // Has to be power of 2
  unsigned capacity = config.dyn_capacity;
  assert(stat_capacity < CAPACITY_UPPER_LIMIT - 1);

  if (mac_tables != NULL) {
    return true;
  }

  mac_tables = alloc_state(capacity, stat_capacity, rte_eth_dev_count());
  if (mac_tables == NULL) {
    return false;
  }
#ifdef NFOS
  read_static_ft_from_array(mac_tables->st_map, mac_tables->st_vec,
                            stat_capacity);
#else
  read_static_ft_from_file(mac_tables->st_map, mac_tables->st_vec,
                           stat_capacity);
#endif
  return true;
}


int nf_process(uint16_t device, uint8_t* buffer, uint16_t buffer_length, vigor_time_t now) {
  bool* write_attempt = &RTE_PER_LCORE(write_attempt);
  bool* write_state = &RTE_PER_LCORE(write_state);

  struct ether_hdr *ether_header = nf_then_get_ether_header(buffer);

  bridge_expire_entries(now);
  CHECK_WRITE_ATTEMPT(write_attempt, write_state);

  bridge_put_update_entry(&ether_header->s_addr, device, now);
  CHECK_WRITE_ATTEMPT(write_attempt, write_state);

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
