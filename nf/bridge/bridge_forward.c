#include <inttypes.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>

// DPDK uses these but doesn't include them. :|
#include <linux/limits.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "lib/nf_forward.h"
#include "lib/nf_util.h"
#include "lib/nf_log.h"
#include "bridge_config.h"

#include "map.h"
#include "vector.h"

struct bridge_config config;

struct StaticKey {
  struct ether_addr addr;
  uint8_t device;
};

struct DynamicEntry {
  struct ether_addr addr;
  uint8_t device;
};

struct DynamicFilterTable {
  struct Map* map;
  struct DoubleChain* heap;
  struct Vector* entries;
};

struct StaticFilterTable {
  struct Map* map;
  struct Vector* keys;
};

struct StaticFilterTable static_ft;
struct DynamicFilterTable dynamic_ft;

int ether_addr_eq(void* k1, void* k2) {
  struct ether_addr* a = (struct ether_addr*)k1;
  struct ether_addr* b = (struct ether_addr*)k2;
  return 0 == memcmp(a->addr_bytes,
                     b->addr_bytes,
                     6);
}

int static_key_eq(void* k1, void* k2) {
  struct StaticKey* a = (struct StaticKey*) k1;
  struct StaticKey* b = (struct StaticKey*) k2;
  return a->device == b->device && ether_addr_eq(&a->addr, &b->addr);

}

int ether_addr_hash(void* k) {
  struct ether_addr* addr = (struct ether_addr*)k;
  return (int)((*(uint32_t*)addr->addr_bytes) ^
               (*(uint32_t*)(addr->addr_bytes + 2)));
}

int static_key_hash(void* key) {
  struct StaticKey *k = (struct StaticKey*)key;
  return (ether_addr_hash(&k->addr) << 2) ^ k->device;
}

int bridge_expire_entries(uint32_t time) {
  int count = 0;
  int index = -1;
  void *trash;
  if (time < config.expiration_time) return 0;
  uint32_t min_time = time - config.expiration_time;
  while (dchain_expire_one_index(dynamic_ft.heap, &index, min_time)) {
    struct DynamicEntry* entry = vector_borrow(dynamic_ft.entries, index);
    map_erase(dynamic_ft.map, &entry->addr, &trash);
    vector_return(dynamic_ft.entries, index, entry);
    ++count;
  }
  return count;
}

int bridge_get_device(struct ether_addr* dst,
                      uint8_t src_device) {
  int device = -1;
  struct StaticKey k;
  memcpy(&k.addr, dst, sizeof(struct ether_addr));
  k.device = src_device;
  int hash = static_key_hash(&k);
  int present = map_get(static_ft.map,
                        &k, &device);
  if (present) {
    return device;
  }

  int index = -1;
  hash = ether_addr_hash(dst);
  present = map_get(dynamic_ft.map, dst, &index);
  if (present) {
    struct DynamicEntry* entry = vector_borrow(dynamic_ft.entries, index);
    device = entry->device;
    vector_return(dynamic_ft.entries, index, entry);
    return device;
  }
  return -1;
}

void bridge_put_update_entry(struct ether_addr* src,
                            uint8_t src_device,
                            uint32_t time) {
  int device = -1;
  struct StaticKey k;
  memcpy(&k.addr, src, sizeof(struct ether_addr));
  k.device = src_device;
  int hash = static_key_hash(&k);
  int present = map_get(static_ft.map, &k, &device);
  if (present) {
    // Static entry does not need updating
    return;
  }

  int index = -1;
  hash = ether_addr_hash(src);
  present = map_get(dynamic_ft.map, src, &index);
  if (present) {
    dchain_rejuvenate_index(dynamic_ft.heap, index, time);
  } else {
    int allocated = dchain_allocate_new_index(dynamic_ft.heap,
                                              &index,
                                              time);
    if (!allocated) {
      NF_INFO("No more space in the dynamic table");
      return;
    }
    struct DynamicEntry* entry = vector_borrow(dynamic_ft.entries, index);
    memcpy(&entry->addr, src, sizeof(struct ether_addr));
    entry->device = device;
    map_put(dynamic_ft.map, &entry->addr, index);
    vector_return(dynamic_ft.entries, index, entry);
  }
}

void allocate_static_ft(int capacity) {
  map_allocate(static_key_eq, static_key_hash,
               capacity, &static_ft.map);
  vector_allocate(sizeof(struct StaticKey), capacity,
                  &static_ft.keys);
}

void read_static_ft_from_file() {
  if (config.static_config_fname[0] == '\0') {
    // No static config
    allocate_static_ft(1);
    return;
  }

  FILE* cfg_file = fopen(config.static_config_fname, "r");
  if (cfg_file == NULL) {
    NF_INFO("Error opening the static config file: %s",
            config.static_config_fname);

    int number_of_lines = 0;
    char ch;
    do {
      ch = fgetc(cfg_file);
      if(ch == '\n')
        number_of_lines++;
    } while (ch != EOF);

    // Make sure the hash table is occupied only by 50%
    int capacity = number_of_lines * 2;
    rewind(cfg_file);
    allocate_static_ft(capacity);
    int count = 0;

    while (1) {
      char mac_addr_str[20];
      char source_str[10];
      char target_str[10];
      int result = fscanf(cfg_file, "%18s", mac_addr_str);
      if (result != 1) {
        if (result == EOF) break;
        else {
          NF_INFO("Cannot read MAC address from file: %s",
                  strerror(errno));
          goto finally;
        }
      }

      result = fscanf(cfg_file, "%9s", source_str);
      if (result != 1) {
        if (result == EOF) {
          NF_INFO("Incomplete config string: %s, skip", mac_addr_str);
          break;
        } else {
          NF_INFO("Cannot read the filtering target for MAC %s: %s",
                  mac_addr_str, strerror(errno));
          goto finally;
        }
      }

      result = fscanf(cfg_file, "%9s", target_str);
      if (result != 1) {
        if (result == EOF) {
          NF_INFO("Incomplete config string: %s, skip", mac_addr_str);
          break;
        } else {
          NF_INFO("Cannot read the filtering target for MAC %s: %s",
                  mac_addr_str, strerror(errno));
          goto finally;
        }
      }

      int device_from;
      int device_to;
      char* temp;
      struct StaticKey* key = vector_borrow(static_ft.keys, count);

      // Ouff... the strings are extracted, now let's parse them.
      result = cmdline_parse_etheraddr(NULL, mac_addr_str,
                                       &key->addr,
                                       sizeof(struct ether_addr));
      if (result < 0) {
        NF_INFO("Invalid MAC address: %s, skip",
                mac_addr_str);
        continue;
      }

      device_from = strtol(source_str, &temp, 10);
      if (temp == target_str || *temp != '\0') {
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
      map_put(static_ft.map, &key->addr, device_to);
      vector_return(static_ft.keys, count, key);
      ++count;
      assert(count < number_of_lines);
    }
  }
 finally:
  fclose(cfg_file);
}

void nf_core_init(void)
{
  read_static_ft_from_file();

  int capacity = config.dyn_capacity;
  map_allocate(ether_addr_eq, ether_addr_hash,
               capacity, &dynamic_ft.map);
  dchain_allocate(capacity, &dynamic_ft.heap);
  vector_allocate(sizeof(struct DynamicEntry), capacity,
                  &dynamic_ft.entries);
}

int nf_core_process(uint8_t device,
                    struct rte_mbuf* mbuf,
                    uint32_t now)
{
  struct ether_hdr* ether_header = nf_get_mbuf_ether_header(mbuf);

  bridge_expire_entries(now);
  bridge_put_update_entry(&ether_header->s_addr, device, now);

  int dst_device = bridge_get_device(&ether_header->d_addr,
                                     device);

  if (dst_device == -1) {
    return FLOOD_FRAME;
  }

  if (dst_device == -2) {
    NF_DEBUG("filtered frame");
    return device;
  }

  return dst_device;
}

void nf_config_init(int argc, char** argv) {
  bridge_config_init(&config, argc, argv);
}

void nf_config_cmdline_print_usage(void) {
  bridge_config_cmdline_print_usage();
}

void nf_print_config() {
  bridge_print_config(&config);
}
