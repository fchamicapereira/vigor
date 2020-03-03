#include <inttypes.h>
// DPDK uses these but doesn't include them. :|
#include <linux/limits.h>
#include <sys/types.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_flow.h>

#include "libvig/verified/boilerplate-util.h"
#include "libvig/verified/packet-io.h"
#include "nf-log.h"
#include "nf-util.h"
#include "nf.h"

#ifdef KLEE_VERIFICATION
#  include "libvig/models/hardware.h"
#  include "libvig/models/verified/vigor-time-control.h"
#  include <klee/klee.h>
#endif // KLEE_VERIFICATION

#ifdef NFOS
#  define MAIN nf_main
#else // NFOS
#  define MAIN main
#endif // NFOS

#ifdef KLEE_VERIFICATION
#  define VIGOR_LOOP_BEGIN                                                     \
    unsigned _vigor_lcore_id = rte_lcore_id();                                 \
    vigor_time_t _vigor_start_time = start_time();                             \
    int _vigor_loop_termination = klee_int("loop_termination");                \
    unsigned VIGOR_DEVICES_COUNT;                                              \
    klee_possibly_havoc(&VIGOR_DEVICES_COUNT, sizeof(VIGOR_DEVICES_COUNT),     \
                        "VIGOR_DEVICES_COUNT");                                \
    vigor_time_t VIGOR_NOW;                                                    \
    klee_possibly_havoc(&VIGOR_NOW, sizeof(VIGOR_NOW), "VIGOR_NOW");           \
    unsigned VIGOR_DEVICE;                                                     \
    klee_possibly_havoc(&VIGOR_DEVICE, sizeof(VIGOR_DEVICE), "VIGOR_DEVICE");  \
    unsigned _d;                                                               \
    klee_possibly_havoc(&_d, sizeof(_d), "_d");                                \
    while (klee_induce_invariants() & _vigor_loop_termination) {               \
      nf_loop_iteration_border(_vigor_lcore_id, _vigor_start_time);            \
      VIGOR_NOW = current_time();                                              \
      /* concretize the device to avoid leaking symbols into DPDK */           \
      VIGOR_DEVICES_COUNT = rte_eth_dev_count();                               \
      VIGOR_DEVICE = klee_range(0, VIGOR_DEVICES_COUNT, "VIGOR_DEVICE");       \
      for (_d = 0; _d < VIGOR_DEVICES_COUNT; _d++)                             \
        if (VIGOR_DEVICE == _d) {                                              \
          VIGOR_DEVICE = _d;                                                   \
          break;                                                               \
        }                                                                      \
      stub_hardware_receive_packet(VIGOR_DEVICE);
#  define VIGOR_LOOP_END                                                       \
    stub_hardware_reset_receive(VIGOR_DEVICE);                                 \
    nf_loop_iteration_border(_vigor_lcore_id, VIGOR_NOW);                      \
    }
#else // KLEE_VERIFICATION
#  define VIGOR_LOOP_BEGIN                                                     \
    while (1) {                                                                \
      vigor_time_t VIGOR_NOW = current_time();                                 \
      unsigned VIGOR_DEVICES_COUNT = rte_eth_dev_count();                      \
      for (uint16_t VIGOR_DEVICE = 0; VIGOR_DEVICE < VIGOR_DEVICES_COUNT;      \
           VIGOR_DEVICE++) {
#  define VIGOR_LOOP_END                                                       \
    }                                                                          \
    }
#endif // KLEE_VERIFICATION

// Number of RX/TX queues
static const uint16_t RX_QUEUES_COUNT = 1;
static const uint16_t TX_QUEUES_COUNT = 1;

// Queue sizes for receiving/transmitting packets
// NOT powers of 2 so that ixgbe doesn't use vector stuff
// but they have to be multiples of 8, and at least 32, otherwise the driver
// refuses
static const uint16_t RX_QUEUE_SIZE = 96;
static const uint16_t TX_QUEUE_SIZE = 96;

void flood(struct rte_mbuf *frame, uint16_t skip_device, uint16_t nb_devices) {
  rte_mbuf_refcnt_set(frame, nb_devices - 1);
  int total_sent = 0;
  for (uint16_t device = 0; device < nb_devices; device++) {
    if (device == skip_device)
      continue;
    total_sent += rte_eth_tx_burst(device, 0, &frame, 1);
  }
  if (total_sent != nb_devices - 1) {
    rte_pktmbuf_free(frame);
  }
}

// Buffer count for mempools
static const unsigned MEMPOOL_BUFFER_COUNT = 256;

#define RSS_HASH_KEY_LENGTH 40
static uint8_t hash_key[RSS_HASH_KEY_LENGTH] = {
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
        0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
        0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
        0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
        0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa
};

// --- Initialization ---
static int nf_init_device(uint16_t device, struct rte_mempool *mbuf_pool) {
  int retval;

  // device_conf passed to rte_eth_dev_configure cannot be NULL
  struct rte_eth_conf device_conf;
  memset(&device_conf, 0, sizeof(struct rte_eth_conf));
  device_conf.rxmode.hw_strip_crc = 1;

  // RSS configuration (symmetric RSS using hash function defined above)
  device_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;

  struct rte_eth_rss_conf rss_conf;
  rss_conf.rss_key = hash_key;
  rss_conf.rss_key_len = RSS_HASH_KEY_LENGTH;
  rss_conf.rss_hf = ETH_RSS_IP;

  device_conf.rx_adv_conf.rss_conf = rss_conf;

  // Configure the device
  retval = rte_eth_dev_configure(device, RX_QUEUES_COUNT, TX_QUEUES_COUNT,
                                 &device_conf);
  if (retval != 0) {
    return retval;
  }

  // Allocate and set up TX queues
  for (int txq = 0; txq < TX_QUEUES_COUNT; txq++) {
    retval = rte_eth_tx_queue_setup(device, txq, TX_QUEUE_SIZE,
                                    rte_eth_dev_socket_id(device), NULL);
    if (retval != 0) {
      return retval;
    }
  }

  // Allocate and set up RX queues
  for (int rxq = 0; rxq < RX_QUEUES_COUNT; rxq++) {
    retval = rte_eth_rx_queue_setup(device, rxq, RX_QUEUE_SIZE,
                                    rte_eth_dev_socket_id(device),
                                    NULL, // default config
                                    mbuf_pool);
    if (retval != 0) {
      return retval;
    }
  }

  // Start the device
  retval = rte_eth_dev_start(device);
  if (retval != 0) {
    return retval;
  }

  // Enable RX in promiscuous mode, just in case
  rte_eth_promiscuous_enable(device);
  if (rte_eth_promiscuous_get(device) != 1) {
    return retval;
  }

  // create RSS flow
  // struct rte_flow_attr attr;
  // struct rte_flow_item pattern[4];
  // struct rte_flow_action actions[4];

  // struct rte_flow_item_eth eth_spec;
  // struct rte_flow_item_eth eth_mask;
  // struct rte_flow_item_vlan vlan_spec;
  // struct rte_flow_item_vlan vlan_mask;
  // struct rte_flow_item_ipv4 ip_spec;
  // struct rte_flow_item_ipv4 ip_mask;

  // uint16_t queues[4];
  // struct rte_flow_action_rss rss;

  // struct rte_flow *flow;
  // struct rte_flow_error error;

  // /* setting flow pattern */
  // memset(pattern, 0, sizeof(pattern));
  // memset(actions, 0, sizeof(actions));

  // /*
  //  * set the rule attribute.
  //  * in this case only ingress packets will be checked.
  //  */
  // memset(&attr, 0, sizeof(struct rte_flow_attr));
  // attr.ingress = 1;

  // /*
  //  * set the first level of the pattern (eth).
  //  * since in this example we just want to get the
  //  * ipv4 we set this level to allow all.
  //  */
  // memset(&eth_spec, 0, sizeof(struct rte_flow_item_eth));
  // memset(&eth_mask, 0, sizeof(struct rte_flow_item_eth));
  // eth_spec.type = 0;
  // eth_mask.type = 0;
  // pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
  // pattern[0].spec = &eth_spec;
  // pattern[0].mask = &eth_mask;

  // /*
  //  * setting the second level of the pattern (vlan).
  //  * since in this example we just want to get the
  //  * ipv4 we also set this level to allow all.
  //  */
  // memset(&vlan_spec, 0, sizeof(struct rte_flow_item_vlan));
  // memset(&vlan_mask, 0, sizeof(struct rte_flow_item_vlan));
  // pattern[1].type = RTE_FLOW_ITEM_TYPE_VLAN;
  // pattern[1].spec = &vlan_spec;
  // pattern[1].mask = &vlan_mask;

  // /*
  //  * setting the third level of the pattern (ip).
  //  * in this example this is the level we care about
  //  * so we set it according to the parameters.
  //  */
  // memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
  // memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
  // pattern[2].type = RTE_FLOW_ITEM_TYPE_IPV4;
  // pattern[2].spec = &ip_spec;
  // pattern[2].mask = &ip_mask;

  // pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

  // /* create the drop action */
  // // rss.types = ETH_RSS_NONFRAG_IPV4_TCP;
  // // rss.level = 0;
  // // rss.func = RTE_ETH_HASH_FUNCTION_SIMPLE_XOR;

  // actions[0].type = RTE_FLOW_ACTION_TYPE_DROP;
  // actions[1].type = RTE_FLOW_ACTION_TYPE_END;

  // /* validate and create the flow rule */
  
  // if (!rte_flow_validate(device, &attr, pattern, actions, &error))
  //     flow = rte_flow_create(device, &attr, pattern, actions, &error);
  // else {
  //   rte_exit(EXIT_FAILURE, "Flow can't be created %d message: %s\n",
  //                   error.type,
  //                   error.message ? error.message : "(no stated reason)");
  // }

  // struct rte_eth_dev_info dev_info;
  // rte_eth_dev_info_get(device, &dev_info);
  
  // NF_DEBUG("driver name %s", dev_info.driver_name);
  // NF_DEBUG("flow_type_rss_offloads %lu", dev_info.flow_type_rss_offloads);

  return 0;
}

// --- Per-core work ---

static void lcore_main(void) {
  for (uint16_t device = 0; device < rte_eth_dev_count(); device++) {
    if (rte_eth_dev_socket_id(device) > 0 &&
        rte_eth_dev_socket_id(device) != (int)rte_socket_id()) {
      NF_INFO("Device %" PRIu8 " is on remote NUMA node to polling thread.",
              device);
    }
  }

  if (!nf_init()) {
    rte_exit(EXIT_FAILURE, "Error initializing NF");
  }

  NF_INFO("Core %u forwarding packets.", rte_lcore_id());

  VIGOR_LOOP_BEGIN
    struct rte_mbuf *mbuf;
    if (nf_receive_packet(VIGOR_DEVICE, &mbuf)) {        
      uint8_t* packet = rte_pktmbuf_mtod(mbuf, uint8_t*);
      NF_DEBUG("[%d] hash %u", rte_lcore_id(), mbuf->hash.rss);

      uint16_t dst_device = nf_process(mbuf->port, packet, mbuf->data_len, VIGOR_NOW);
      nf_return_all_chunks(packet);

      if (dst_device == VIGOR_DEVICE) {
        nf_free_packet(mbuf);
      } else if (dst_device == FLOOD_FRAME) {
        flood(mbuf, VIGOR_DEVICE, VIGOR_DEVICES_COUNT);
      } else {
        concretize_devices(&dst_device, rte_eth_dev_count());
        nf_send_packet(mbuf, dst_device);
      }
    }
  VIGOR_LOOP_END
}

// --- Main ---

int MAIN(int argc, char *argv[]) {
  // Initialize the Environment Abstraction Layer (EAL)
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "Error with EAL initialization, ret=%d\n", ret);
  }
  argc -= ret;
  argv += ret;

  // NF-specific config
  nf_config_init(argc, argv);
  nf_config_print();

  // Create a memory pool
  unsigned nb_devices = rte_eth_dev_count();
  struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(
      "MEMPOOL",                         // name
      MEMPOOL_BUFFER_COUNT * nb_devices, // #elements
      0, // cache size (per-lcore, not useful in a single-threaded app)
      0, // application private area size
      RTE_MBUF_DEFAULT_BUF_SIZE, // data buffer size
      rte_socket_id()            // socket ID
  );
  if (mbuf_pool == NULL) {
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool: %s\n",
             rte_strerror(rte_errno));
  }

  // Initialize all devices
  for (uint16_t device = 0; device < nb_devices; device++) {
    ret = nf_init_device(device, mbuf_pool);
    if (ret == 0) {
      NF_INFO("Initialized device %" PRIu16 ".", device);
    } else {
      rte_exit(EXIT_FAILURE, "Cannot init device %" PRIu16 ", ret=%d", device,
               ret);
    }
  }

  nf_util_init();

  // Run!
  // ...in single-threaded mode, that is.
  
  // ... UNTIL NOW

  unsigned lcore_id;

  // call on each lcore
  rte_eal_mp_remote_launch((lcore_function_t *)lcore_main, NULL, CALL_MASTER);

  return 0;
}
