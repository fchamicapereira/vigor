#include <stdlib.h>

#include "flow.h.gen.h"
#include "fw_flowmanager.h"
#include "fw_config.h"
#include "nf.h"
#include "nf-log.h"
#include "nf-util.h"
#include "nf-rss.h"

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

RTE_DEFINE_PER_LCORE(struct FlowManager *, _flow_manager);

bool nf_init(void) {
  struct FlowManager ** flow_manager_ptr = &RTE_PER_LCORE(_flow_manager);
  (*flow_manager_ptr) = flow_manager_allocate(
      config.wan_device, config.expiration_time, config.max_flows);
  return (*flow_manager_ptr) != NULL;
}

int nf_process(uint16_t device, uint8_t* buffer, uint16_t buffer_length, vigor_time_t now) {
  bool* write_attempt = &RTE_PER_LCORE(write_attempt);
  bool* write_state = &RTE_PER_LCORE(write_state);

  struct FlowManager ** flow_manager_ptr = &RTE_PER_LCORE(_flow_manager);
  struct FlowManager *flow_manager = (*flow_manager_ptr);

  NF_DEBUG("It is %" PRId64, now);

  flow_manager_expire(flow_manager, now);
  NF_DEBUG("Flows have been expired");
  if (*write_attempt && !*write_state) {
    return 1;
  }

  struct ether_hdr *ether_header = nf_then_get_ether_header(buffer);
  uint8_t *ip_options;
  struct ipv4_hdr *ipv4_header =
      nf_then_get_ipv4_header(ether_header, buffer, &ip_options);
  if (ipv4_header == NULL) {
    NF_DEBUG("Not IPv4, dropping");
    return device;
  }

  struct tcpudp_hdr *tcpudp_header =
      nf_then_get_tcpudp_header(ipv4_header, buffer);
  if (tcpudp_header == NULL) {
    NF_DEBUG("Not TCP/UDP, dropping");
    return device;
  }

  NF_DEBUG("Forwarding an IPv4 packet on device %" PRIu16, device);

  uint16_t dst_device;
  if (device == config.wan_device) {
    // Inverse the src and dst for the "reply flow"
    struct FlowId id = {
      .src_port = tcpudp_header->dst_port,
      .dst_port = tcpudp_header->src_port,
      .src_ip = ipv4_header->dst_addr,
      .dst_ip = ipv4_header->src_addr,
      .protocol = ipv4_header->next_proto_id,
    };

    uint32_t dst_device_long;
    if (!flow_manager_get_refresh_flow(flow_manager, &id, now,
                                       &dst_device_long)) {
      NF_DEBUG("Unknown external flow, dropping");
      return device;
    }
    if (*write_attempt && !*write_state) {
      return 1;
    }
    dst_device = dst_device_long;
  } else {
    struct FlowId id = {
      .src_port = tcpudp_header->src_port,
      .dst_port = tcpudp_header->dst_port,
      .src_ip = ipv4_header->src_addr,
      .dst_ip = ipv4_header->dst_addr,
      .protocol = ipv4_header->next_proto_id,
    };
    if (!*write_state) {
      *write_attempt = true;
      return 1;
    }
    flow_manager_allocate_or_refresh_flow(flow_manager, &id, device, now);
    dst_device = config.wan_device;
  }

  concretize_devices(&dst_device, rte_eth_dev_count());

  ether_header->s_addr = config.device_macs[dst_device];
  ether_header->d_addr = config.endpoint_macs[dst_device];

  return dst_device;
}
