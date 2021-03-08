#include <stdlib.h>

#include "nf.h"
#include "flow.h.gen.h"
#include "nat_flowmanager.h"
#include "nat_config.h"
#include "nf-log.h"
#include "nf-util.h"
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

struct FlowManager *flow_manager;

bool nf_init(void) {
  if (rte_get_master_lcore() != rte_lcore_id()) {
    return true;
  }

  flow_manager = flow_manager_allocate(
      config.start_port, config.external_addr, config.wan_device,
      config.expiration_time, config.max_flows);

  return flow_manager != NULL;
}

int nf_process(uint16_t device, uint8_t* buffer, uint16_t buffer_length, vigor_time_t now) {
  bool* write_attempt = &RTE_PER_LCORE(write_attempt);
  bool* write_state = &RTE_PER_LCORE(write_state);

  NF_DEBUG("It is %" PRId64, now);

  flow_manager_expire(flow_manager, now);
  CHECK_WRITE_ATTEMPT(write_attempt, write_state);
  NF_DEBUG("Flows have been expired");

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
    NF_DEBUG("Device %" PRIu16 " is external", device);

    struct FlowId internal_flow;
    if (flow_manager_get_external(flow_manager, tcpudp_header->dst_port, now,
                                  &internal_flow)) {
      NF_DEBUG("Found internal flow.");
      LOG_FLOWID(&internal_flow, NF_DEBUG);

      if (internal_flow.dst_ip != ipv4_header->src_addr |
          internal_flow.dst_port != tcpudp_header->src_port |
          internal_flow.protocol != ipv4_header->next_proto_id) {
        NF_DEBUG("Spoofing attempt, dropping.");
        return device;
      }

      ipv4_header->dst_addr = internal_flow.src_ip;
      tcpudp_header->dst_port = internal_flow.src_port;
      dst_device = internal_flow.internal_device;
    } else {
      NF_DEBUG("Unknown flow, dropping");
      return device;
    }
  } else {
    struct FlowId id = { .src_port = tcpudp_header->src_port,
                         .dst_port = tcpudp_header->dst_port,
                         .src_ip = ipv4_header->src_addr,
                         .dst_ip = ipv4_header->dst_addr,
                         .protocol = ipv4_header->next_proto_id,
                         .internal_device = device };

    NF_DEBUG("For id:");
    LOG_FLOWID(&id, NF_DEBUG);

    NF_DEBUG("Device %" PRIu16 " is internal (not %" PRIu16 ")", device,
             config.wan_device);

    uint16_t external_port;
    if (!flow_manager_get_internal(flow_manager, &id, now, &external_port)) {
      NF_DEBUG("New flow");
      if (!flow_manager_allocate_flow(flow_manager, &id, device, now,
                                      &external_port)) {
        NF_DEBUG("No space for the flow, dropping");
        CHECK_WRITE_ATTEMPT(write_attempt, write_state);
        return device;
      }
    }
    CHECK_WRITE_ATTEMPT(write_attempt, write_state);
    NF_DEBUG("Forwarding from ext port:%d", external_port);

    ipv4_header->src_addr = config.external_addr;
    tcpudp_header->src_port = external_port;
    dst_device = config.wan_device;
  }

  nf_set_ipv4_udptcp_checksum(ipv4_header, tcpudp_header, buffer);

  concretize_devices(&dst_device, rte_eth_dev_count());

  ether_header->s_addr = config.device_macs[dst_device];
  ether_header->d_addr = config.endpoint_macs[dst_device];

  return dst_device;
}
