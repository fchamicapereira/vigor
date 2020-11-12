#include <stdlib.h>

#include "nf.h"
#include "flow.h.gen.h"
#include "nat_flowmanager.h"
#include "nat_config.h"
#include "nf-log.h"
#include "nf-util.h"
#include "nf-rss.h"

struct nf_config config;

uint8_t hash_key_0[RSS_HASH_KEY_LENGTH] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x2f, 0xb9, 0x81, 0x7b, 0xfc, 0xb0, 0x21, 0x8a,
  0x12, 0xb5, 0x2f, 0x75, 0x5c, 0xd3, 0xc8, 0x92,
  0xda, 0x7f, 0xbf, 0x1a, 0x63, 0x69, 0xd8, 0x8d,
  0xa2, 0x2c, 0x47, 0x57, 0x18, 0x13, 0xc6, 0x47,
  0xcd, 0x47, 0xc2, 0xc9
};

uint8_t hash_key_1[RSS_HASH_KEY_LENGTH] = {
  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
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
      config.start_port, config.external_addr, config.wan_device,
      config.expiration_time, config.max_flows);

  return (*flow_manager_ptr) != NULL;
}

int nf_process(uint16_t device, uint8_t* buffer, uint16_t buffer_length, vigor_time_t now) {
  struct FlowManager ** flow_manager_ptr = &RTE_PER_LCORE(_flow_manager);
  struct FlowManager *flow_manager = (*flow_manager_ptr);

  NF_DEBUG("It is %" PRId64, now);

  flow_manager_expire(flow_manager, now);
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
        return device;
      }
    }

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
