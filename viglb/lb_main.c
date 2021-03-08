#include <stdlib.h>

#include "lb_config.h"
#include "lb_balancer.h"
#include "nf.h"
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

struct LoadBalancer *balancer;

bool nf_init(void) {
  if (rte_get_master_lcore() != rte_lcore_id()) {
    return true;
  }

  balancer = lb_allocate_balancer(
      config.flow_capacity, config.backend_capacity, config.cht_height,
      config.backend_expiration_time, config.flow_expiration_time);
  return balancer != NULL;
}

int nf_process(uint16_t device, uint8_t* buffer, uint16_t buffer_length, vigor_time_t now) {
  bool* write_attempt = &RTE_PER_LCORE(write_attempt);
  bool* write_state = &RTE_PER_LCORE(write_state);

  lb_expire_flows(balancer, now);

  if (*write_attempt && !*write_state) {
    return 1;
  }

  lb_expire_backends(balancer, now);
  CHECK_WRITE_ATTEMPT(write_attempt, write_state);

  struct ether_hdr *ether_header = nf_then_get_ether_header(buffer);
  uint8_t *ip_options;
  struct ipv4_hdr *ipv4_header =
      nf_then_get_ipv4_header(ether_header, buffer, &ip_options);
  if (ipv4_header == NULL) {
    NF_DEBUG("Malformed IPv4, dropping");
    return device;
  }

  struct tcpudp_hdr *tcpudp_header =
      nf_then_get_tcpudp_header(ipv4_header, buffer);
  if (tcpudp_header == NULL) {
    NF_DEBUG("Not TCP/UDP, dropping");
    return device;
  }

  struct LoadBalancedFlow flow = { .src_ip = ipv4_header->src_addr,
                                   .dst_ip = ipv4_header->dst_addr,
                                   .src_port = tcpudp_header->src_port,
                                   .dst_port = tcpudp_header->dst_port,
                                   .protocol = ipv4_header->next_proto_id };

  if (device != config.wan_device) {
    lb_process_heartbit(balancer, &flow, ether_header->s_addr, device, now);
    CHECK_WRITE_ATTEMPT(write_attempt, write_state);
    return device;
  }

  struct LoadBalancedBackend backend = lb_get_backend(balancer, &flow, now,
                                                      config.wan_device);
  CHECK_WRITE_ATTEMPT(write_attempt, write_state);

  concretize_devices(&backend.nic, rte_eth_dev_count());

  if (backend.nic != config.wan_device) {
    ipv4_header->dst_addr = backend.ip;
    ether_header->s_addr = config.device_macs[backend.nic];
    ether_header->d_addr = backend.mac;

    // Checksum
    nf_set_ipv4_udptcp_checksum(ipv4_header, tcpudp_header, buffer);
  }

  return backend.nic;
}
