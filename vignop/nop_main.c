#include "nat_config.h"
#include "nf.h"
#include "nf-util.h"
#include "nf-rss.h"

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

bool nf_init(void) {
  return true;
}

int nf_process(uint16_t device, uint8_t* buffer, uint16_t buffer_length, time_t now) {
  // Mark now as unused, we don't care about time
  (void)now;

  // This is a bit of a hack; the benchmarks are designed for a NAT, which knows
  // where to forward packets, but for a plain forwarding app without any logic,
  // we just send all packets from LAN to the WAN port, and all packets from WAN
  // to the main LAN port, and let the recipient ignore the useless ones.

  uint16_t dst_device;
  if (device == config.wan_device) {
    dst_device = config.lan_main_device;
  } else {
    dst_device = config.wan_device;
  }

  // L2 forwarding
  struct ether_hdr *ether_header = nf_then_get_ether_header(buffer);
  ether_header->s_addr = config.device_macs[dst_device];
  ether_header->d_addr = config.endpoint_macs[dst_device];

  return dst_device;
}
