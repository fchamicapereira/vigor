#include "nat_config.h"
#include "nf.h"
#include "nf-util.h"
#include "nf-rss.h"

struct nf_config config;

uint8_t hash_key[RSS_HASH_KEY_LENGTH] = {
  0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
  0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
  0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
  0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
  0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
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
