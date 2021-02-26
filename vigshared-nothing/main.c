#include "nf.h"
#include "config.h"

#include "nf-log.h"
#include "nf-util.h"

RTE_DEFINE_PER_LCORE(uint64_t, counter);

bool nf_init(void) {
  return true;
}

int nf_process(uint16_t device, uint8_t* buffer, uint16_t buffer_length, vigor_time_t now) {
  struct ether_hdr *ether_header = nf_then_get_ether_header(buffer);

  uint64_t *counter_ptr = &RTE_PER_LCORE(counter);
  (*counter_ptr)++;

  uint16_t dst_device = 1 - device;

  // Special method required during symbolic execution to avoid path explosion
  concretize_devices(&dst_device, rte_eth_dev_count());

  ether_header->s_addr = config.device_macs[dst_device];
  ether_header->d_addr = config.endpoint_macs[dst_device];

  return dst_device;
}
