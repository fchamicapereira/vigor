#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <netinet/in.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "nf-util.h"

#ifdef KLEE_VERIFICATION
#  include <klee/klee.h>
#endif

RTE_DEFINE_PER_LCORE(void **, chunks_borrowed);
RTE_DEFINE_PER_LCORE(size_t, chunks_borrowed_num);

void nf_util_init() {
  size_t *chunks_borrowed_num_ptr = &RTE_PER_LCORE(chunks_borrowed_num);
  void** *chunks_borrowed_ptr = &RTE_PER_LCORE(chunks_borrowed);

  (*chunks_borrowed_num_ptr) = 0;
  (*chunks_borrowed_ptr) = (void**) malloc(sizeof(void*) * MAX_N_CHUNKS);
}

bool nf_has_ipv4_header(struct ether_hdr *header) {
  return header->ether_type == rte_be_to_cpu_16(ETHER_TYPE_IPv4);
}

bool nf_has_tcpudp_header(struct ipv4_hdr *header) {
  // NOTE: Use non-short-circuiting version of OR, so that symbex doesn't fork
  //       since here we only care of it's UDP or TCP, not if it's a specific
  //       one
  return header->next_proto_id == IPPROTO_TCP |
         header->next_proto_id == IPPROTO_UDP;
}

#ifdef KLEE_VERIFICATION
void nf_set_ipv4_udptcp_checksum(struct ipv4_hdr *ip_header,
                                 struct tcpudp_hdr *l4_header, void *packet) {
  klee_trace_ret();
  klee_trace_param_u64((uint64_t)ip_header, "ip_header");
  klee_trace_param_u64((uint64_t)l4_header, "l4_header");
  klee_trace_param_u64((uint64_t)packet, "packet");
  // Make sure the packet pointer points to the TCPUDP continuation
  assert(packet_is_last_borrowed_chunk(packet, l4_header));
  ip_header->hdr_checksum = klee_int("checksum");
}
#else  // KLEE_VERIFICATION
void nf_set_ipv4_udptcp_checksum(struct ipv4_hdr *ip_header,
                                 struct tcpudp_hdr *l4_header, void *packet) {
  // Make sure the packet pointer points to the TCPUDP continuation
  // This check is exercised during verification, no need to repeat it.
  // void* payload = nf_borrow_next_chunk(packet,
  // rte_be_to_cpu_16(ip_header->total_length) - sizeof(struct tcpudp_hdr));
  // assert((char*)payload == ((char*)l4_header + sizeof(struct tcpudp_hdr)));

  ip_header->hdr_checksum = 0; // Assumed by cksum calculation
  if (ip_header->next_proto_id == IPPROTO_TCP) {
    struct tcp_hdr *tcp_header = (struct tcp_hdr *)l4_header;
    tcp_header->cksum = 0; // Assumed by cksum calculation
    tcp_header->cksum = rte_ipv4_udptcp_cksum(ip_header, tcp_header);
  } else if (ip_header->next_proto_id == IPPROTO_UDP) {
    struct udp_hdr *udp_header = (struct udp_hdr *)l4_header;
    udp_header->dgram_cksum = 0; // Assumed by cksum calculation
    udp_header->dgram_cksum = rte_ipv4_udptcp_cksum(ip_header, udp_header);
  }
  ip_header->hdr_checksum = rte_ipv4_cksum(ip_header);
}
#endif // KLEE_VERIFICATION

uintmax_t nf_util_parse_int(const char *str, const char *name, int base,
                            char next) {
  char *temp;
  intmax_t result = strtoimax(str, &temp, base);

  // There's also a weird failure case with overflows, but let's not care
  if (temp == str || *temp != next) {
    rte_exit(EXIT_FAILURE, "Error while parsing '%s': %s\n", name, str);
  }

  return result;
}

char *nf_mac_to_str(struct ether_addr *addr) {
  // format is xx:xx:xx:xx:xx:xx\0
  uint16_t buffer_size = 6 * 2 + 5 + 1; // FIXME: why dynamic alloc here?
  char *buffer = (char *)calloc(buffer_size, sizeof(char));
  if (buffer == NULL) {
    rte_exit(EXIT_FAILURE, "Out of memory in nf_mac_to_str!");
  }

  snprintf(buffer, buffer_size, "%02X:%02X:%02X:%02X:%02X:%02X", addr->addr_bytes[0],
           addr->addr_bytes[1], addr->addr_bytes[2],
           addr->addr_bytes[3], addr->addr_bytes[4],
           addr->addr_bytes[5]);

  return buffer;
}

char *nf_ipv4_to_str(uint32_t addr) {
  // format is xxx.xxx.xxx.xxx\0
  uint16_t buffer_size = 4 * 3 + 3 + 1;
  char *buffer = (char *)calloc(buffer_size,
                                sizeof(char)); // FIXME: why dynamic alloc here?
  if (buffer == NULL) {
    rte_exit(EXIT_FAILURE, "Out of memory in nf_ipv4_to_str!");
  }

  snprintf(buffer, buffer_size, "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8,
           addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF,
           (addr >> 24) & 0xFF);
  return buffer;
}

void reta_from_file(uint16_t reta[512]) {
  int lcores = rte_lcore_count();

  FILE* fp;
  char* line = NULL;
  char* delim;
  size_t num_len;
  char* number;

  size_t len = 0;
  ssize_t read;

  fp = fopen("./lut.txt", "r");
  if (fp == NULL) {
    rte_exit(EXIT_FAILURE, "lut.txt not found");
  }

  int reta_lcores = 2;
  while ((read = getline(&line, &len, fp)) != -1) {
    if (reta_lcores == lcores) {
      break;
    }
    reta_lcores++;
  }
  fclose(fp);

  delim = line;
  number = (char*) malloc(sizeof(char) * read);
  for (uint16_t bucket = 0; bucket < 512; bucket++) {
    num_len = 1;
    while (*delim != ' ' && *delim != '\n') { delim++; number[num_len - 1] = *delim; num_len++; }
    delim++;
    number[num_len] = '\0';

    reta[bucket] = atoi(number);
    printf("bucket %" PRIu16 " value %" PRIu16 "\n", bucket, reta[bucket]);
  }

  free(number);
  free(line);
  rte_exit(EXIT_FAILURE, "done :)");
}

void set_reta(uint16_t device, uint16_t reta[512]) {

}
