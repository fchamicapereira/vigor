#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <rte_common.h>
#include <rte_atomic.h>
#include <rte_pause.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

typedef struct {

  // rte_atomic32_t active; // DEBUG
	
  rte_atomic32_t* tokens;
  rte_atomic32_t write_token;

} nf_lock_t;

static inline void
nf_lock_init(nf_lock_t *nfl)
{
  nfl->tokens = (rte_atomic32_t*) rte_malloc(NULL, sizeof(rte_atomic32_t) * RTE_MAX_LCORE, 64);

	unsigned lcore_id;
	RTE_LCORE_FOREACH(lcore_id) {
    rte_atomic32_init(&nfl->tokens[lcore_id]);
	}

  // rte_atomic32_init(&nfl->active); // DEBUG
	rte_atomic32_init(&nfl->write_token);
}

static inline void
nf_lock_allow_writes(nf_lock_t *nfl) {
  // rte_atomic32_dec(&nfl->active); // DEBUG
	unsigned lcore_id = rte_lcore_id();
  rte_atomic32_clear(&nfl->tokens[lcore_id]);
}

static inline void
nf_lock_block_writes(nf_lock_t *nfl) {
	unsigned lcore_id = rte_lcore_id();
  while (!rte_atomic32_test_and_set(&nfl->tokens[lcore_id])) {
    // prevent the compiler from removing this loop
		__asm__ __volatile__("");
  }

  // rte_atomic32_inc(&nfl->active); // DEBUG
}

static inline void
nf_lock_write_lock(nf_lock_t *nfl) {
  // rte_atomic32_dec(&nfl->active); // DEBUG
	
  unsigned lcore_id = rte_lcore_id();
  rte_atomic32_clear(&nfl->tokens[lcore_id]);

  while (!rte_atomic32_test_and_set(&nfl->write_token)) {
    // prevent the compiler from removing this loop
    __asm__ __volatile__("");
  }

	RTE_LCORE_FOREACH(lcore_id) {
	  while (!rte_atomic32_test_and_set(&nfl->tokens[lcore_id])) {
      // prevent the compiler from removing this loop
      __asm__ __volatile__("");
    }
	}

  // rte_atomic32_inc(&nfl->active); // DEBUG
  // assert(rte_atomic32_read(&nfl->active) == 1); // DEBUG
}

static inline void
nf_lock_write_unlock(nf_lock_t *nfl) {
  // assert(rte_atomic32_read(&nfl->active) == 1); // DEBUG

  unsigned lcore_id;
  RTE_LCORE_FOREACH(lcore_id) {
	  rte_atomic32_clear(&nfl->tokens[lcore_id]);
	}

  // rte_atomic32_dec(&nfl->active); // DEBUG
  rte_atomic32_clear(&nfl->write_token);
}

#ifdef __cplusplus
}
#endif
