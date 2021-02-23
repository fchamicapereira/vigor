#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <rte_common.h>
#include <rte_atomic.h>
#include <rte_pause.h>
#include <rte_lcore.h>

typedef struct {

  // rte_atomic32_t active;
	
  rte_spinlock_t activity_locks[RTE_MAX_LCORE];
	rte_spinlock_t write_lock;

} nf_lock_t;

static inline void
nf_lock_init(nf_lock_t *nfl)
{
	unsigned lcore_id;
	RTE_LCORE_FOREACH(lcore_id) {
    rte_spinlock_init(&nfl->activity_locks[lcore_id]);
	}
  // rte_atomic32_init(&nfl->active);
	rte_spinlock_init(&nfl->write_lock);
}

static inline void
nf_lock_allow_writes(nf_lock_t *nfl) {
	unsigned lcore_id = rte_lcore_id();
  // rte_atomic32_dec(&nfl->active);
  rte_spinlock_unlock(&nfl->activity_locks[lcore_id]);
}

static inline void
nf_lock_block_writes(nf_lock_t *nfl) {
	unsigned lcore_id = rte_lcore_id();
  rte_spinlock_lock(&nfl->activity_locks[lcore_id]);
  // rte_atomic32_inc(&nfl->active);
}

static inline void
nf_lock_write_lock(nf_lock_t *nfl) {
  unsigned this_lcore_id = rte_lcore_id();

  // rte_atomic32_dec(&nfl->active);
  rte_spinlock_unlock(&nfl->activity_locks[this_lcore_id]);

  rte_spinlock_lock(&nfl->write_lock);

  unsigned lcore_id;
  RTE_LCORE_FOREACH(lcore_id) {
    rte_spinlock_lock(&nfl->activity_locks[lcore_id]);
  }

  // rte_atomic32_inc(&nfl->active);
  // assert(rte_atomic32_read(&nfl->active) == 1);
}

static inline void
nf_lock_write_unlock(nf_lock_t *nfl) {
  // assert(rte_atomic32_read(&nfl->active) == 1);

  unsigned lcore_id;
  RTE_LCORE_FOREACH(lcore_id) {
    rte_spinlock_unlock(&nfl->activity_locks[lcore_id]);
  }

  // rte_atomic32_dec(&nfl->active);
	rte_spinlock_unlock(&nfl->write_lock);
}

#ifdef __cplusplus
}
#endif
