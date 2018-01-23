#ifndef _BRIDGE_LOOP_H_INCLUDED_
#define _BRIDGE_LOOP_H_INCLUDED_
#include "lib/containers/double-chain.h"
#include "lib/containers/map.h"
#include "lib/containers/vector.h"
#include "bridge_data.h"
#include "lib/coherence.h"
#include "lib/nf_time.h"

/*@
  fixpoint bool st_entry_bound<t>(int bound, pair<t,int> p) {
    return 0 <= snd(p) && snd(p) < bound;
  }

  predicate bridge_loop_invariant(struct DoubleChain* dyn_heap,
                                  struct Map* dyn_map,
                                  struct Vector* dyn_vec,
                                  struct Map* st_map,
                                  struct Vector* st_vec,
                                  uint32_t capacity,
                                  uint32_t time,
                                  uint32_t dev_count) =
    double_chainp(?dh, dyn_heap) &*&
    mapp<ether_addri>(dyn_map, ether_addrp, eth_addr_hash,
                      ?earecp,
                      mapc(capacity, ?dm, ?daddrs)) &*&
    vectorp<dynenti>(dyn_vec, dynamic_entryp, ?dv) &*&
    mapp<stat_keyi>(st_map, static_keyp,
                    st_key_hash,
                    ?strecp,
                    mapc(?stcap, ?sm, ?saddrs)) &*&
    vectorp<stat_keyi>(st_vec, static_keyp, ?sv) &*&
    0 < capacity &*&
    length(dv) == capacity &*&
    map_vec_chain_coherent<ether_addri, dynenti>(dm, dv, dh) &*&
    dchain_high_fp(dh) <= time &*&
    last_time(time) &*&
    true == forall(sm, (st_entry_bound)(dev_count));
  @*/

void bridge_loop_invariant_consume(struct DoubleChain** dyn_heap,
                                   struct Map** dyn_map,
                                   struct Vector** dyn_vec,
                                   struct Map** st_map,
                                   struct Vector** st_vec,
                                   uint32_t capacity,
                                   uint32_t time,
                                   uint32_t dev_count);
/*@ requires *dyn_heap |-> ?dh &*&
             *dyn_map |-> ?dm &*&
             *dyn_vec |-> ?dv &*&
             *st_map |-> ?sm &*&
             *st_vec |-> ?sv &*&
             bridge_loop_invariant(dh, dm, dv, sm, sv,
                                   capacity, time,
                                   dev_count); @*/
/*@ ensures *dyn_heap |-> dh &*&
            *dyn_map |-> dm &*&
            *dyn_vec |-> dv &*&
            *st_map |-> sm &*&
            *st_vec |-> sv; @*/


void bridge_loop_invariant_produce(struct DoubleChain** dyn_heap,
                                   struct Map** dyn_map,
                                   struct Vector** dyn_vec,
                                   struct Map** st_map,
                                   struct Vector** st_vec,
                                   uint32_t capacity,
                                   uint32_t* time,
                                   uint32_t dev_count);
/*@ requires *dyn_heap |-> ?dh &*&
             *dyn_map |-> ?dm &*&
             *dyn_vec |-> ?dv &*&
             *st_map |-> ?sm &*&
             *st_vec |-> ?sv &*&
             *time |-> _; @*/
/*@ ensures *dyn_heap |-> dh &*&
            *dyn_map |-> dm &*&
            *dyn_vec |-> dv &*&
            *st_map |-> sm &*&
            *st_vec |-> sv &*&
            *time |-> ?t &*&
            bridge_loop_invariant(dh, dm, dv, sm, sv,
                                  capacity, t,
                                  dev_count); @*/

void bridge_loop_iteration_begin(struct DoubleChain** dyn_heap,
                                 struct Map** dyn_map,
                                 struct Vector** dyn_vec,
                                 struct Map** st_map,
                                 struct Vector** st_vec,
                                 uint32_t capacity,
                                 uint32_t time,
                                 uint8_t dev_count);
/*@ requires true; @*/
/*@ ensures true; @*/

void bridge_loop_iteration_end(struct DoubleChain** dyn_heap,
                               struct Map** dyn_map,
                               struct Vector** dyn_vec,
                               struct Map** st_map,
                               struct Vector** st_vec,
                               uint32_t capacity,
                               uint32_t time,
                               uint8_t dev_count);
/*@ requires true; @*/
/*@ ensures true; @*/

void bridge_loop_iteration_assumptions(struct DoubleChain** dyn_heap,
                                       struct Map** dyn_map,
                                       struct Vector** dyn_vec,
                                       struct Map** st_map,
                                       struct Vector** st_vec,
                                       uint32_t capacity,
                                       uint32_t time);
/*@ requires true; @*/
/*@ ensures true; @*/

#endif//_BRIDGE_LOOP_H_INCLUDED_
