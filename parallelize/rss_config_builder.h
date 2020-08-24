#pragma once

#include "constraint.h"
#include "rss_config.h"
#include "libvig_access.h"

#include <vector>
#include <map>

namespace R3S {
#include <r3s.h>
}

namespace ParallelSynthesizer {

class RSSConfigBuilder {

private:
  R3S::R3S_cfg_t cfg;

  std::vector<Constraint> constraints;
  std::vector<CallPathsConstraint> call_paths_constraints;

  std::vector<unsigned int> unique_devices;
  std::vector<std::pair<LibvigAccess, LibvigAccess> > unique_access_pairs;
  std::vector<R3S::R3S_pf_t> unique_packet_fields_dependencies;
  std::vector<R3S::R3S_cnstrs_func> solver_constraints_generators;

  RSSConfig rss_config;

private:
  void load_rss_config_options();
  void load_solver_constraints_generators();
  int get_device_index(unsigned int device) const;

  void merge_unique_packet_field_dependencies(
      const std::vector<R3S::R3S_pf_t> &packet_fields);
  bool is_access_pair_already_stored(
      const std::pair<LibvigAccess, LibvigAccess> &pair);

  void fill_unique_devices(const std::vector<LibvigAccess> &accesses);
  std::vector<LibvigAccess> filter_reads_without_writes_on_objects(const std::vector<LibvigAccess> &accesses);

  void poison_packet_fields(std::map< unsigned int, std::vector<R3S::R3S_pf_t> >& poisoned_packet_fields);
  void remove_constraints_with_prohibited_packet_fields(unsigned int device, std::vector<R3S::R3S_pf_t> prohibited_packet_fields);
  void analyse_dchain_interpretations(const std::vector<LibvigAccess>& accesses);
  bool is_write_modifying(const std::vector<LibvigAccess>&cp, LibvigAccess write);
  bool are_call_paths_equivalent(const std::vector<LibvigAccess>& cp1, const std::vector<LibvigAccess>& cp2);
  void verify_dchain_correctness(const std::vector<LibvigAccess>& accesses, const LibvigAccess& dchain_verify);

  void fill_constraints(const std::vector<LibvigAccess> &accesses);
  void analyse_constraints();

  static std::vector<Constraint> get_constraints_between_devices(std::vector<Constraint> constraints,
                                                                 unsigned int p1_device, unsigned int p2_device);
  static R3S::Z3_ast constraint_to_solver_input(R3S::R3S_cfg_t cfg, R3S::R3S_packet_ast_t p1,
                                                R3S::R3S_packet_ast_t p2, const Constraint& constraint);
  static R3S::Z3_ast make_solver_constraints(R3S::R3S_cfg_t cfg,
                                             R3S::R3S_packet_ast_t p1,
                                             R3S::R3S_packet_ast_t p2);

public:
  RSSConfigBuilder(const std::vector<LibvigAccess> &accesses, const std::vector<CallPathsConstraint>& _call_paths_constraints)
   : call_paths_constraints(_call_paths_constraints) {

    R3S::R3S_cfg_init(&cfg);
    R3S::R3S_cfg_set_skew_analysis(cfg, false);

    fill_unique_devices(accesses);

    auto trimmed_accesses = filter_reads_without_writes_on_objects(accesses);

    fill_constraints(trimmed_accesses);
    analyse_dchain_interpretations(trimmed_accesses);
    analyse_constraints();

    Logger::log() << "\n";
    Logger::log() << "Packet field dependencies:";
    Logger::log() << "\n";
    for (auto &pf : unique_packet_fields_dependencies) {
      Logger::log() << "  " << R3S::R3S_pf_to_string(pf);
      Logger::log() << "\n";
    }

    Logger::log() << "\n";
    Logger::log() << "Devices:";
    Logger::log() << "\n";
    for (const auto &device : unique_devices) {
      Logger::log() << "  " << device;
      Logger::log() << "\n";
    }

    R3S::R3S_cfg_set_number_of_keys(cfg, unique_devices.size());
    load_rss_config_options();

    R3S::R3S_cfg_set_user_data(cfg, (void *)&constraints);

    Logger::log() << "\nR3S configuration:\n" << R3S::R3S_cfg_to_string(cfg)
                  << "\n";
  }

  const R3S::R3S_cfg_t &get_cfg() const { return cfg; }
  const std::vector<Constraint> &get_constraints() const { return constraints; }
  const RSSConfig &get_generated_rss_cfg() const { return rss_config; }

  static R3S::Z3_ast ast_replace(R3S::Z3_context ctx, R3S::Z3_ast root,
                                 R3S::Z3_ast target, R3S::Z3_ast dst);

  static R3S::Z3_ast ast_equal_association(R3S::Z3_context ctx, R3S::Z3_ast root,
                                                             R3S::Z3_ast target);

  void build_rss_config();

  std::pair<R3S::R3S_packet_t, R3S::R3S_packet_t>
  generate_packets(unsigned device1, unsigned device2);

  ~RSSConfigBuilder() { R3S::R3S_cfg_delete(cfg); }
};
}
