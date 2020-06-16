#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <r3s.h>
#include <z3.h>

#include "./libvig_access.h"
#include "./constraint.h"
#include "./parser.h"

Z3_ast ast_replace(Z3_context ctx, Z3_ast root, Z3_ast target, Z3_ast dst) {
  if (Z3_get_ast_kind(ctx, root) != Z3_APP_AST)
    return root;

  Z3_app app = Z3_to_app(ctx, root);
  unsigned num_fields = Z3_get_app_num_args(ctx, app);
  Z3_ast *updated_args = (Z3_ast *)malloc(sizeof(Z3_ast) * num_fields);

  for (unsigned i = 0; i < num_fields; i++) {
    updated_args[i] =
        Z3_is_eq_ast(ctx, Z3_get_app_arg(ctx, app, i), target)
            ? dst
            : ast_replace(ctx, Z3_get_app_arg(ctx, app, i), target, dst);
  }

  root = Z3_update_term(ctx, root, num_fields, updated_args);
  free(updated_args);
  return root;
}

/*
Z3_ast mk_cnstrs(R3S_cfg_t cfg, R3S_packet_ast_t p1, R3S_packet_ast_t p2) {
  R3S_status_t status;
  constraints_t *cnstrs;
  Z3_ast *and_args;
  unsigned and_i;
  Z3_ast cnstr;

  cnstrs = (constraints_t *)R3S_get_user_data(cfg);
  and_args =
      (Z3_ast *)malloc(sizeof(Z3_ast) * (cnstrs->cnstrs[0].pfs.sz * 2 + 1));

  cnstr = cnstrs->cnstrs[0].cnstr;
  and_i = 0;

  printf("constraint before:\n%s\n", Z3_ast_to_string(cfg.ctx, cnstr));

  for (unsigned c = 0; c < cnstrs->cnstrs[0].pfs.sz; c++) {
    Z3_ast pf1_ast, pf2_ast;
    unsigned pf1_sz, pf2_sz;
    unsigned high, low;

    R3S_packet_extract_pf(cfg, p1, cnstrs->cnstrs[0].pfs.pfs[c].pf.pf,
                          &pf1_ast);
    R3S_packet_extract_pf(cfg, p2, cnstrs->cnstrs[0].pfs.pfs[c].pf.pf,
                          &pf2_ast);

    pf1_sz = Z3_get_bv_sort_size(cfg.ctx, Z3_get_sort(cfg.ctx, pf1_ast));
    pf2_sz = Z3_get_bv_sort_size(cfg.ctx, Z3_get_sort(cfg.ctx, pf2_ast));

    high = pf1_sz - cnstrs->cnstrs[0].pfs.pfs[c].pf.bytes * 8 - 1;
    low = high - 7;

    //low = cnstrs->cnstrs[0].pfs.pfs[c].pf.bytes * 8;
    //high = low + 7;

    if (cnstrs->cnstrs[0].pfs.pfs[c].p_count == 0) {
      Z3_ast pf1_ext = Z3_mk_extract(cfg.ctx, high, low, pf1_ast);

      cnstr = ast_replace(cfg.ctx, cnstr, cnstrs->cnstrs[0].pfs.pfs[c].select,
                          pf1_ext);
    } else if (cnstrs->cnstrs[0].pfs.pfs[c].p_count == 1) {
      Z3_ast pf2_ext = Z3_mk_extract(cfg.ctx, high, low, pf2_ast);

      cnstr = ast_replace(cfg.ctx, cnstr, cnstrs->cnstrs[0].pfs.pfs[c].select,
                          pf2_ext);
    } else {
      assert(false && "Packet counter with invalid value");
    }

    assert(cnstr != NULL);
  }

  printf("p1 option %s\n", R3S_opt_to_string(p1.loaded_opt.opt));
  printf("p2 option %s\n", R3S_opt_to_string(p2.loaded_opt.opt));
  printf("constraints after:\n%s\n", Z3_ast_to_string(cfg.ctx, cnstr));

  cnstr = Z3_simplify(cfg.ctx, cnstr);

  printf("simplified:\n%s\n", Z3_ast_to_string(cfg.ctx, cnstr));

  return cnstr;
}

void validate(R3S_cfg_t cfg) {
  R3S_packet_t p1, p2;
  R3S_status_t status;

  for (int i = 0; i < 25; i++) {
    R3S_packet_rand(cfg, &p1);

    if ((status = R3S_packet_from_cnstrs(cfg, p1, &mk_cnstrs, &p2)) !=
        R3S_STATUS_SUCCESS) {
      printf("ERROR: %s\n", R3S_status_to_string(status));
      assert(false);
    }

    printf("\n===== iteration %d =====\n", i);
    printf("Packet 1:\n%s\n", R3S_packet_to_string(p1));
    printf("Packet 2:\n%s\n", R3S_packet_to_string(p2));
  }
}
*/

int main(int argc, char *argv[]) {

  if (argc < 2) {
    printf("[ERROR] Missing arguments.");
    printf("Please provide a libvig-access-out.txt file location\n");
    return 1;
  }

  char *libvig_access_out = argv[1];

  /*
  parsed_data_t data;
  parsed_data_init(&data);
  */

  R3S_cfg_t cfg;
  R3S_cnstrs_func cnstrs[1];
  R3S_status_t status;

  R3S_cfg_init(&cfg);
  Parser parser(cfg.ctx);

  /*
  parse_libvig_access_file(libvig_access_out, &data, cfg.ctx);

  unsigned curr_device;
  bool curr_device_set = false;

  for (unsigned i = 0; i < data.accesses.sz; i++) {
    printf("Device %u\n", data.accesses.accesses[i].device);
    printf("Object %u\n", data.accesses.accesses[i].obj);
    printf("ID     %u\n", data.accesses.accesses[i].id);

    for (unsigned idep = 0; idep < data.accesses.accesses[i].deps.sz; idep++) {
      if (data.accesses.accesses[i].deps.deps[idep].pf_is_set)
        printf("    %s (byte %u)\n",
               R3S_pf_to_string(data.accesses.accesses[i].deps.deps[idep].pf),
               data.accesses.accesses[i].deps.deps[idep].bytes);
      else
        printf("  * %s\n",
               data.accesses.accesses[i].deps.deps[idep].error_descr);
    }
  }

  constraints_process_pfs(&data.constraints, data.accesses);

  R3S_pf_t *pfs =
      (R3S_pf_t *)malloc(sizeof(R3S_pf_t) * data.constraints.cnstrs[0].pfs.sz);

  for (unsigned i = 0; i < data.constraints.sz; i++) {
    printf("\n===========================\n");
    printf("Constraint %u\n", i);
    printf("first access id: %u\n", data.constraints.cnstrs[i].first->id);
    printf("second access id: %u\n", data.constraints.cnstrs[i].second->id);

    printf("ast:\n%s\n",
           Z3_ast_to_string(cfg.ctx, data.constraints.cnstrs[i].cnstr));

    for (unsigned j = 0; j < data.constraints.cnstrs[i].pfs.sz; j++) {
      pfs[j] = data.constraints.cnstrs[i].pfs.pfs[j].pf.pf;

      if (data.constraints.cnstrs[i].pfs.pfs[j].processed) {
        printf("\nselect: %s\n",
               Z3_ast_to_string(cfg.ctx,
                                data.constraints.cnstrs[i].pfs.pfs[j].select));
        printf("pf %s byte %u\n",
               R3S_pf_to_string(data.constraints.cnstrs[i].pfs.pfs[j].pf.pf),
               data.constraints.cnstrs[i].pfs.pfs[j].pf.bytes);
      }
    }
  }

  R3S_opt_t *opts;
  size_t opts_sz;

  assert(data.constraints.cnstrs[0].pfs.sz);

  R3S_opts_from_pfs(pfs, data.constraints.cnstrs[0].pfs.sz, &opts, &opts_sz);

  for (unsigned iopt = 0; iopt < opts_sz; iopt++)
    R3S_cfg_load_opt(&cfg, opts[iopt]);
  
  printf("%s\n", R3S_cfg_to_string(cfg));

  R3S_set_user_data(&cfg, (void *)&data.constraints);
  cnstrs[0] = &mk_cnstrs;

  validate(cfg);

  constraints_destroy(&(data.constraints));
  libvig_accesses_destroy(&(data.accesses));
  */
}