#include "./constraint.h"
#include <stdlib.h>
#include "string.h"
#include <assert.h>

bool pfast_eq(pfast_t pfast1, pfast_t pfast2) {
  assert(pfast1.processed == pfast2.processed);

  if (pfast1.processed) {
    return pfast1.pf == pfast2.pf;
  } else {
    return pfast1.index == pfast2.index;
  }
}

void pfasts_init(pfasts_t *pfasts) {
  pfasts->pfs = NULL;
  pfasts->sz = 0;
}

void pfasts_destroy(pfasts_t *pfasts) {
  if (pfasts->sz)
    free(pfasts->pfs);
}

void pfasts_append_unique(pfasts_t *pfasts, pfast_t pfast) {
  for (unsigned i = 0; i < pfasts->sz; i++)
    if (pfast_eq(pfasts->pfs[i], pfast)) return;

  pfasts->sz++;
  pfasts->pfs = (pfast_t *)realloc(pfasts->pfs, sizeof(pfast_t) * pfasts->sz);
  pfasts->pfs[pfasts->sz - 1] = pfast;
}

void parse_symbol(Z3_context ctx, Z3_symbol symbol) {
  switch (Z3_get_symbol_kind(ctx, symbol)) {
  case Z3_INT_SYMBOL:
    printf("INT #%d", Z3_get_symbol_int(ctx, symbol));
    break;
  case Z3_STRING_SYMBOL:
    printf("STRING %s", Z3_get_symbol_string(ctx, symbol));
    break;
  default:
    printf("error\n");
    exit(1);
  }
}

bool is_select_from_chunk(Z3_context ctx, Z3_app app) {
  Z3_func_decl decl = Z3_get_app_decl(ctx, app);
  Z3_symbol name = Z3_get_decl_name(ctx, decl);

  if (strcmp(Z3_get_symbol_string(ctx, name), "select") != 0)
    return false;

  Z3_ast array_ast = Z3_get_app_arg(ctx, app, 0);

  assert(Z3_get_ast_kind(ctx, array_ast) == Z3_APP_AST);

  Z3_app array_app = Z3_to_app(ctx, array_ast);
  Z3_func_decl array_decl = Z3_get_app_decl(ctx, array_app);
  Z3_symbol array_name = Z3_get_decl_name(ctx, array_decl);

  if (strcmp(Z3_get_symbol_string(ctx, array_name), "packet_chunks") != 0)
    return false;

  return true;
}

void traverse_ast_and_retrieve_selects(Z3_context ctx, Z3_ast ast,
                                       pfasts_t *selects) {
  if (Z3_get_ast_kind(ctx, ast) != Z3_APP_AST)
    return;

  printf("ast: %s\n", Z3_ast_to_string(ctx, ast));

  Z3_app app = Z3_to_app(ctx, ast);
  Z3_func_decl decl = Z3_get_app_decl(ctx, app);

  Z3_symbol name = Z3_get_decl_name(ctx, decl);

  if (is_select_from_chunk(ctx, app)) {
    printf("\n! ****** BAM ****** !\n");

    Z3_ast index_ast = Z3_get_app_arg(ctx, app, 1);
    assert(Z3_get_ast_kind(ctx, index_ast) == Z3_NUMERAL_AST);

    Z3_sort index_sort = Z3_get_sort(ctx, index_ast);
    pfast_t select;

    select.processed = false;
    select.select = ast;
    Z3_get_numeral_uint(ctx, index_ast, &(select.index));
    pfasts_append_unique(selects, select);
  } else {
    unsigned num_fields = Z3_get_app_num_args(ctx, app);
    for (unsigned i = 0; i < num_fields; i++) {
      traverse_ast_and_retrieve_selects(ctx, Z3_get_app_arg(ctx, app, i),
                                        selects);
    }
  }
}

void constraints_init(constraints_t *cnstrs) {
  cnstrs->cnstrs = NULL;
  cnstrs->sz = 0;
}

void constraints_append(constraints_t *cnstrs, libvig_accesses_t accesses,
                        smt_t smt, Z3_context ctx) {
  constraint_t *curr;
  libvig_access_t *first, *second;

  first = second = NULL;

  // check if first access is saved
  for (unsigned i = 0; i < accesses.sz; i++) {
    if (accesses.accesses[i].id == smt.first_access_id) {
      first = &(accesses.accesses[i]);
      break;
    }
  }

  if (!first)
    return;

  // check if second access is saved
  for (unsigned i = 0; i < accesses.sz; i++) {
    if (accesses.accesses[i].id == smt.second_access_id) {
      second = &(accesses.accesses[i]);
      break;
    }
  }

  if (!second || first->obj != second->obj)
    return;

  cnstrs->sz += 1;
  cnstrs->cnstrs = (constraint_t *)realloc(cnstrs->cnstrs,
                                           sizeof(constraint_t) * (cnstrs->sz));

  curr = &(cnstrs->cnstrs[cnstrs->sz - 1]);

  curr->first = first;
  curr->second = second;

  Z3_ast ast = Z3_parse_smtlib2_string(ctx, smt.query, 0, 0, 0, 0, 0, 0);

  curr->cnstr = ast;
  pfasts_init(&(curr->pfs));

  traverse_ast_and_retrieve_selects(ctx, ast, &(curr->pfs));
}

void constraints_destroy(constraints_t *cnstrs) {
  if (cnstrs->sz == 0)
    return;

  for (unsigned i = 0; i < cnstrs->sz; i++) {
    pfasts_destroy(&(cnstrs->cnstrs[i].pfs));
  }
}