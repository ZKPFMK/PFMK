
#pragma once

#include "ecc/ecc.h"
#include <libsnark/gadgetlib1/gadget.hpp>
namespace circuit {
inline void BuildHpVec(libsnark::linear_combination<Fr> const &lc,
                       std::vector<Fr> & a){
    for (auto const &term : lc.terms) {
        a[term.index] += term.coeff;
    }
}

inline void Preprocess(libsnark::protoboard<Fr> const& pb,
                       std::vector<std::vector<Fr>> & a,
                       std::vector<std::vector<Fr>> & b,
                       std::vector<std::vector<Fr>> & c){
    a.resize(pb.num_constraints(), std::vector<Fr>(pb.num_variables() + 1, 0));
    b.resize(pb.num_constraints(), std::vector<Fr>(pb.num_variables() + 1, 0));
    c.resize(pb.num_constraints(), std::vector<Fr>(pb.num_variables() + 1, 0));

    // Use const reference to avoid copying the entire constraint system
    auto const& cs = pb.get_constraint_system_ref();

    std::array<parallel::VoidTask, 3> tasks;
    tasks[0] = [&cs, &a]() {
      auto parallel_f= [&cs, &a](size_t i) {
        BuildHpVec(cs.constraints[i].a, a[i]);
      };
      parallel::For((size_t)cs.num_constraints(), parallel_f);
    };
    tasks[1] = [&cs, &b]() {
      auto parallel_f= [&cs, &b](size_t i) {
        BuildHpVec(cs.constraints[i].b, b[i]);
      };
      parallel::For((size_t)cs.num_constraints(), parallel_f);
    }; 
    tasks[2] = [&cs, &c]() {
      auto parallel_f= [&cs, &c](size_t i) {
        BuildHpVec(cs.constraints[i].c, c[i]);
      };
      parallel::For((size_t)cs.num_constraints(), parallel_f);
    };
    parallel::Invoke(tasks);
}

inline void BuildSparseFromLC(libsnark::protoboard<Fr> const& pb,
                             SparseMatrix& mat,
                             int selector) {
    int64_t num_constraints = (int64_t)pb.num_constraints();
    int64_t num_vars = (int64_t)pb.num_variables() + 1;

    // Use const reference to avoid copying the entire constraint system
    auto const& cs = pb.get_constraint_system_ref();

    mat.rows_ = num_constraints;
    mat.cols_ = num_vars;
    mat.row_ptr_.resize(num_constraints + 1);

    // Step 1: Parallel compute per-row nnz
    auto compute_nnz = [&cs, &mat, selector](int64_t i) {
      auto const& constraint = cs.constraints[i];
      auto const& lc = (selector == 0) ? constraint.a : (selector == 1) ? constraint.b : constraint.c;
      mat.row_ptr_[i + 1] = (int64_t)lc.terms.size();
    };
    parallel::For(num_constraints, compute_nnz);

    // Step 2: Prefix sum to build row_ptr (sequential, but O(m) which is fast)
    mat.row_ptr_[0] = 0;
    for (int64_t i = 0; i < num_constraints; ++i) {
      mat.row_ptr_[i + 1] += mat.row_ptr_[i];
    }

    int64_t total_nnz = mat.row_ptr_[num_constraints];
    mat.col_idx_.resize(total_nnz);
    mat.values_.resize(total_nnz);

    // Step 3: Parallel fill col_idx and values (each row is independent)
    auto fill_row = [&cs, &mat, selector](int64_t i) {
      auto const& constraint = cs.constraints[i];
      auto const& lc = (selector == 0) ? constraint.a : (selector == 1) ? constraint.b : constraint.c;
      int64_t offset = mat.row_ptr_[i];
      for (size_t j = 0; j < lc.terms.size(); ++j) {
        mat.col_idx_[offset + (int64_t)j] = (int64_t)lc.terms[j].index;
        mat.values_[offset + (int64_t)j] = lc.terms[j].coeff;
      }
    };
    parallel::For(num_constraints, fill_row);
}

inline void PreprocessSparse(libsnark::protoboard<Fr> const& pb,
                             SparseMatrix& a,
                             SparseMatrix& b,
                             SparseMatrix& c) {
    // Build all three sparse matrices in parallel
    std::array<parallel::VoidTask, 3> tasks;
    tasks[0] = [&]() { BuildSparseFromLC(pb, a, 0); };
    tasks[1] = [&]() { BuildSparseFromLC(pb, b, 1); };
    tasks[2] = [&]() { BuildSparseFromLC(pb, c, 2); };
    parallel::Invoke(tasks);
}

inline R1csStats GetR1csStats(SparseMatrix const& a, SparseMatrix const& b, SparseMatrix const& c) {
    R1csStats stats;
    stats.num_constraints = a.rows();
    stats.num_variables = a.cols();
    stats.nnz_a = a.nnz();
    stats.nnz_b = b.nnz();
    stats.nnz_c = c.nnz();
    return stats;
}

};