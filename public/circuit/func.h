
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

    std::array<parallel::VoidTask, 3> tasks;
    tasks[0] = [&pb, &a]() {
      auto parallel_f= [&pb, &a](size_t i) {
        BuildHpVec(pb.get_constraint_system().constraints[i].a, a[i]);
      };
      parallel::For(pb.num_constraints(), parallel_f);
    };
    tasks[1] = [&pb, &b]() {
      auto parallel_f= [&pb, &b](size_t i) {
        BuildHpVec(pb.get_constraint_system().constraints[i].b, b[i]);
      };
      parallel::For(pb.num_constraints(), parallel_f);
    }; 
    tasks[2] = [&pb, &c]() {
      auto parallel_f= [&pb, &c](size_t i) {
        BuildHpVec(pb.get_constraint_system().constraints[i].c, c[i]);
      };
      parallel::For(pb.num_constraints(), parallel_f);
    };
    parallel::Invoke(tasks);
}
};