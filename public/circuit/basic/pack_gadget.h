#pragma once

#include "circuit/basic/circuit.h"

namespace circuit {
// 约束数量:n+1, n:比特长度
class pack_gadget : public libsnark::gadget<Fr> {

public:
  libsnark::pb_variable_array<Fr> b;
  libsnark::linear_combination<Fr> const x;

  pack_gadget(libsnark::protoboard<Fr> &pb,
              libsnark::linear_combination<Fr> const& x,
              size_t n, bool enforce_pack = true, const std::string &annotation_prefix="") :
      x(x), gadget<Fr>(pb, annotation_prefix) {
    assert(n >= 0);
    b.allocate(pb, n, FMT(this->annotation_prefix, " bits"));
    
    Fr pow2 = 1;
    std::vector<libsnark::linear_term<Fr>> terms;
    for (size_t i = 0; i < b.size(); ++i) {
      pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(b[i], -b[i] + 1, 0),
        FMT(this->annotation_prefix, " b[%zu] is binary", i)
      );
      terms.emplace_back(b[i] * pow2);
      pow2 *= 2;
    }

    if(enforce_pack){
      pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(1, terms, x),
        FMT(this->annotation_prefix, " pack")
      );
    }
  }

  void generate_r1cs_witness(){
    Fr vx = x.evaluate(pb.full_variable_assignment_ref());

    mpz_class v = vx.getMpz();
    for (size_t i=0; i<b.size(); ++i){
        pb.val(b[i]).setMpz(v & 1);
        v = v >> 1;
    }
  }

  libsnark::pb_variable_array<Fr> ret() { 
    return b;
  }

  libsnark::pb_variable<Fr> ret(size_t i) { 
    DCHECK(i < b.size(), "");
    return b[i];
  }
};

// 约束数量:m*(n+1), n:比特长度, m:batch size
class pack_batch_gadget : public libsnark::gadget<Fr> {

public:
  std::vector<libsnark::pb_variable_array<Fr>> b;
  libsnark::linear_combination_array<Fr> const x;

  pack_batch_gadget(libsnark::protoboard<Fr> &pb,
                    libsnark::linear_combination_array<Fr> const& x,
                    size_t n, const std::string &annotation_prefix="") :
      x(x), gadget<Fr>(pb, annotation_prefix) {
    CHECK(n >= 1, "");
    b.resize(n);
      
    
    std::vector<std::vector<libsnark::linear_term<Fr>>> terms(x.size());
    Fr pow2 = 1;
    for(size_t i=0; i<n; i++){
      b[i].allocate(pb, x.size(), FMT(this->annotation_prefix, " bits[%zu]", i));
      for(size_t j=0; j<x.size(); j++){
        pb.add_r1cs_constraint(
          libsnark::r1cs_constraint<Fr>(b[i][j], -b[i][j] + 1, 0),
          FMT(this->annotation_prefix, " b[%zu][%zu] is binary", i, j)
        );
        terms[j].emplace_back(b[i][j], pow2);
      }
      pow2 *= 2;  // 在外层循环递增，确保每个比特位有正确的权重
    }

    for(size_t j=0; j<x.size(); j++){
      pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(1, terms[j], x[j]),
        FMT(this->annotation_prefix, " pack[%zu]", j)
      );
    }
  }

  void generate_r1cs_witness(){
    auto const& assignment = pb.full_variable_assignment_ref();
    auto f = [this, &assignment](size_t j){
      Fr vx = x[j].evaluate(assignment);
      mpz_class v = vx.getMpz();
      for (size_t i=0; i<b.size(); ++i){
          pb.val(b[i][j]).setMpz(v & 1);
          v = v >> 1;
      }
    };
    parallel::For(x.size(), f);
  }

  /**
   * 使用预计算的绝对值进行比特分解 (跳过昂贵的 evaluate 调用)
   * @param precomputed_abs 预计算的绝对值数组, 大小必须等于 batch_size
   */
  void generate_r1cs_witness_precomputed(std::vector<Fr> const& precomputed_abs) {
    CHECK(precomputed_abs.size() == x.size(), "precomputed size mismatch");
    auto f = [this, &precomputed_abs](size_t j){
      mpz_class v = precomputed_abs[j].getMpz();
      for (size_t i=0; i<b.size(); ++i){
          pb.val(b[i][j]).setMpz(v & 1);
          v = v >> 1;
      }
    };
    parallel::For(x.size(), f);
  }

  size_t batch_size() {
    return x.size();
  }

  std::vector<libsnark::pb_variable_array<Fr>> ret() { 
    return b;
  }

  // 第i个元素的第j比特
  libsnark::pb_variable<Fr> ret(size_t i, size_t j) { 
    return b[j][i];
  }
};

inline bool TestPackGadget() {
  Tick tick(__FN__);
  size_t n = 4;
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x;
  x.allocate(pb);
  pack_gadget gadget(pb, x, n);
  for(size_t i=0; i<(1 << n); i++){
      pb.val(x) = i;
      gadget.generate_r1cs_witness();
      for(size_t j=0; j<n; j++){
        CHECK((i >> j & 1) == pb.val(gadget.ret(j)).getInt64(), "")
      }
  }
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
  CHECK(pb.is_satisfied(), "");
  return true;
}

inline bool TestPackBatchGadget() {
  Tick tick(__FN__);
  size_t n = 10, m = 4;
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable_array<Fr> x;
  x.allocate(pb, n);
  pack_batch_gadget gadget(pb, x, m);
  for(size_t i=0; i<n; i++){
    pb.val(x[i]) = i;
  }
  gadget.generate_r1cs_witness();
  for(size_t i=0; i<n; i++){
    for(size_t j=0; j<m; j++){
      CHECK((i >> j & 1) == pb.val(gadget.ret(i, j)).getInt64(), "")
    }
  }
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  CHECK(pb.is_satisfied(), "");
  return true;
}
}
