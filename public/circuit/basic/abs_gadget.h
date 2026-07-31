#pragma once

#include "circuit/basic/pack_gadget.h"

namespace circuit {
/**
 * ret = |x|, 其中x \in {0, 1}^n
 * 约束数量: n+3
 */
class abs_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x \in {0, 1}^n < (p-1)/2
   * ret = |x|
   */
  abs_gadget(libsnark::protoboard<Fr>& pb,
             libsnark::linear_combination<Fr> const& x,
             size_t n, const std::string& annotation_prefix = "")
      : x(x), libsnark::gadget<Fr>(pb, annotation_prefix) {
    // Tick tick(__FN__);
    CHECK(n < 127, "");
    s.allocate(pb, annotation_prefix + " s");
    y.allocate(pb, annotation_prefix + " y");
  
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(s, s-1, 0),
      annotation_prefix + " s_bool"
    );
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(s*2, x, x-y), //x - y = 2 * s * x
      annotation_prefix + " abs_calc"
    );

    // 使用 pack_gadget 验证 y 在 [0, 2^n) 范围内
    // pack_gadget 会将 y 解包为 n 个比特，并验证每个比特是 0 或 1
    pack.reset(new pack_gadget(pb, y, n, true, annotation_prefix + " range_check"));
  }

  libsnark::pb_variable<Fr> ret_abs() {
    return y;
  }

  libsnark::pb_variable<Fr> ret_sign() {
    return s;
  }

  void generate_r1cs_witness() {
    Fr vx = x.evaluate(pb.full_variable_assignment_ref());
    if(vx.isNegative()){
      pb.val(s) = 1;
      vx = -vx;
    }else{
      pb.val(s) = 0;
    }
    pb.val(y) = vx;
    pack->generate_r1cs_witness();
  }
  libsnark::pb_variable<Fr> s;
  std::unique_ptr<pack_gadget> pack;

public:
  libsnark::linear_combination<Fr> const x;
  libsnark::pb_variable<Fr> y;
};


// 约束数量: m(n+3)
class abs_batch_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x \in {0, 1}^n < (p-1)/2
   * ret = |x|
   */
  abs_batch_gadget(libsnark::protoboard<Fr>& pb,
                   libsnark::linear_combination_array<Fr> const& x,
                   size_t n, const std::string& annotation_prefix = "")
      : x(x), libsnark::gadget<Fr>(pb, annotation_prefix) {
    // Tick tick(__FN__);
    CHECK(n < 127, "");
    s.allocate(pb, x.size(), FMT(annotation_prefix, " s"));
    y.allocate(pb, x.size(), FMT(annotation_prefix, " y"));
    
    for(size_t i=0; i<x.size(); i++){
      pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(s[i], s[i]-1, 0),
        FMT(annotation_prefix, " s_bool_%zu", i)
      );
      pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(s[i]*2, x[i], x[i]-y[i]), //x - y = 2 * s * x
        FMT(annotation_prefix, " abs_calc_%zu", i)
      );
    }
    pack.reset(new pack_batch_gadget(pb, y, n, annotation_prefix + " pack"));
  }

  size_t batch_size() { return x.size(); }

  libsnark::pb_variable<Fr> ret_abs(size_t i) {
    return y[i];
  }

  libsnark::pb_variable_array<Fr> ret_abs() {
    return y;
  }

  libsnark::pb_variable<Fr> ret_bit(size_t i, size_t j) {
    return pack->ret(i, j);
  }

  std::vector<libsnark::pb_variable_array<Fr>> ret_bit() {
    return pack->ret();
  }

  libsnark::pb_variable<Fr> ret_sign(size_t i) {
    return s[i];
  }

  libsnark::pb_variable_array<Fr> ret_sign() {
    return s;
  }

  void generate_r1cs_witness() {
    auto f = [this](size_t i){
      Fr vx = x[i].evaluate(pb.full_variable_assignment_ref());
      if(vx.isNegative()){
        pb.val(s[i]) = 1;
        vx = -vx;
      }else{
        pb.val(s[i]) = 0;
      }
      pb.val(y[i]) = vx;
    };
    parallel::For(x.size(), f);
    pack->generate_r1cs_witness();
  }

  /**
   * 使用预计算的原始值生成 witness (跳过昂贵的 evaluate 调用)
   * @param precomputed_x 预计算的原始值数组 (有符号), 大小必须等于 batch_size
   */
  void generate_r1cs_witness_precomputed(std::vector<int64_t> const& precomputed_x) {
    CHECK(precomputed_x.size() == x.size(), "precomputed size mismatch");
    std::vector<Fr> abs_values(x.size());
    auto f = [this, &precomputed_x, &abs_values](size_t i){
      int64_t vx = precomputed_x[i];
      if (vx < 0) {
        pb.val(s[i]) = 1;
        abs_values[i] = Fr(-vx);
      } else {
        pb.val(s[i]) = 0;
        abs_values[i] = Fr(vx);
      }
      pb.val(y[i]) = abs_values[i];
    };
    parallel::For(x.size(), f);
    pack->generate_r1cs_witness_precomputed(abs_values);
  }

  libsnark::pb_variable_array<Fr> s;
  std::shared_ptr<pack_batch_gadget> pack;

public:
  libsnark::linear_combination_array<Fr> const x;
  libsnark::pb_variable_array<Fr> y;
};

inline bool TestAbsGadget() {
  Tick tick(__FN__);
  size_t n = 2;
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x;
  x.allocate(pb);

  abs_gadget gadget(pb, x, n);
  for(int i=1; i<(1<<n); i++){
    pb.val(x) = -i;
    gadget.generate_r1cs_witness();
    CHECK(pb.is_satisfied(), "");
    CHECK(i == pb.val(gadget.ret_abs()).getInt64(), "");
  }
  
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
  return true;
}

inline bool TestAbsBatchGadget() {
  Tick tick(__FN__);
  size_t n = 10, m = 4;
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable_array<Fr> x;
  x.allocate(pb, n);

  abs_batch_gadget gadget(pb, x, m);
  for(int i=0; i<n; i++){
    pb.val(x[i]) = i - (n/2);
  }
  gadget.generate_r1cs_witness();
  CHECK(pb.is_satisfied(), "");
  for(int i=0; i<n; i++){
    size_t r = pb.val(x[i]).isNegative() ? (n/2)-i : i-(n/2);
    CHECK(r == pb.val(gadget.ret_abs(i)).getInt64(), "");
  }
  
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
  return true;
}
}  // namespace circuit::fixed_point
