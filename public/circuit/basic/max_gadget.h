#pragma once

#include "circuit/basic/abs_gadget.h"
#include "circuit/basic/select_gadget.h"

namespace circuit {

/**
 * ret = max(x, y), 其中x, y的二进制长度为n
 */
class max_gadget : public libsnark::gadget<Fr> {
public:
  max_gadget(libsnark::protoboard<Fr>& pb,
             libsnark::linear_combination<Fr> const& x,
             libsnark::linear_combination<Fr> const& y,
             size_t n, const std::string& annotation_prefix = "")
      : x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    assert(n > 0);

    abs.reset(new abs_gadget(pb, x-y, n, FMT(this->annotation_prefix, " abs")));
    slt.reset(new select_gadget(pb, abs->ret_sign(), y, x, FMT(this->annotation_prefix, " select")));
  }

  void generate_r1cs_witness() {
    abs->generate_r1cs_witness();
    slt->generate_r1cs_witness();
  }

  libsnark::pb_variable<Fr> ret() const { return slt->ret(); }
  
  // 访问内部的 abs_gadget，用于复用符号信息
  const std::shared_ptr<abs_gadget>& get_abs() const { return abs; }

private:
  std::shared_ptr<abs_gadget> abs;
  std::shared_ptr<select_gadget> slt;

public:
  libsnark::linear_combination<Fr> const x;
  libsnark::linear_combination<Fr> const y;
};

class max_batch_gadget : public libsnark::gadget<Fr> {
public:
  max_batch_gadget(libsnark::protoboard<Fr>& pb,
                    libsnark::linear_combination_array<Fr> const& x,
                    libsnark::linear_combination_array<Fr> const& y,
                    size_t n, const std::string& annotation_prefix = "")
      :libsnark::gadget<Fr>(pb, annotation_prefix) {
    assert(n > 0);
    libsnark::linear_combination_array<Fr> in(x.size());
    for(size_t i=0; i<x.size(); i++){
      in[i] = x[i] - y[i];
    }
    abs.reset(new abs_batch_gadget(pb, in, n, FMT(this->annotation_prefix, " abs")));
    slt.reset(new select_batch_gadget(pb, abs->ret_sign(), y, x, FMT(this->annotation_prefix, " select")));
  }

  void generate_r1cs_witness() {
    abs->generate_r1cs_witness();
    slt->generate_r1cs_witness();
  }

  size_t batch_size() { return abs->batch_size(); }
  libsnark::pb_variable_array<Fr> ret() const { return slt->ret(); }
  libsnark::pb_variable<Fr> ret(size_t i) const { return slt->ret(i); }

private:
  std::shared_ptr<abs_batch_gadget> abs;
  std::shared_ptr<select_batch_gadget> slt;
};

inline bool TestMaxGadget() {
  Tick tick(__FN__);
  size_t n = 3;
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x, y;
  x.allocate(pb);
  y.allocate(pb);
  max_gadget gadget(pb, x, y, n, "MaxGadget");
  for(size_t i=0; i<(1 << n); i++){
    for(size_t j=0; j<(1 << n); j++){
      pb.val(x) = i;
      pb.val(y) = j;
      gadget.generate_r1cs_witness();
      CHECK(std::max(i, j) == pb.val(gadget.ret()).getInt64(), "");
    }
  }
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  CHECK(pb.is_satisfied(), "");
  return true;
}

inline bool TestMaxBatchGadget() {
  Tick tick(__FN__);
  int n = 10, m = 4;
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable_array<Fr> x, y;
  x.allocate(pb, n);
  y.allocate(pb, n);
  max_batch_gadget gadget(pb, x, y, m, "MaxGadget");
  for(int i=0; i<n; i++){
      pb.val(x[i]) = i;
      pb.val(y[i]) = n-1-i;
  }
  gadget.generate_r1cs_witness();
  for(int i=0; i<n; i++){
    CHECK(std::max(i, n-1-i) == pb.val(gadget.ret(i)).getInt64(), "");
  }
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  CHECK(pb.is_satisfied(), "");
  return true;
}
}  // namespace circuit::fixed_point
