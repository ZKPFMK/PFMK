#pragma once

#include "circuit/basic/circuit.h"

namespace circuit {
/**
 * ret = x xnor v, 其中x, y \in {0, 1}
 * 约束数量: 1
 */
class xnor_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x, y \in {0, 1}
   * z = 1 - (x + y - 2xy) = x xnor y 
   */
  xnor_gadget(libsnark::protoboard<Fr>& pb,
              libsnark::linear_combination<Fr> const& x,
              libsnark::linear_combination<Fr> const& y,
            const std::string& annotation_prefix = "")
      : x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    z.allocate(pb);
  
    pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(2*x, y, z+x+y-1)
    );
  }

  void generate_r1cs_witness() {
    auto const& assignment = pb.full_variable_assignment_ref();
    uint vx = x.evaluate(assignment).getUint64();
    uint vy = y.evaluate(assignment).getUint64();
    if(vx == vy) pb.val(z) = 1;
    else pb.val(z) = 0;
  }

  libsnark::pb_variable<Fr> ret() const { return z; }

public:
  libsnark::linear_combination<Fr> const x;
  libsnark::linear_combination<Fr> const y;
  libsnark::pb_variable<Fr> z;
};

// 约束数量: n
class xnor_batch_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x, y \in {0, 1}
   * z = 1 - (x + y - 2xy) = x xnor y 
   */
  xnor_batch_gadget(libsnark::protoboard<Fr>& pb,
              libsnark::linear_combination_array<Fr> const& x,
              libsnark::linear_combination_array<Fr> const& y,
            const std::string& annotation_prefix = "")
      : x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    z.allocate(pb, x.size());
    
    for(size_t i=0; i<x.size(); i++){
      pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(2*x[i], y[i], z[i]+x[i]+y[i]-1)
      );
    }
  }

  void generate_r1cs_witness() {
    auto const& assignment = pb.full_variable_assignment_ref();
    auto f = [this, &assignment](size_t i){
      uint vx = x[i].evaluate(assignment).getUint64();
      uint vy = y[i].evaluate(assignment).getUint64();
      if(vx == vy) pb.val(z[i]) = 1;
      else pb.val(z[i]) = 0;
    };
    parallel::For(x.size(), f);
  }

  size_t batch_size() { return x.size(); }
  libsnark::pb_variable_array<Fr> ret() const { return z; }
  libsnark::pb_variable<Fr> ret(size_t i) const { return z[i]; }

public:
  libsnark::linear_combination_array<Fr> const x;
  libsnark::linear_combination_array<Fr> const y;
  libsnark::pb_variable_array<Fr> z;
};

inline bool TestXnorGadget() {
  Tick tick(__FN__);
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x, y;
  x.allocate(pb);
  y.allocate(pb);
  xnor_gadget gadget(pb, x, y, "OrGadget");
  for(size_t i=0; i<2; i++){
    for(size_t j=0; j<2; j++){
      pb.val(x) = i;
      pb.val(y) = j;
      gadget.generate_r1cs_witness();
      CHECK(!(i ^ j) == pb.val(gadget.ret()).getInt64(), "");
    }
  }
  
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  assert(pb.is_satisfied());
  return true;
}

inline bool TestXnorBatchGadget() {
  Tick tick(__FN__);
  size_t n = 10;
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable_array<Fr> x, y;
  x.allocate(pb, n);
  y.allocate(pb, n);
  xnor_batch_gadget gadget(pb, x, y);
  for(size_t i=0; i<n; i++){
    pb.val(x[i]) = i % 2;
    pb.val(y[i]) = (n-1-i) % 2;
  }
  gadget.generate_r1cs_witness();
  for(size_t i=0; i<n; i++){
    CHECK(!((i%2)^((n-1-i)%2)) == pb.val(gadget.ret(i)).getInt64(), "");
  }
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  CHECK(pb.is_satisfied(), "");
  return true;
}
}  // namespace circuit::fixed_point
