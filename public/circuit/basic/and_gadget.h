#pragma once

#include "circuit/basic/circuit.h"

namespace circuit {

// 约束数量: 1
class and_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x, y \in {0, 1}
   * z = x * y = x and y 
   */
  and_gadget(libsnark::protoboard<Fr>& pb,
            libsnark::linear_combination<Fr> const& x,
            libsnark::linear_combination<Fr> const& y,
            const std::string& annotation_prefix = "")
      : x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    z.allocate(pb, FMT(this->annotation_prefix, " z"));

    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(x, y, z),
      FMT(this->annotation_prefix, " and")
    );
  }

  void generate_r1cs_witness() {
    auto const& assignment = pb.full_variable_assignment_ref();
    Fr vx = x.evaluate(assignment);
    Fr vy = y.evaluate(assignment);
    pb.val(z) = vx * vy;
  }

  libsnark::pb_variable<Fr> ret() const { return z; }

public:
  libsnark::linear_combination<Fr> const x;
  libsnark::linear_combination<Fr> const y;
  libsnark::pb_variable<Fr> z;
};

inline bool TestAndGadget() {
  Tick tick(__FN__);
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x, y;
  x.allocate(pb);
  y.allocate(pb);
  and_gadget gadget(pb, x, y, "OrGadget");
  for(size_t i=0; i<2; i++){
    for(size_t j=0; j<2; j++){
      pb.val(x) = i;
      pb.val(y) = j;
      gadget.generate_r1cs_witness();
      CHECK((i & j) == pb.val(gadget.ret()).getInt64(), "");
    }
  }
  
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  CHECK(pb.is_satisfied(), "");
  return true;
}
}  // namespace circuit::fixed_point
