#pragma once

#include "circuit/basic/circuit.h"

namespace circuit {

// 约束数量: 2
class zero_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:for any x
   * y = x == 0 ? 1 : 0
   */
  zero_gadget(libsnark::protoboard<Fr>& pb,
              libsnark::linear_combination<Fr> const& x,
              const std::string& annotation_prefix = "")
      : x(x), libsnark::gadget<Fr>(pb, annotation_prefix) {
    t.allocate(pb, FMT(this->annotation_prefix, " t"));
    y.allocate(pb, FMT(this->annotation_prefix, " y"));

    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(x, y, 0),
      FMT(this->annotation_prefix, " x*y=0")
    );
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(t, x, -y+1),
      FMT(this->annotation_prefix, " t*x=1-y")
    );
  }

  void generate_r1cs_witness() {
    Fr vx = x.evaluate(pb.full_variable_assignment_ref());
    if(vx == 0){
      pb.val(t) = 0;
      pb.val(y) = 1;
    }else{
      pb.val(t) = 1 / vx;
      pb.val(y) = 0;
    }
  }

  libsnark::pb_variable<Fr> ret() const { return y; }

private:
  libsnark::pb_variable<Fr> t;

public:
  libsnark::linear_combination<Fr> const x;
  libsnark::pb_variable<Fr> y;
};

// 约束数量: 2
class zero_batch_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:for any x
   * y = x == 0 ? 1 : 0
   */
  zero_batch_gadget(libsnark::protoboard<Fr>& pb,
                    libsnark::linear_combination_array<Fr> const& x,
                    const std::string& annotation_prefix = "")
      : x(x), libsnark::gadget<Fr>(pb, annotation_prefix) {
    t.allocate(pb, x.size());
    y.allocate(pb, x.size());
    
    for(size_t i=0; i<x.size(); i++){
      pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(x[i], y[i], 0)
      );
      pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(t[i], x[i], -y[i]+1)
      );
    }
    
  }

  void generate_r1cs_witness() {
    auto const& assignment = pb.full_variable_assignment_ref();
    auto f = [this, &assignment](size_t i){
      Fr vx = x[i].evaluate(assignment);
      if(vx == 0){
        pb.val(t[i]) = 0;
        pb.val(y[i]) = 1;
      }else{
        pb.val(t[i]) = 1 / vx;
        pb.val(y[i]) = 0;
      }
    };
    parallel::For(x.size(), f);
  }

  size_t batch_size() { return x.size(); }
  libsnark::pb_variable_array<Fr> ret() const { return y; }
  libsnark::pb_variable<Fr> ret(size_t i) const { return y[i]; }

private:
  libsnark::pb_variable_array<Fr> t;

public:
  libsnark::linear_combination_array<Fr> const x;
  libsnark::pb_variable_array<Fr> y;
};

inline bool TestZeroGadget() {
  Tick tick(__FN__);
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x;
  x.allocate(pb);
  zero_gadget gadget(pb, x);
  for(size_t i=0; i<2; i++){
      pb.val(x) = i;
      gadget.generate_r1cs_witness();
      CHECK((i == 0 ? 1 : 0) == pb.val(gadget.ret()).getInt64(), "");
  }
  
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  CHECK(pb.is_satisfied(), "");
  return true;
}

inline bool TestZeroBatchGadget() {
  Tick tick(__FN__);
  size_t n = 10;
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable_array<Fr> x;
  x.allocate(pb, n);
  zero_batch_gadget gadget(pb, x);
  for(size_t i=0; i<n; i++){
    pb.val(x[i]) = i % 2;
  }
  gadget.generate_r1cs_witness();
  for(size_t i=0; i<n; i++){
    CHECK((i%2 == 0 ? 1 : 0) == pb.val(gadget.ret(i)).getInt64(), "");
  }
      
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  CHECK(pb.is_satisfied(), "");
  return true;
}

}  // namespace circuit::fixed_point
