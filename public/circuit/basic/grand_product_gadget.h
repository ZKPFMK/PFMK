#pragma once

#include "circuit/basic/circuit.h"

namespace circuit {
// 约束数量: n-1
class grand_product_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x.size() > 1
   * y = x[0] * x[1] * ... * x[n-1]
   */
  grand_product_gadget(libsnark::protoboard<Fr>& pb,
                       libsnark::linear_combination_array<Fr> const& x,
                       const std::string& annotation_prefix = "")
      : x(x), libsnark::gadget<Fr>(pb, annotation_prefix) {
    CHECK(x.size() > 1, "");

    y.allocate(this->pb, x.size()-1, FMT(this->annotation_prefix, " y"));
    this->pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(x[0], x[1], y[0]),
      FMT(this->annotation_prefix, " y[0] = x[0] * x[1]")
    );
    
    for(size_t i=2; i<x.size(); i++){
      this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(y[i-2], x[i], y[i-1]),
        FMT(this->annotation_prefix, " y[%zu] = y[%zu] * x[%zu]", i-1, i-2, i)
      );
    }
  }

  void generate_r1cs_witness() {
    std::vector<Fr> vx(x.size());
    x.evaluate(pb.full_variable_assignment_ref(), vx);
    pb.val(y[0]) = vx[0] * vx[1];
    for(size_t i=2; i<x.size(); i++){
        pb.val(y[i-1]) = pb.val(y[i-2]) * vx[i];
    }
  }

  libsnark::pb_variable<Fr> ret() { return y[y.size()-1]; }

private:
  libsnark::pb_variable_array<Fr> y;

public:
  libsnark::linear_combination_array<Fr> const x;
};

class grand_product_batch_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x.size() > 1
   * y = x[0] * x[1] * ... * x[n-1]
   */
  grand_product_batch_gadget(libsnark::protoboard<Fr>& pb,
                              std::vector<libsnark::linear_combination_array<Fr>> const& x,
                              const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix) {
    product.resize(x.size());
    
    for(size_t i=0; i<x.size(); i++){
      product[i].reset(new grand_product_gadget(pb, x[i],
          FMT(this->annotation_prefix, " product[%zu]", i)));
    } 
  }

  void generate_r1cs_witness() {
    auto f = [this](size_t i){
      product[i]->generate_r1cs_witness();
    };
    parallel::For(product.size(), f);
  }

  size_t batch_size() { return product.size(); }
  libsnark::pb_variable<Fr> ret(size_t i) { return product[i]->ret(); }

  std::vector<std::shared_ptr<grand_product_gadget>> product;
};

inline bool TestGrandProductGadget() {
  Tick tick(__FN__);
 
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable_array<Fr> x;
  libsnark::linear_combination_array<Fr> y(3);

  x.allocate(pb, 3, "x");
  pb.val(x[0]) = 2;
  pb.val(x[1]) = 4;
  pb.val(x[2]) = 6;
  
  y[0] = x[1] - x[0];
  y[1] = x[2] - x[1];
  y[2] = 1;
  grand_product_gadget gadget(pb, y);
  gadget.generate_r1cs_witness();
  CHECK(4 == pb.val(gadget.ret()).getInt64(), "");
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints() << "\n";
  std::cout << Tick::GetIndentString()
            << "num_variables: " << pb.num_variables() << "\n";

  CHECK(pb.is_satisfied(), "");
  return true;
}

inline bool TestGrandProductBatchGadget() {
  Tick tick(__FN__);
  size_t n = 10, m = 4;
  libsnark::protoboard<Fr> pb;
  std::vector<int> ret(n);
  std::vector<libsnark::pb_variable_array<Fr>> x(n);
  std::vector<libsnark::linear_combination_array<Fr>> y(n);
  for(size_t i=0; i<n; i++){
    x[i].allocate(pb, m);
    for(size_t j=0; j<m; j++){
      y[i].emplace_back(x[i][j]);
    }
  }
  grand_product_batch_gadget gadget(pb, y);
  for(size_t i=0; i<n; i++){
    ret[i] = 1;
    for(size_t j=0; j<m; j++){
      ret[i] *= (1+i+j);
      pb.val(x[i][j]) = 1+i+j;
    }
  }
  gadget.generate_r1cs_witness();
  CHECK(pb.is_satisfied(), "");
  for(size_t i=0; i<n; i++){
    CHECK(ret[i] == pb.val(gadget.ret(i)).getUint64(), "");
  }
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints() << "\n";
  std::cout << Tick::GetIndentString()
            << "num_variables: " << pb.num_variables() << "\n";
  return true;
}
}
