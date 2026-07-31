#pragma once

#include "circuit/basic/not_zero_gadget.h"

namespace circuit{

// 约束数量: 1
class or_gadget1 : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x, y \in {0, 1}
   * z = x + y - xy =  x1 or x2
   */
  or_gadget1(libsnark::protoboard<Fr>& pb,
            libsnark::linear_combination<Fr> const& x,
            libsnark::linear_combination<Fr> const& y,
            const std::string& annotation_prefix = "")
      : x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    z.allocate(pb, FMT(this->annotation_prefix, " z"));
    pb.add_r1cs_constraint(
      libsnark::r1cs_constraint<Fr>(x, y, x+y-z),
      FMT(this->annotation_prefix, " or")
    );
  }

  void generate_r1cs_witness() {
    auto const& assignment = pb.full_variable_assignment_ref();
    uint vx = x.evaluate(assignment).getUint64();
    uint vy = y.evaluate(assignment).getUint64();
    pb.val(z) = vx | vy;
  }

  libsnark::pb_variable<Fr> ret() const { return z; }

public:
  libsnark::linear_combination<Fr> const x, y;
  libsnark::pb_variable<Fr> z;
};

// 约束数量: 2
class or_gadget2 : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x1, ..., xn \in {0, 1}
   * y = x1 or ... or xn
   */
  or_gadget2(libsnark::protoboard<Fr>& pb,
              libsnark::linear_combination_array<Fr> const& x,
              const std::string& annotation_prefix = "")
      :libsnark::gadget<Fr>(pb, annotation_prefix) {
    libsnark::linear_combination<Fr> t;
    for(size_t i=0; i<x.size(); i++){
      t = t + x[i];
    }
    not_zero.reset(new not_zero_gadget(pb, t));
  }

  void generate_r1cs_witness() {
    not_zero->generate_r1cs_witness();
  }

  libsnark::pb_variable<Fr> ret() const { return not_zero->ret(); }
private:
  std::shared_ptr<not_zero_gadget> not_zero;
};

// 约束数量: n
class or1_batch_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x, y \in {0, 1}
   * z = x + y - xy =  x1 or x2
   */
  or1_batch_gadget(libsnark::protoboard<Fr>& pb,
                  libsnark::linear_combination_array<Fr> const& x,
                  libsnark::linear_combination_array<Fr> const& y,
                  const std::string& annotation_prefix = "")
      : x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    z.allocate(pb, x.size(), FMT(this->annotation_prefix, " z"));
    for(size_t i=0; i<x.size(); i++){
      pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(x[i], y[i], x[i]+y[i]-z[i]),
        FMT(this->annotation_prefix, " or_%zu", i)
      );
    }
  }

  void generate_r1cs_witness() {
    auto const& assignment = pb.full_variable_assignment_ref();
    auto f = [this, &assignment](size_t i){
      uint vx = x[i].evaluate(assignment).getUint64();
      uint vy = y[i].evaluate(assignment).getUint64();
      pb.val(z[i]) = vx | vy;
    };
    parallel::For(x.size(), f);
  }

  libsnark::pb_variable<Fr> ret(size_t i) const { return z[i]; }
  libsnark::pb_variable_array<Fr> ret() const { return z; }
  size_t batch_size() {
    return x.size();
  }

public:
  libsnark::linear_combination_array<Fr> const x, y;
  libsnark::pb_variable_array<Fr> z;
};

class or2_batch_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:x1, ..., xn \in {0, 1}
   * y =  x1 or ... or xn
   */
  or2_batch_gadget(libsnark::protoboard<Fr>& pb,
                   std::vector<libsnark::linear_combination_array<Fr>> const& x,
                   const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix) {
    libsnark::linear_combination_array<Fr> t(x.size());
    for(size_t i=0; i<x.size(); i++){
      for(size_t j=0; j<x[0].size(); j++){
        t[i] = t[i] + x[i][j];
      }
    }
    not_zero.reset(new not_zero_batch_gadget(pb, t));
  }

  void generate_r1cs_witness() {
    not_zero->generate_r1cs_witness();
  }

  libsnark::pb_variable<Fr> ret(size_t i) const { return not_zero->ret(i); }
  libsnark::pb_variable_array<Fr> ret() const { return not_zero->ret(); }
  size_t batch_size() {
    return not_zero->batch_size();
  }

private:
  std::shared_ptr<not_zero_batch_gadget> not_zero;
};

inline bool TestOr1Gadget() {
  Tick tick(__FN__);
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> x, y;
  x.allocate(pb);
  y.allocate(pb);
  or_gadget1 gadget(pb, x, y);

  for(size_t i=0; i<2; i++){
    for(size_t j=0; j<2; j++){
      pb.val(x) = i;
      pb.val(y) = j;
      gadget.generate_r1cs_witness();
      CHECK((i | j) == pb.val(gadget.ret()).getInt64(), "");
    }
  }
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  CHECK(pb.is_satisfied(), "");
  return true;
}

inline bool TestOr2Gadget() {
  Tick tick(__FN__);
  size_t n = 10;
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable_array<Fr> x;
  x.allocate(pb, n);
  or_gadget2 gadget(pb, x);

  size_t j = 0;
  for(size_t i=0; i<n; i++){
    pb.val(x[i]) = i % 2;
    j = j | (i % 2);
  }
  gadget.generate_r1cs_witness();
  CHECK(pb.is_satisfied(), "");
  CHECK(j == pb.val(gadget.ret()).getInt64(), "");
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
  return true;
}

inline bool TestOr1BatchGadget() {
  Tick tick(__FN__);
  size_t n = 10;
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable_array<Fr> x, y;
  x.allocate(pb, n);
  y.allocate(pb, n);
  or1_batch_gadget gadget(pb, x, y);
  for(size_t i=0; i<n; i++){
    pb.val(x[i]) = i % 2;
    pb.val(y[i]) = (n-1-i) % 2;
  }
  gadget.generate_r1cs_witness();
  for(size_t i=0; i<n; i++){
    CHECK(((i%2)|((n-1-i)%2)) == pb.val(gadget.ret(i)).getInt64(), "");
  }
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  CHECK(pb.is_satisfied(), "");
  return true;
}

inline bool TestOr2BatchGadget() {
  Tick tick(__FN__);
  size_t n = 10, m = 4;
  std::vector<int> ret(n);
  libsnark::protoboard<Fr> pb;
  std::vector<libsnark::pb_variable_array<Fr>> x(n);
  std::vector<libsnark::linear_combination_array<Fr>> y(n);
  for(size_t i=0; i<n; i++){
    x[i].allocate(pb, m);
    for(size_t j=0; j<m; j++){
      y[i].emplace_back(x[i][j]);
    }
  }
  or2_batch_gadget gadget(pb, y);
  for(size_t i=0; i<n; i++){
    ret[i] = 0;
    for(size_t j=0; j<m; j++){
      pb.val(x[i][j]) = (i * n + j) % 2;
      ret[i] = ret[i] | ((i * n + j) % 2);
    }
  }
  gadget.generate_r1cs_witness();
  for(size_t i=0; i<n; i++){
    CHECK(ret[i] == pb.val(gadget.ret(i)).getInt64(), "");
  }
  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints()
            << ", num_variables: " << pb.num_variables() << "\n";
    
  CHECK(pb.is_satisfied(), "");
  return true;
}
}
