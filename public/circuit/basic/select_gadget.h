#pragma once

#include "circuit/basic/circuit.h"

namespace circuit {
// 约束数量: 1
class select_gadget : public libsnark::gadget<Fr> {
public:
  /**
   * 要求:flag \in {0, 1}
   * z = b (x - y) + y
   * 当b = 1 => z = x
   * 当b = 0 => z = y
   */
  select_gadget(libsnark::protoboard<Fr>& pb,
                libsnark::linear_combination<Fr> const& b,
                libsnark::linear_combination<Fr> const& x,
                libsnark::linear_combination<Fr> const& y,
                const std::string& annotation_prefix = "")
      : b(b), x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    z.allocate(pb, FMT(this->annotation_prefix, " z"));
  
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(b, x - y, z - y),
        FMT(this->annotation_prefix, " z = b ? x : y")
    );
  }

  void generate_r1cs_witness() {
    auto const& assignment = pb.full_variable_assignment_ref();
    Fr vb = b.evaluate(assignment);
    Fr vx = x.evaluate(assignment);
    Fr vy = y.evaluate(assignment);
    if(vb == 0){
        this->pb.val(z) = vy;
    }else{
        this->pb.val(z) = vx;
    }
  }

  libsnark::pb_variable<Fr> ret() { return z; }
  libsnark::linear_combination<Fr> other() { return x+y-z; }

public:
  libsnark::linear_combination<Fr> const b;
  libsnark::linear_combination<Fr> const x;
  libsnark::linear_combination<Fr> const y;
  libsnark::pb_variable<Fr> z;
};

// 约束数量: n
class select_batch_gadget : public libsnark::gadget<Fr> {
public:
    select_batch_gadget(libsnark::protoboard<Fr>& pb,
                      libsnark::linear_combination<Fr> const& b,
                      libsnark::linear_combination_array<Fr> const& x,
                      libsnark::linear_combination_array<Fr> const& y,
                 const std::string& annotation_prefix = "")
      : x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    // CHECK(x.size() == y.size(), "");
    z.allocate(pb, x.size(), FMT(this->annotation_prefix, " z"));
    this->b.resize(x.size(), b);

    for(size_t i=0; i<x.size(); i++){
      this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(this->b[i], x[i]-y[i], z[i]-y[i]),
        FMT(this->annotation_prefix, " z[%zu] = b ? x[%zu] : y[%zu]", i, i, i)
      );
    }
  }
  /**
   * 要求:flag \in {0, 1}
   * z = b (x - y) + y
   * 当b = 1 => z = x
   * 当b = 0 => z = y
   */
  select_batch_gadget(libsnark::protoboard<Fr>& pb,
                      libsnark::linear_combination_array<Fr> const& b,
                      libsnark::linear_combination_array<Fr> const& x,
                      libsnark::linear_combination_array<Fr> const& y,
                 const std::string& annotation_prefix = "")
      : b(b), x(x), y(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    // CHECK(x.size() == y.size(), "");
    z.allocate(pb, x.size(), FMT(this->annotation_prefix, " z"));
    
    for(size_t i=0; i<x.size(); i++){
      this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(b[i], x[i]-y[i], z[i]-y[i]),
        FMT(this->annotation_prefix, " z[%zu] = b[%zu] ? x[%zu] : y[%zu]", i, i, i, i)
      );
    }
  }

  void generate_r1cs_witness() {
    auto const& assignment = pb.full_variable_assignment_ref();
    auto f = [this, &assignment](size_t i){
      Fr vx = x[i].evaluate(assignment);
      Fr vy = y[i].evaluate(assignment);
      Fr vb = b[i].evaluate(assignment);
      if(vb == Fr(0)) pb.val(z[i]) = vy;
      else if(vb == Fr(1)) pb.val(z[i]) = vx;
      else CHECK(false, "");
    };
    parallel::For(x.size(), f);
  }
  size_t batch_size() { return x.size(); }
  libsnark::pb_variable_array<Fr> ret() { return z; }
  libsnark::pb_variable<Fr> ret(size_t i) { return z[i]; }
  libsnark::linear_combination_array<Fr> other() { 
    libsnark::linear_combination_array<Fr> r;
    for(size_t i=0; i<z.size(); i++){
      r.emplace_back(x[i] + y[i] - z[i]);
    }
    return r;
  }

public:
  libsnark::linear_combination_array<Fr> b;
  libsnark::linear_combination_array<Fr> const x;
  libsnark::linear_combination_array<Fr> const y;
  libsnark::pb_variable_array<Fr> z;
};


// class range_select_gadget : public libsnark::gadget<Fr> {
// public:
//   /**
//    * 要求: target, lbound, rbound, \in {0, 1}^n
//    * x < a => x
//    * x \in [a, b] => y
//    * x > b => z
//    * ret = z + b1(y - z) + b0(x - y)
//    * 约束数量: 2n+12
//    */
//   range_select_gadget(libsnark::protoboard<Fr>& pb,
//                       size_t n,
//                       libsnark::linear_combination<Fr> const& target,
//                       libsnark::linear_combination<Fr> const& lbound,
//                       libsnark::linear_combination<Fr> const& rbound,
//                       libsnark::linear_combination<Fr> const& x,
//                       libsnark::linear_combination<Fr> const& y,
//                       libsnark::linear_combination<Fr> const& z,
//                       const std::string& annotation_prefix = "")
//     : target(target), lbound(lbound), rbound(rbound), x(x), y(y), z(z),
//       libsnark::gadget<Fr>(pb, annotation_prefix) {
//     range.reset(new range_gadget(pb, n, target, lbound, rbound));

//     t.allocate(pb);
//     t1.allocate(pb);
//     pb.add_r1cs_constraint(
//       libsnark::r1cs_constraint<Fr>(range->ret(1), y-z, t1)
//     );
//     pb.add_r1cs_constraint(
//       libsnark::r1cs_constraint<Fr>(range->ret(0), x-y, t-z-t1)
//     );
//   }

//   void generate_r1cs_witness() {
//     range->generate_r1cs_witness();
//     Fr vb1 = pb.val(range->ret(1)).getUint64();
//     Fr vb0 = pb.val(range->ret(0)).getUint64();
//     Fr vx = x.evaluate(pb.full_variable_assignment());
//     Fr vy = y.evaluate(pb.full_variable_assignment());
//     Fr vz = z.evaluate(pb.full_variable_assignment());
//     pb.val(t1) = vb1 * (vy - vz);
//     if(vb1+vb0 == 2) pb.val(t) = vx;
//     else if(vb1+vb0 == 1) pb.val(t) = vy;
//     else if(vb1+vb0 == 0) pb.val(t) = vz;
//     else CHECK(false, "");
//   }

//   libsnark::pb_variable<Fr> ret() {
//     return t;
//   }
//   std::shared_ptr<range_gadget> range;

//   libsnark::pb_variable<Fr> t, t1;
  
//   libsnark::linear_combination<Fr> const target, lbound, rbound;
//   libsnark::linear_combination<Fr> const x, y, z;
// };




// inline bool TestRangeSelectGadget() {
//   Tick tick(__FN__);
//   size_t n = 4;
//   libsnark::protoboard<Fr> pb;
//   libsnark::pb_variable<Fr> b, x, y, z, l, r;
//   b.allocate(pb, "b");
//   l.allocate(pb);
//   r.allocate(pb);
//   x.allocate(pb, "x");
//   y.allocate(pb, "y");
//   z.allocate(pb, "z");
//   /**
//    * 这里需要改为pb_linea
//    */
//   range_select_gadget gadget(pb, n, b, l, r, x, y, z);

//   pb.val(b) = 1;
//   pb.val(l) = 2;
//   pb.val(r) = 4;
//   pb.val(x) = 0;
//   pb.val(y) = 1;
//   pb.val(z) = 2;
//   gadget.generate_r1cs_witness();
//   CHECK(pb.is_satisfied(), "");
//   CHECK(pb.val(gadget.ret()).getInt64() == 0, "");

//   pb.val(b) = 2;
//   gadget.generate_r1cs_witness();
//   CHECK(pb.is_satisfied(), "");
//   CHECK(pb.val(gadget.ret()).getInt64() == 1, "");

//   pb.val(b) = 3;
//   gadget.generate_r1cs_witness();
//   CHECK(pb.is_satisfied(), "");
//   CHECK(pb.val(gadget.ret()).getInt64() == 1, "");

//   pb.val(b) = 4;
//   gadget.generate_r1cs_witness();
//   CHECK(pb.is_satisfied(), "");
//   CHECK(pb.val(gadget.ret()).getInt64() == 1, "");

//   pb.val(b) = 5;
//   gadget.generate_r1cs_witness();
//   CHECK(pb.is_satisfied(), "");
//   CHECK(pb.val(gadget.ret()).getInt64() == 2, "");

//   std::cout << Tick::GetIndentString()
//             << "num_constraints: " << pb.num_constraints() << "\n";
//   std::cout << Tick::GetIndentString()
//             << "num_variables: " << pb.num_variables() << "\n";

//   return true;
// }

inline bool TestSelectGadget() {
  Tick tick(__FN__);
 
  libsnark::protoboard<Fr> pb;
  libsnark::pb_variable<Fr> b, x, y;
  b.allocate(pb, "b");
  x.allocate(pb, "x");
  y.allocate(pb, "y");
  /**
   * 这里需要改为pb_linea
   */
  select_gadget gadget(pb, b, x, y, "select");
  for(size_t i=0; i<2; i++){
      pb.val(b) = i;
      pb.val(x) = 2;
      pb.val(y) = 3;
      gadget.generate_r1cs_witness();
      CHECK(pb.val(gadget.ret()).getInt64() ==  (i == 0 ? 3 : 2), "");
  }

  std::cout << Tick::GetIndentString()
            << "num_constraints: " << pb.num_constraints() << "\n";
  std::cout << Tick::GetIndentString()
            << "num_variables: " << pb.num_variables() << "\n";

  CHECK(pb.is_satisfied(), "");
  return true;
}
}  // namespace circuit::fixed_point
