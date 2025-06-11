#pragma once

#include "./misc.h"

namespace circuit::fixed_point {

// insure x >=-kFrDN && x < kFrDN, that is [-2^(D+N), 2^(D+N)-1]
// assert(xi == 0 || xi == kFrN)
// assert(\sum i * xi == x_packed)
// num_constraints:
// num_variables:

template <size_t D, size_t N>
class OnehotGadget : public libsnark::gadget<Fr> {
  static_assert(D + N < 253, "invalid D,N");

 public:
  OnehotGadget(libsnark::protoboard<Fr>& pb,
            libsnark::pb_linear_combination_array<Fr> const& x_lc,
            libsnark::pb_linear_combination<Fr> const& x_lc_packed,
            const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        x_lc(x_lc), x_lc_packed(x_lc_packed) {
    assert(x_lc.size() > 1);
  }

  void generate_r1cs_constraints(const bool enforce_bitness) {
    RationalConst<D, N> rationalConst;

    libsnark::linear_combination<Fr> sum;
    libsnark::linear_combination<Fr> sum_packed;

    if(enforce_bitness){
      for (size_t i = 0; i < x_lc.size(); ++i) {
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<Fr>(x_lc[i], x_lc[i] - rationalConst.kFrN, 0),
            " x[i] * (1 - x[i]) == 0"
        );
      }
    }

    for (size_t i = 0; i < x_lc.size(); ++i) {
      sum = sum + x_lc[i];
      sum_packed = sum_packed + x_lc[i] * i;
    }
  
    libsnark::pb_linear_combination<Fr> lc_sum;
    libsnark::pb_linear_combination<Fr> lc_sum_packed;
    lc_sum.assign(this->pb, sum);
    lc_sum_packed.assign(this->pb, sum_packed);

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(lc_sum - rationalConst.kFrN, Fr(1), Fr(0)),
        FMT(this->annotation_prefix, " sum_of_x = 1")
    );

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(lc_sum_packed - x_lc_packed, Fr(1), Fr(0)),
        FMT(this->annotation_prefix, " sum_of_x_packed = packed")
    );
  }

  void generate_r1cs_witness_from_bits() {
    Fr packed = 0;
    for (size_t i = 0; i < x_lc.size(); ++i) {
      x_lc[i].evaluate(this->pb);
      packed = packed + this->pb.lc_val(x_lc[i]) * i;
    }
    this->pb.lc_val(x_lc_packed) = packed;
  }

  void generate_r1cs_witness_from_packed() {
    RationalConst<D, N> rationalConst;

    x_lc_packed.evaluate(this->pb);
    int idx = (this->pb.lc_val(x_lc_packed) / rationalConst.kFrN).getInt64();

    assert(idx < x_lc.size());

    for (size_t i = 0; i < x_lc.size(); ++i) {
      this->pb.lc_val(x_lc[i]) = 0;
    }
    this->pb.lc_val(x_lc[idx]) = rationalConst.kFrN;
  }

  static bool Test1(std::vector<Fr> const& x, Fr const& packed_x) {
    libsnark::protoboard<Fr> pb;
    libsnark::pb_variable_array<Fr> pb_x;
    libsnark::pb_variable<Fr> pb_x_packed;

    pb_x.allocate(pb, x.size(), "Test x");
    pb_x_packed.allocate(pb, "Test x_packed");

    OnehotGadget<D, N> gadget(pb, pb_x, pb_x_packed, "OnehotGadget");

    gadget.generate_r1cs_constraints(true);

    std::cout << Tick::GetIndentString()
              << "num_constraints: " << pb.num_constraints()
              << ", num_variables: " << pb.num_variables() << "\n";

    for (size_t i = 0; i < x.size(); ++i) {
      pb.val(pb_x[i]) = x[i];
    }
    gadget.generate_r1cs_witness_from_bits();

    return pb.is_satisfied() && pb.val(pb_x_packed) == packed_x;
  }

  static bool Test2(std::vector<Fr> const& x, Fr const& packed_x) {
    libsnark::protoboard<Fr> pb;
    libsnark::pb_variable_array<Fr> pb_x;
    libsnark::pb_variable<Fr> pb_x_packed;

    pb_x.allocate(pb, x.size(), "Test x");
    pb_x_packed.allocate(pb, "Test x_packed");

    OnehotGadget<D, N> gadget(pb, pb_x, pb_x_packed, "OnehotGadget");

    gadget.generate_r1cs_constraints(true);

    std::cout << Tick::GetIndentString()
              << "num_constraints: " << pb.num_constraints()
              << ", num_variables: " << pb.num_variables() << "\n";

    pb.val(pb_x_packed) = packed_x;

    gadget.generate_r1cs_witness_from_packed();

    bool ret = true;
    for(int i=0; i<x.size(); i++){
      ret = (ret && pb.val(pb_x[i]) == x[i]);
    }

    return pb.is_satisfied() && ret;
  }


 private:
  libsnark::pb_linear_combination_array<Fr> x_lc;
  libsnark::pb_linear_combination<Fr> x_lc_packed;
};

inline bool OnehotTest() {
  Tick tick(__FN__);
  constexpr size_t D = 8;
  constexpr size_t N = 24;
  std::vector<Fr> x;
  std::vector<bool> rets;

  RationalConst<D, N> rationalConst;

  rets.push_back(OnehotGadget<D, N>::Test2({0, 0, 0, rationalConst.kFrN}, 3 * rationalConst.kFrN));
  rets.push_back(OnehotGadget<D, N>::Test2({0, 0, rationalConst.kFrN, 0}, 2 * rationalConst.kFrN));
  rets.push_back(OnehotGadget<D, N>::Test2({0, rationalConst.kFrN, 0, 0}, 1 * rationalConst.kFrN));
  rets.push_back(OnehotGadget<D, N>::Test2({rationalConst.kFrN, 0, 0, 0}, 0 * rationalConst.kFrN));
  // rets.push_back(OnehotGadget<D, N>::Test({0, 0, 0, 0}, 0));

  std::cout << "\n\nret:" << std::all_of(rets.begin(), rets.end(), [](auto i) { return i; }) << "*****\n\n";
  return std::all_of(rets.begin(), rets.end(), [](auto i) { return i; });
}
}  // namespace circuit::fixed_point