#pragma once

#include "./sign_gadget.h"

namespace circuit::fixed_point {

// insure a >=-kFrDN && a < kFrDN, that is [-2^(D+N), 2^(D+N)-1]
// ret = a >= 0? a : 0
// num_constraints:
// num_variables:

template <size_t D, size_t N>
class ReluGadget : public libsnark::gadget<Fr> {
  static_assert(D + N < 253, "invalid D,N");

 public:
  ReluGadget(libsnark::protoboard<Fr>& pb,
             libsnark::linear_combination<Fr> const& a,
             libsnark::linear_combination<Fr> const* sign = nullptr,
             const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix), a_(a) {
    if (sign) {
      sign_ = *sign;
    } else {
      sign_gadget_.reset(new SignGadget<D, N>(
          this->pb, a_, FMT(this->annotation_prefix, " sign_gadget")));
      sign_ = sign_gadget_->ret();
    }
    ret_.allocate(pb, FMT(this->annotation_prefix, " ret"));
  }

  void generate_r1cs_constraints() {
    if (sign_gadget_) {
      sign_gadget_->generate_r1cs_constraints();
    }
    // ret = sign_*a
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(a_, sign_, ret_),
        FMT(this->annotation_prefix, " ret = sign? a:0"));
  }

  void generate_r1cs_witness() {
    if (sign_gadget_) {
      sign_gadget_->generate_r1cs_witness();
    }

    auto a = a_.evaluate(this->pb.full_variable_assignment_ref());
    auto sign = sign_.evaluate(this->pb.full_variable_assignment_ref());
    assert(sign == (a.isNegative() ? Fr(0) : Fr(1)));
    this->pb.val(ret_) = sign == Fr(0) ? Fr(0) : a;
  }

  libsnark::pb_variable<Fr> ret() const { return ret_; }

  static bool Test(Fr const& x, bool set_sign) {
    std::unique_ptr<ReluGadget<D, N>> gadget;
    libsnark::protoboard<Fr> pb;
    libsnark::pb_variable<Fr> pb_x;
    pb_x.allocate(pb, "Test x");
    libsnark::pb_variable<Fr> pb_sign;
    libsnark::linear_combination<Fr> lc_sign;

    if (set_sign) {
      pb_sign.allocate(pb, "Test sign");
      lc_sign = pb_sign;
      gadget = std::make_unique<ReluGadget<D, N>>(pb, pb_x, &lc_sign,
                                                  "ReluGadget");
    } else {
      gadget =
          std::make_unique<ReluGadget<D, N>>(pb, pb_x, nullptr, "ReluGadget");
    }

    gadget->generate_r1cs_constraints();
    pb.val(pb_x) = x;
    if (set_sign) {
      pb.val(pb_sign) = x.isNegative() ? 0 : 1;
    }

    gadget->generate_r1cs_witness();
    assert(pb.is_satisfied());
    return pb.is_satisfied();
  }

 private:
  libsnark::linear_combination<Fr> a_;
  std::unique_ptr<SignGadget<D, N>> sign_gadget_;
  libsnark::linear_combination<Fr> sign_;
  libsnark::pb_variable<Fr> ret_;
};

inline bool TestRelu() {
  Tick tick(__FN__);
  constexpr size_t D = 8;
  constexpr size_t N = 2;
  std::vector<bool> rets;
  rets.push_back(ReluGadget<D, N>::Test(Fr(100), true));
  rets.push_back(ReluGadget<D, N>::Test(Fr(0), true));
  rets.push_back(ReluGadget<D, N>::Test(Fr(-1), false));
  rets.push_back(ReluGadget<D, N>::Test(Fr(-100), false));
  rets.push_back(ReluGadget<D, N>::Test(Fr(-1024), true));
  rets.push_back(ReluGadget<D, N>::Test(Fr(-1024), false));
  return std::all_of(rets.begin(), rets.end(), [](auto i) { return i; });
}
}  // namespace circuit::fixed_point
