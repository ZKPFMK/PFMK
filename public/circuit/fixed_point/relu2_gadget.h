#pragma once

#include "./precision_gadget.h"

namespace circuit::fixed_point {

// NOTE the template M
// insure a >=-kFrDN && a < kFrDN, that is [-2^(D+N), 2^(D+N)-1]
// ret = a >= 0? a : 0
// num_constraints:
// num_variables:

template <size_t D, size_t N, size_t M> //D=6, N=48, M=24
class Relu2Gadget : public libsnark::gadget<Fr> {
  static_assert(D + N < 253, "invalid D,N");
  static_assert(N > M, "invalid N or M");

  public:
  // Constructor that allocates internal input variable a_ (standalone mode)
  Relu2Gadget(libsnark::protoboard<Fr>& pb,
              const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix), a_is_external_(false) {
    a_.allocate(this->pb, FMT(this->annotation_prefix, " a"));
    ret_.allocate(pb, FMT(this->annotation_prefix, " ret"));
    precision_gadget_.reset(new PrecisionGadget<D, N, M>(
        this->pb, a_, FMT(this->annotation_prefix, " precision_gadget")));
    generate_r1cs_constraints();
  }

  // Constructor that accepts external input variable (chained mode)
  // Use this when chaining with previous gadget to ensure variable identity
  Relu2Gadget(libsnark::protoboard<Fr>& pb,
              libsnark::pb_variable<Fr> const& a_external,
              const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        a_(a_external),
        a_is_external_(true) {
    ret_.allocate(pb, FMT(this->annotation_prefix, " ret"));
    precision_gadget_.reset(new PrecisionGadget<D, N, M>(
        this->pb, a_, FMT(this->annotation_prefix, " precision_gadget")));
    generate_r1cs_constraints();
  }

  // Constructor that accepts external input as linear_combination
  // For compatibility with IpGadget::ret() which returns linear_combination
  Relu2Gadget(libsnark::protoboard<Fr>& pb,
              libsnark::linear_combination<Fr> const& a_external_lc,
              const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        a_is_external_(true) {
    // Allocate a_ and add constraint: a_ = a_external_lc
    a_.allocate(this->pb, FMT(this->annotation_prefix, " a"));
    ret_.allocate(pb, FMT(this->annotation_prefix, " ret"));
    
    // Add constraint to link external LC to internal a_
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(a_external_lc, 1, a_),
        FMT(this->annotation_prefix, " a = external_lc"));
    
    precision_gadget_.reset(new PrecisionGadget<D, N, M>(
        this->pb, a_, FMT(this->annotation_prefix, " precision_gadget")));
    generate_r1cs_constraints();
  }

  void Assign(Fr const& a) {
    this->pb.val(a_) = a;
    generate_r1cs_witness();
  }

  libsnark::pb_variable<Fr> ret() const { return ret_; }

  void generate_r1cs_witness() {
    precision_gadget_->generate_r1cs_witness();

    // auto a = a_.evaluate(this->pb.full_variable_assignment_ref());
    auto b = precision_gadget_->ret().evaluate(this->pb.full_variable_assignment_ref());
    auto sign = precision_gadget_->sign().evaluate(this->pb.full_variable_assignment_ref());
    this->pb.val(ret_) = sign == Fr(0) ? Fr(0) : b;
  }

 private:
  void generate_r1cs_constraints() {
    precision_gadget_->generate_r1cs_constraints();

    // ret = sign_*b
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(precision_gadget_->ret(),
                                      precision_gadget_->sign(), ret_),
        FMT(this->annotation_prefix, " ret = sign? b:0"));
  }

 public:
  static bool Test(double const& dx) {
    Fr x = DoubleToRational<D, N>(dx);
    std::unique_ptr<Relu2Gadget<D, N, M>> gadget;
    libsnark::protoboard<Fr> pb;
    gadget = std::make_unique<Relu2Gadget<D, N, M>>(pb, "Relu2Gadget");
    gadget->Assign(x);
    CHECK(pb.is_satisfied(), "");
    std::cout << Tick::GetIndentString()
              << "num_constraints: " << pb.num_constraints()
              << ", num_variables: " << pb.num_variables() << "\n";
#ifdef _DEBUG
    double dr = RationalToDouble<D, M>(pb.val(gadget->ret()));
    if (dx < 0) {
      CHECK(dr == 0, "");
    } else {
      CHECK(std::abs(dx - dr) < 0.001, "");
    }
#endif
    return pb.is_satisfied();
  }

 private:
  libsnark::pb_variable<Fr> a_;
  bool a_is_external_;
  std::unique_ptr<PrecisionGadget<D, N, M>> precision_gadget_;
  libsnark::pb_variable<Fr> ret_;
};

inline bool TestRelu2() {
  Tick tick(__FN__);
  constexpr size_t D = 8;
  constexpr size_t N = 48;
  constexpr size_t M = 24;
  std::vector<bool> rets;
  rets.push_back(Relu2Gadget<D, N, M>::Test(3.124));
  rets.push_back(Relu2Gadget<D, N, M>::Test(-22.212));
  rets.push_back(Relu2Gadget<D, N, M>::Test(0.00123));
  rets.push_back(Relu2Gadget<D, N, M>::Test(-0.00123));
  rets.push_back(Relu2Gadget<D, N, M>::Test(34.123));
  rets.push_back(Relu2Gadget<D, N, M>::Test(-23.11224));
  return std::all_of(rets.begin(), rets.end(), [](auto i) { return i; });
}
}  // namespace circuit::fixed_point
