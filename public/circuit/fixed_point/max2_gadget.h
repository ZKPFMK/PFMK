#pragma once

#include "./max_gadget.h"
#include "./onehot_gadget.h"

namespace circuit::fixed_point {


/***
 * insure x >=-kFrDN && x < kFrDN, that is [-2^(D+N), 2^(D+N)-1]
 * mx = max(x1, x2, x3, x4), ret = idx(mx)
 * 最大值的索引可以使用一个one-hot向量表示: a0, \cdots, a4, 也可以用一个整数表示: a
 * mx = \sum ai * xi
 * 
 */

template <size_t D, size_t N>
class Max2Gadget : public libsnark::gadget<Fr> {
  static_assert(D + N < 253, "invalid D,N");

 public:
  Max2Gadget(libsnark::protoboard<Fr>& pb,
            libsnark::pb_linear_combination_array<Fr> const& x_lc,
            const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix), x_lc(x_lc){
    assert(x_lc.size() > 1);
    ret_.allocate(this->pb, " ret");
    bits_.allocate(this->pb, x_lc.size(), " bits");
    prods_.allocate(this->pb, x_lc.size(), " prod");

    max_gadget_.reset(new MaxGadget<D, N>(
          this->pb, x_lc, FMT(this->annotation_prefix, " max_gadget"))
    );

    onehot_gadget_.reset(new OnehotGadget<D, 0>(
          this->pb, bits_, ret_, FMT(this->annotation_prefix, " onehot_gadget"))
    );
  }

  Max2Gadget(libsnark::protoboard<Fr>& pb, size_t n,
            const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix){
    assert(n > 1);

    x_.allocate(this->pb, n, " x_");
    
    ret_.allocate(this->pb, " ret");
    bits_.allocate(this->pb, x_.size(), " bits");
    prods_.allocate(this->pb, x_.size(), " prod");

    x_lc = x_;

    max_gadget_.reset(new MaxGadget<D, N>(
          this->pb, x_lc, FMT(this->annotation_prefix, " max_gadget"))
    );

    onehot_gadget_.reset(new OnehotGadget<D, 0>(
          this->pb, bits_, ret_, FMT(this->annotation_prefix, " onehot_gadget"))
    );

    generate_r1cs_constraints();
  }

  void Assign(std::vector<Fr> const& x) {
    assert(x.size() == x_.size());
    for(int i=0; i<x_.size(); i++){
      this->pb.val(x_[i]) = x[i];
    }
    generate_r1cs_witness();
  }

  void generate_r1cs_constraints() {
    max_gadget_->generate_r1cs_constraints();
    onehot_gadget_->generate_r1cs_constraints(true);

    libsnark::linear_combination<Fr> sum_of_prod;
    for (size_t i = 0; i < x_lc.size(); ++i) {
      sum_of_prod = sum_of_prod + prods_[i];
      this->pb.add_r1cs_constraint(
          libsnark::r1cs_constraint<Fr>(bits_[i], x_lc[i], prods_[i]),
          " bits[i] * x[i] == prod[i]"
      );
    }

    libsnark::pb_linear_combination<Fr> lc_sum_of_prod;
    lc_sum_of_prod.assign(this->pb, sum_of_prod);

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(lc_sum_of_prod - (max_gadget_->ret()), Fr(1), Fr(0)),
        FMT(this->annotation_prefix, " sum_of_prod = max")
    );
  }

  void generate_r1cs_witness() {
    max_gadget_->generate_r1cs_witness();

    for (size_t i = 0; i < x_lc.size(); ++i) {
      x_lc[i].evaluate(this->pb);
      this->pb.val(prods_[i]) = 0;
    }
 
    size_t max_idx = 0;
    Fr max = this->pb.lc_val(x_lc[0]);
    for (size_t i = 1; i < x_lc.size(); ++i) {
      Fr x = this->pb.lc_val(x_lc[i]);
      Fr diff = max - x;
      if (diff.isNegative()) {
        max = x;
        max_idx = i;
      }
    }
    this->pb.val(ret_) = max_idx;
    this->pb.val(prods_[max_idx]) = max;

    onehot_gadget_->generate_r1cs_witness_from_packed();
  }

  libsnark::pb_variable<Fr> ret() const { return ret_; }

  libsnark::pb_variable<Fr> oh() const { return bits_[0]; }

  static bool Test1(std::vector<Fr> const& x, Fr max, int64_t max_idx) {
    libsnark::protoboard<Fr> pb;
    libsnark::pb_variable_array<Fr> pb_x;
    pb_x.allocate(pb, x.size(), "Test x");

    Max2Gadget<D, N> gadget(pb, pb_x, "Max2Gadget");

    gadget.generate_r1cs_constraints();

    std::cout << Tick::GetIndentString()
              << "num_constraints: " << pb.num_constraints()
              << ", num_variables: " << pb.num_variables() << "\n";

    for (size_t i = 0; i < x.size(); ++i) {
      pb.val(pb_x[i]) = x[i];
    }

    gadget.generate_r1cs_witness();
    return pb.is_satisfied() && x[pb.val(gadget.ret()).getInt64()] == max;
  }

  static bool Test2(std::vector<Fr> const& x, Fr max, int64_t max_idx) {
    libsnark::protoboard<Fr> pb;
    Max2Gadget<D, N> gadget(pb, x.size(), "Max2Gadget");
    std::cout << "max ret:" << gadget.ret().index << "\n";
    std::cout << Tick::GetIndentString()
              << "num_constraints: " << pb.num_constraints()
              << ", num_variables: " << pb.num_variables() << "\n";

    gadget.Assign(x);
    return pb.is_satisfied() && x[pb.val(gadget.ret()).getInt64()] == max;
  }

 private:
  std::unique_ptr<MaxGadget<D, N>> max_gadget_;
  std::unique_ptr<OnehotGadget<D, 0>> onehot_gadget_;

  libsnark::pb_linear_combination_array<Fr> x_lc;

  libsnark::pb_variable_array<Fr> prods_;
  libsnark::pb_variable_array<Fr> bits_;
  libsnark::pb_variable_array<Fr> x_;
  libsnark::pb_variable<Fr> ret_;
};

inline bool TestMax2() {
  Tick tick(__FN__);
  constexpr size_t D = 8;
  constexpr size_t N = 24;
  std::vector<Fr> x;
  std::vector<bool> rets;

  rets.push_back(Max2Gadget<D, N>::Test1({1001234, 0, -11, 2445}, 1001234, 0));
  rets.push_back(Max2Gadget<D, N>::Test1({1, 3, -11}, 3, 1));
  rets.push_back(Max2Gadget<D, N>::Test1({-32, -1, 31}, 31, 2));
  rets.push_back(Max2Gadget<D, N>::Test1({-32, 31, -1, 49}, 49, 3));

  rets.push_back(Max2Gadget<D, N>::Test2({1001234, 0, -11, 2445}, 1001234, 0));
  rets.push_back(Max2Gadget<D, N>::Test2({1, 3, -11}, 3, 1));
  rets.push_back(Max2Gadget<D, N>::Test2({-32, -1, 31}, 31, 2));
  rets.push_back(Max2Gadget<D, N>::Test2({-32, 31, -1, 49}, 49, 3));
  std::cout << "\n\nret:" << std::all_of(rets.begin(), rets.end(), [](auto i) { return i; }) << "*****\n\n";
  return std::all_of(rets.begin(), rets.end(), [](auto i) { return i; });
}
}  // namespace circuit::fixed_point