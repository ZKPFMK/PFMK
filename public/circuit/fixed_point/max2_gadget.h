#pragma once

#include "./max_gadget.h"
#include "./sign_gadget.h"

namespace circuit::fixed_point {

/***
 * Max2Gadget: Find argmax and output one-hot vector
 * 
 * Input: x[0], x[1], ..., x[n-1] (fixed-point values)
 * Output: bits[0..n-1] (one-hot vector, bits[max_idx] = 1, others = 0)
 * 
 * Constraints:
 * 1. bits[i] is binary (0 or 1)
 * 2. sum(bits[i]) = 1 (exactly one element is 1)
 * 3. <bits, x> = max (inner product equals maximum)
 * 4. max is indeed the maximum (verified by MaxGadget)
 * 
 */

template <size_t D, size_t N>
class Max2Gadget : public libsnark::gadget<Fr> {
  static_assert(D + N < 253, "invalid D,N");

 public:
  Max2Gadget(libsnark::protoboard<Fr>& pb,
            libsnark::linear_combination_array<Fr> const& x_lc,
            const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix), x_lc_(x_lc) {
    assert(x_lc.size() > 1);
    
    n_ = x_lc.size();
    
    // Allocate one-hot vector
    bits_.allocate(this->pb, n_, FMT(this->annotation_prefix, " bits"));
    
    // Allocate products for inner product
    prods_.allocate(this->pb, n_, FMT(this->annotation_prefix, " prod"));

    // MaxGadget to verify max is indeed maximum
    max_gadget_.reset(new MaxGadget<D, N>(
          this->pb, x_lc_, FMT(this->annotation_prefix, " max_gadget"))
    );

    // Add constraints in constructor
    generate_r1cs_constraints();
  }

  void generate_r1cs_constraints() {
    // First, MaxGadget constraints
    max_gadget_->generate_r1cs_constraints();

    // Constraint 1: bits[i] is binary: bits[i] * (1 - bits[i]) = 0
    for (size_t i = 0; i < n_; ++i) {
      this->pb.add_r1cs_constraint(
          libsnark::r1cs_constraint<Fr>(bits_[i], -bits_[i] + 1, Fr(0)),
          FMT(this->annotation_prefix, " bits[%zu] is binary", i)
      );
    }

    // Constraint 2: sum(bits[i]) = 1
    libsnark::linear_combination<Fr> sum_of_bits;
    for (size_t i = 0; i < n_; ++i) {
      sum_of_bits = sum_of_bits + bits_[i];
    }
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(sum_of_bits, Fr(1), Fr(1)),
        FMT(this->annotation_prefix, " sum(bits) = 1")
    );

    // Constraint 3: prods[i] = bits[i] * x[i]
    libsnark::linear_combination<Fr> sum_of_prod;
    for (size_t i = 0; i < n_; ++i) {
      sum_of_prod = sum_of_prod + prods_[i];
      this->pb.add_r1cs_constraint(
          libsnark::r1cs_constraint<Fr>(bits_[i], x_lc_[i], prods_[i]),
          FMT(this->annotation_prefix, " bits[%zu] * x[%zu] = prod[%zu]", i, i, i)
      );
    }

    // Constraint 4: sum(prods) = max (inner product equals max_gadget's result)
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(sum_of_prod, Fr(1), max_gadget_->ret()),
        FMT(this->annotation_prefix, " sum(prods) = max")
    );
  }

  void generate_r1cs_witness() {
    // Find max and max_idx
    size_t max_idx = 0;
    Fr max = x_lc_[0].evaluate(this->pb.full_variable_assignment_ref());
    for (size_t i = 1; i < n_; ++i) {
      Fr x = x_lc_[i].evaluate(this->pb.full_variable_assignment_ref());
      Fr diff = max - x;
      if (diff.isNegative()) {
        max = x;
        max_idx = i;
      }
    }

    // Set one-hot vector
    for (size_t i = 0; i < n_; ++i) {
      this->pb.val(bits_[i]) = (i == max_idx) ? Fr(1) : Fr(0);
      this->pb.val(prods_[i]) = (i == max_idx) ? max : Fr(0);
    }

    // Generate MaxGadget witness
    max_gadget_->generate_r1cs_witness();
  }

  // Return one-hot vector
  libsnark::pb_variable_array<Fr> const& ret_array() const { return bits_; }
  
  // Return max value (from MaxGadget)
  libsnark::pb_variable<Fr> max_val() const { return max_gadget_->ret(); }

  static bool Test(std::vector<Fr> const& x, Fr max, int64_t max_idx) {
    libsnark::protoboard<Fr> pb;
    libsnark::pb_variable_array<Fr> pb_x;
    pb_x.allocate(pb, x.size(), "Test x");

    Max2Gadget<D, N> gadget(pb, pb_x, "Max2Gadget");

    std::cout << Tick::GetIndentString()
              << "num_constraints: " << pb.num_constraints()
              << ", num_variables: " << pb.num_variables() << "\n";

    for (size_t i = 0; i < x.size(); ++i) {
      pb.val(pb_x[i]) = x[i];
    }

    gadget.generate_r1cs_witness();
    
    // Check one-hot is correct
    bool onehot_correct = true;
    for (size_t i = 0; i < x.size(); ++i) {
      int64_t expected = (i == (size_t)max_idx) ? 1 : 0;
      int64_t actual = pb.val(gadget.ret_array()[i]).getInt64();
      if (actual != expected) {
        onehot_correct = false;
        break;
      }
    }
    
    return pb.is_satisfied() && onehot_correct && 
           pb.val(gadget.max_val()) == max;
  }

 private:
  std::unique_ptr<MaxGadget<D, N>> max_gadget_;

  libsnark::linear_combination_array<Fr> x_lc_;
  libsnark::pb_variable_array<Fr> bits_;
  libsnark::pb_variable_array<Fr> prods_;
  size_t n_;
};

}  // namespace circuit::fixed_point
