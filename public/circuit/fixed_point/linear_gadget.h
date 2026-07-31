#pragma once

#include "./fixed_point.h"
#include "parallel/parallel.h"

namespace circuit::fixed_point {

/**
 * LinearGadget: implements a fully-connected (linear) layer as R1CS constraints.
 *
 * Computes: output[j] = sum_i(input[i] * weight[i][j]) + bias[j]
 *         = <input, weight[:,j]> + bias[j]
 *
 * Template parameters:
 *   D, N: fixed-point precision (D=integer bits, N=fractional bits)
 *   WithRelu: whether to apply ReLU activation after the linear transformation
 *
 * IMPORTANT: Both weights and inputs are passed as variables (witness variables),
 * NOT as constants. This ensures all model parameters are part of the secret witness.
 *
 * Input can be either:
 *   - pb_variable_array<Fr> (allocated variables)
 *   - linear_combination_array<Fr> (e.g., output from previous layer)
 * This allows direct layer chaining without bridge variables.
 *
 * Constraints are generated in the constructor.
 */
template <size_t D, size_t N, bool WithRelu = false>
class LinearGadget : public libsnark::gadget<Fr> {
  static_assert(2 * D + 2 * N < 253, "invalid D,N");
  using RC = RationalConst<D, N>;

 public:
  /**
   * Constructor for LinearGadget with pb_variable_array input.
   */
  LinearGadget(libsnark::protoboard<Fr>& pb,
               size_t in_size, size_t out_size,
               libsnark::pb_variable_array<Fr> const& weight_vars,
               libsnark::pb_variable_array<Fr> const& input_vars,
               const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        in_size_(in_size), out_size_(out_size),
        weight_vars_(weight_vars) {
    
    assert(weight_vars.size() == out_size * (in_size + 1));
    assert(input_vars.size() == in_size);

    // Convert pb_variable_array to linear_combination_array
    for (size_t i = 0; i < in_size; ++i) {
      input_lc_.emplace_back(input_vars[i]);
    }

    init(annotation_prefix);
  }

  /**
   * Constructor for LinearGadget with linear_combination_array input.
   * This allows direct chaining from previous layer's output.
   */
  LinearGadget(libsnark::protoboard<Fr>& pb,
               size_t in_size, size_t out_size,
               libsnark::pb_variable_array<Fr> const& weight_vars,
               libsnark::linear_combination_array<Fr> const& input_lc,
               const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        in_size_(in_size), out_size_(out_size),
        weight_vars_(weight_vars),
        input_lc_(input_lc) {
    
    assert(weight_vars.size() == out_size * (in_size + 1));
    assert(input_lc.size() == in_size);

    init(annotation_prefix);
  }

  void generate_r1cs_witness() {
    RC rc;
    
    // Pre-compute all input and weight values
    auto const& assignment = this->pb.full_variable_assignment_ref();
    std::vector<Fr> input_vals(in_size_);
    std::vector<Fr> weight_vals(weight_vars_.size());
    
    for (size_t i = 0; i < in_size_; ++i) {
      input_vals[i] = input_lc_[i].evaluate(assignment);
    }
    for (size_t i = 0; i < weight_vars_.size(); ++i) {
      weight_vals[i] = this->pb.val(weight_vars_[i]);
    }

    // Parallel compute all output values and products
    size_t total_products = out_size_ * in_size_;
    std::vector<Fr> product_vals(total_products);
    std::vector<Fr> linear_output_vals(out_size_);

    auto compute_output = [this, &input_vals, &weight_vals, &linear_output_vals, &product_vals, &rc](size_t j) {
      Fr sum = Fr(0);
      size_t product_base = j * in_size_;
      size_t weight_base = j * (in_size_ + 1);
      
      for (size_t i = 0; i < in_size_; ++i) {
        Fr product = weight_vals[weight_base + i] * input_vals[i];
        product_vals[product_base + i] = product;
        sum = sum + product;
      }

      sum = sum + weight_vals[weight_base + in_size_] * rc.kFrN;
      linear_output_vals[j] = sum;
    };

    parallel::For(out_size_, compute_output);

    // Write back to protoboard
    for (size_t i = 0; i < total_products; ++i) {
      this->pb.val(all_products_[i]) = product_vals[i];
    }
    for (size_t j = 0; j < out_size_; ++j) {
      this->pb.val(linear_out_vars_[j]) = linear_output_vals[j];
    }

    // If WithRelu, generate ReLU witnesses
    if constexpr (WithRelu) {
      for (size_t j = 0; j < out_size_; ++j) {
        relu_gadgets_[j]->generate_r1cs_witness();
      }
    }
  }

  size_t in_size() const { return in_size_; }
  size_t out_size() const { return out_size_; }
  
  /**
   * Get output variable at index j.
   * For WithRelu=true, returns ReLU output variable.
   * For WithRelu=false, returns linear output variable.
   */
  libsnark::pb_variable<Fr> out_var(size_t j) const {
    if constexpr (WithRelu) {
      return relu_gadgets_[j]->ret();
    } else {
      return linear_out_vars_[j];
    }
  }

  /**
   * Get output variables as a linear_combination_array.
   * This is suitable for feeding into the next layer.
   */
  libsnark::linear_combination_array<Fr> out_lc_array() const {
    libsnark::linear_combination_array<Fr> result;
    result.reserve(out_size_);
    for (size_t j = 0; j < out_size_; ++j) {
      if constexpr (WithRelu) {
        result.emplace_back(relu_gadgets_[j]->ret());
      } else {
        result.emplace_back(linear_out_vars_[j]);
      }
    }
    return result;
  }

  /**
   * Get linear output variables (before activation).
   * Useful for debugging or when you need the pre-activation values.
   */
  libsnark::pb_variable_array<Fr> const& linear_out_vars() const {
    return linear_out_vars_;
  }

  /**
   * Helper: Get the required size of weight_vars array.
   */
  static constexpr size_t weight_array_size(size_t in_size, size_t out_size) {
    return out_size * (in_size + 1);
  }

 private:
  void init(const std::string& annotation_prefix) {
    (void)annotation_prefix;
    RC rc;

    // Allocate output variables (linear output, before activation)
    linear_out_vars_.allocate(this->pb, out_size_, "");

    // Batch-allocate ALL product variables in one call
    all_products_.allocate(this->pb, out_size_ * in_size_, "");

    // Generate constraints for all output neurons
    for (size_t j = 0; j < out_size_; ++j) {
      size_t product_base = j * in_size_;
      size_t weight_base = j * (in_size_ + 1);

      // Multiplication constraints: product = weight * input
      for (size_t i = 0; i < in_size_; ++i) {
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<Fr>(
                weight_vars_[weight_base + i],
                input_lc_[i],
                all_products_[product_base + i]),
            "");
      }

      // Sum constraint: sum(products) + bias * kFrN = linear_output
      libsnark::linear_combination<Fr> sum_lc;
      sum_lc.terms.reserve(in_size_ + 1);
      for (size_t i = 0; i < in_size_; ++i) {
        sum_lc.add_term(all_products_[product_base + i]);
      }
      sum_lc.add_term(weight_vars_[weight_base + in_size_], rc.kFrN);

      this->pb.add_r1cs_constraint(
          libsnark::r1cs_constraint<Fr>(1, sum_lc, linear_out_vars_[j]),
          "");
    }

    // If WithRelu, create ReLU gadgets (they generate constraints in their constructors)
    if constexpr (WithRelu) {
      relu_gadgets_.reserve(out_size_);
      for (size_t j = 0; j < out_size_; ++j) {
        relu_gadgets_.emplace_back(new Relu2Gadget<D, 2 * N, N>(
            this->pb, linear_out_vars_[j], ""));
      }
    }
  }

 private:
  size_t in_size_;
  size_t out_size_;
  
  libsnark::pb_variable_array<Fr> const& weight_vars_;
  libsnark::linear_combination_array<Fr> input_lc_;

  // Linear output variables (before activation)
  libsnark::pb_variable_array<Fr> linear_out_vars_;
  
  // All product variables in a single flat array: [j * in_size + i]
  libsnark::pb_variable_array<Fr> all_products_;
  
  // ReLU gadgets (if WithRelu)
  std::vector<std::unique_ptr<Relu2Gadget<D, 2 * N, N>>> relu_gadgets_;
};

/**
 * LinearReluGadget: Linear layer with ReLU activation.
 * This is a convenience typedef for LinearGadget with WithRelu=true.
 */
template <size_t D, size_t N>
using LinearReluGadget = LinearGadget<D, N, true>;

}  // namespace circuit::fixed_point
