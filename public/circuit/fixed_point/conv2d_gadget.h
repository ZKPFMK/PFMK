#pragma once

#include "./fixed_point.h"
#include "parallel/parallel.h"

namespace circuit::fixed_point {

/**
 * Conv2dGadget: implements a 2D convolution layer as R1CS constraints.
 *
 * Conv2d(in_channels, out_channels, kernel_size, stride, padding=0)
 *
 * For each output pixel (oc, oh, ow):
 *   out[oc][oh][ow] = sum_{ic, kh, kw} weight[oc][ic][kh][kw] * in[ic][ih+kh][iw+kw] + bias[oc]
 *
 * where ih = oh * stride, iw = ow * stride.
 *
 * Template parameters:
 *   D, N: fixed-point precision (D=integer bits, N=fractional bits)
 *
 * IMPORTANT: Both weights and inputs are passed as pb_variable_array (witness variables),
 * NOT as constants. This ensures all model parameters are part of the secret witness
 * and each weight*input multiplication generates an R1CS constraint.
 *
 * Constraints are generated in the constructor.
 */
template <size_t D, size_t N>
class Conv2dGadget : public libsnark::gadget<Fr> {
  using RC = fixed_point::RationalConst<D, N>;
 public:
  /**
   * @param in_c       Number of input channels
   * @param in_h       Input height
   * @param in_w       Input width
   * @param out_c      Number of output channels (filters)
   * @param kernel_h   Kernel height
   * @param kernel_w   Kernel width
   * @param stride_h   Stride height
   * @param stride_w   Stride in width dimension
   * @param weight_vars Flat weight variables array:
   *                    [out_c * (in_c * kernel_h * kernel_w + 1)]
   *                    For each output channel: [in_c * kernel_h * kernel_w weights, 1 bias]
   *                    Indexed as: weight_vars[oc * (kernel_size + 1) + idx]
   * @param input_vars Flat input variables array,
   *                    indexed as [ic * in_h * in_w + ih * in_w + iw]
   */
  Conv2dGadget(libsnark::protoboard<Fr>& pb,
               size_t in_c, size_t in_h, size_t in_w,
               size_t out_c, size_t kernel_h, size_t kernel_w,
               size_t stride_h, size_t stride_w,
               libsnark::pb_variable_array<Fr> const& weight_vars,
               libsnark::pb_variable_array<Fr> const& input_vars,
               const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        in_c_(in_c), in_h_(in_h), in_w_(in_w),
        out_c_(out_c), kernel_h_(kernel_h), kernel_w_(kernel_w),
        stride_h_(stride_h), stride_w_(stride_w),
        weight_vars_(weight_vars) {
    
    // Convert pb_variable_array to linear_combination_array
    for (size_t i = 0; i < input_vars.size(); ++i) {
      input_lc_.emplace_back(input_vars[i]);
    }

    init(annotation_prefix);
  }

  /**
   * Constructor with linear_combination_array input.
   * This allows direct chaining from previous layer's output (e.g., ReLU output).
   */
  Conv2dGadget(libsnark::protoboard<Fr>& pb,
               size_t in_c, size_t in_h, size_t in_w,
               size_t out_c, size_t kernel_h, size_t kernel_w,
               size_t stride_h, size_t stride_w,
               libsnark::pb_variable_array<Fr> const& weight_vars,
               libsnark::linear_combination_array<Fr> const& input_lc,
               const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        in_c_(in_c), in_h_(in_h), in_w_(in_w),
        out_c_(out_c), kernel_h_(kernel_h), kernel_w_(kernel_w),
        stride_h_(stride_h), stride_w_(stride_w),
        weight_vars_(weight_vars),
        input_lc_(input_lc) {
    
    init(annotation_prefix);
  }

  void generate_r1cs_witness() {
    size_t total_outputs = out_c_ * out_h_ * out_w_;
    RC rc;

    // Pre-compute all input and weight values (thread-safe reads)
    auto const& assignment = this->pb.full_variable_assignment_ref();
    std::vector<Fr> input_vals(input_lc_.size());
    std::vector<Fr> weight_vals(weight_vars_.size());
    
    for (size_t i = 0; i < input_lc_.size(); ++i) {
      input_vals[i] = input_lc_[i].evaluate(assignment);
    }
    for (size_t i = 0; i < weight_vars_.size(); ++i) {
      weight_vals[i] = this->pb.val(weight_vars_[i]);
    }

    // Parallel compute all output values and products
    size_t total_products = total_outputs * kernel_size_;
    std::vector<Fr> product_vals(total_products);
    std::vector<Fr> output_vals(total_outputs);

    auto compute_output = [this, &input_vals, &weight_vals, &output_vals, &product_vals, &rc](size_t out_idx) {
      Fr sum = Fr(0);
      size_t product_base = out_idx * kernel_size_;
      size_t base_weight_idx = weight_base_indices_[out_idx];
      
      for (size_t i = 0; i < kernel_size_; ++i) {
        Fr product = weight_vals[base_weight_idx + i] * input_vals[patch_indices_[out_idx][i]];
        product_vals[product_base + i] = product;
        sum = sum + product;
      }

      sum = sum + weight_vals[base_weight_idx + kernel_size_] * rc.kFrN;
      output_vals[out_idx] = sum;
    };

    parallel::For(total_outputs, compute_output);

    // Write back to protoboard
    for (size_t i = 0; i < total_products; ++i) {
      this->pb.val(all_products_[i]) = product_vals[i];
    }
    for (size_t out_idx = 0; out_idx < total_outputs; ++out_idx) {
      this->pb.val(out_vars_[out_idx]) = output_vals[out_idx];
    }
  }

  size_t out_h() const { return out_h_; }
  size_t out_w() const { return out_w_; }
  size_t out_c() const { return out_c_; }
  size_t total_outputs() const { return out_c_ * out_h_ * out_w_; }
  size_t kernel_size() const { return kernel_size_; }

  libsnark::pb_variable_array<Fr> const& out_vars() const {
    return out_vars_;
  }

  /**
   * Build a linear_combination_array from the output variables,
   * suitable for feeding into the next layer.
   */
  libsnark::linear_combination_array<Fr> out_lc_array() const {
    libsnark::linear_combination_array<Fr> result(total_outputs());
    for (size_t i = 0; i < total_outputs(); ++i) {
      result[i] = libsnark::linear_combination<Fr>(out_vars_[i]);
    }
    return result;
  }

  /**
   * Helper: Get the required size of weight_vars array.
   */
  static constexpr size_t weight_array_size(size_t in_c, size_t kernel_h, 
                                             size_t kernel_w, size_t out_c) {
    return out_c * (in_c * kernel_h * kernel_w + 1);
  }

 private:
  void init(const std::string& annotation_prefix) {
    (void)annotation_prefix;
    out_h_ = (in_h_ - kernel_h_) / stride_h_ + 1;
    out_w_ = (in_w_ - kernel_w_) / stride_w_ + 1;
    kernel_size_ = in_c_ * kernel_h_ * kernel_w_;
    size_t total_outputs = out_c_ * out_h_ * out_w_;

    assert(weight_vars_.size() == out_c_ * (kernel_size_ + 1));
    assert(input_lc_.size() == in_c_ * in_h_ * in_w_);

    // Pre-allocate index vectors
    patch_indices_.resize(total_outputs);
    weight_base_indices_.resize(total_outputs);

    // Allocate all output variables at once
    out_vars_.allocate(this->pb, total_outputs, "");

    // Batch-allocate ALL product variables in one call instead of per-output
    all_products_.allocate(this->pb, total_outputs * kernel_size_, "");

    RC rc;

    // Pre-compute patch indices (no constraint generation yet)
    for (size_t oc = 0; oc < out_c_; ++oc) {
      size_t base_weight_idx = oc * (kernel_size_ + 1);
      for (size_t oh = 0; oh < out_h_; ++oh) {
        for (size_t ow = 0; ow < out_w_; ++ow) {
          size_t out_idx = oc * out_h_ * out_w_ + oh * out_w_ + ow;
          weight_base_indices_[out_idx] = base_weight_idx;

          auto& indices = patch_indices_[out_idx];
          indices.resize(kernel_size_);
          size_t k = 0;
          for (size_t ic = 0; ic < in_c_; ++ic) {
            for (size_t kh = 0; kh < kernel_h_; ++kh) {
              for (size_t kw = 0; kw < kernel_w_; ++kw) {
                size_t ih = oh * stride_h_ + kh;
                size_t iw = ow * stride_w_ + kw;
                indices[k++] = ic * in_h_ * in_w_ + ih * in_w_ + iw;
              }
            }
          }
        }
      }
    }

    // Generate all constraints
    for (size_t out_idx = 0; out_idx < total_outputs; ++out_idx) {
      size_t base_weight_idx = weight_base_indices_[out_idx];
      size_t product_base = out_idx * kernel_size_;

      // Multiplication constraints: product = weight * input
      for (size_t i = 0; i < kernel_size_; ++i) {
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<Fr>(
                weight_vars_[base_weight_idx + i],
                input_lc_[patch_indices_[out_idx][i]],
                all_products_[product_base + i]),
            "");
      }

      // Sum constraint: sum(products) + bias * kFrN = output
      libsnark::linear_combination<Fr> sum_lc;
      sum_lc.terms.reserve(kernel_size_ + 1);
      for (size_t i = 0; i < kernel_size_; ++i) {
        sum_lc.add_term(all_products_[product_base + i]);
      }
      sum_lc.add_term(weight_vars_[base_weight_idx + kernel_size_], rc.kFrN);

      this->pb.add_r1cs_constraint(
          libsnark::r1cs_constraint<Fr>(1, sum_lc, out_vars_[out_idx]),
          "");
    }
  }

  size_t in_c_, in_h_, in_w_;
  size_t out_c_, kernel_h_, kernel_w_;
  size_t stride_h_, stride_w_;
  size_t out_h_, out_w_;
  size_t kernel_size_;

  libsnark::pb_variable_array<Fr> const& weight_vars_;
  libsnark::linear_combination_array<Fr> input_lc_;

  libsnark::pb_variable_array<Fr> out_vars_;

  // All product variables in a single flat array: [out_idx * kernel_size + i]
  libsnark::pb_variable_array<Fr> all_products_;
  // For each output pixel: indices into input_lc_ for the patch
  std::vector<std::vector<size_t>> patch_indices_;
  // For each output pixel: base index into weight_vars_
  std::vector<size_t> weight_base_indices_;
};

}  // namespace circuit::fixed_point
