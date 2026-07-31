#pragma once

#include "circuit/fixed_point/fixed_point.h"
#include "circuit/fixed_point/linear_gadget.h"
#include "circuit/fixed_point/conv2d_gadget.h"
#include "circuit/fixed_point/max2_gadget.h"
#include "circuit/fixed_point/batch_relu2_gadget.h"
#include "log/tick.h"
#include "parallel/parallel.h"

namespace circuit::flappybird {

/**
 * DqnGadget: implements the CNN-based Deep Q-Network as R1CS constraints.
 *
 * CNN Architecture (matching deep_q_network.py):
 *   Conv1: Conv2d(4, 32, kernel=8, stride=4) -> ReLU  => (32, 20, 20)
 *   Conv2: Conv2d(32, 64, kernel=4, stride=2) -> ReLU => (64, 9, 9)
 *   Conv3: Conv2d(64, 64, kernel=3, stride=1) -> ReLU => (64, 7, 7)
 *   FC1:   Linear(3136, 512) -> ReLU
 *   FC2:   Linear(512, 2)
 *   Max:   argmax -> action one-hot [no_flap, flap]
 *
 * Template parameters:
 *   D, N: fixed-point precision (D=integer bits, N=fractional bits)
 *
 * IMPORTANT: All weights (conv and FC) are witness variables, NOT constants.
 * This ensures the model parameters are part of the secret witness.
 */
template <size_t D, size_t N>
class DqnGadget : public libsnark::gadget<Fr> {
  static constexpr size_t N2 = 2 * N;  // Double precision for intermediate results

  typedef fixed_point::BatchRelu2Gadget<D, N2, N> BatchRelu2Gadget;
  typedef fixed_point::Max2Gadget<D, N2> Max2Gadget;
  typedef fixed_point::LinearGadget<D, N, false> LinearGadgetNoRelu;
  typedef fixed_point::LinearReluGadget<D, N> LinearReluGadget;
  typedef fixed_point::Conv2dGadget<D, N> Conv2dGadget;

 public:
  // CNN dimensions (public for external allocation)
  static constexpr size_t IMG_C = 4;
  static constexpr size_t IMG_H = 84;
  static constexpr size_t IMG_W = 84;
  static constexpr size_t IMG_SIZE = IMG_C * IMG_H * IMG_W;  // 28224

  // Conv1: (4, 84, 84) -> (32, 20, 20)
  static constexpr size_t CONV1_OUT_C = 32;
  static constexpr size_t CONV1_K = 8;
  static constexpr size_t CONV1_S = 4;
  static constexpr size_t CONV1_OUT_H = (IMG_H - CONV1_K) / CONV1_S + 1;  // 20
  static constexpr size_t CONV1_OUT_W = (IMG_W - CONV1_K) / CONV1_S + 1;  // 20
  static constexpr size_t CONV1_OUT_SIZE = CONV1_OUT_C * CONV1_OUT_H * CONV1_OUT_W;  // 12800
  static constexpr size_t CONV1_WEIGHT_SIZE = CONV1_OUT_C * (IMG_C * CONV1_K * CONV1_K + 1);

  // Conv2: (32, 20, 20) -> (64, 9, 9)
  static constexpr size_t CONV2_OUT_C = 64;
  static constexpr size_t CONV2_K = 4;
  static constexpr size_t CONV2_S = 2;
  static constexpr size_t CONV2_OUT_H = (CONV1_OUT_H - CONV2_K) / CONV2_S + 1;  // 9
  static constexpr size_t CONV2_OUT_W = (CONV1_OUT_W - CONV2_K) / CONV2_S + 1;  // 9
  static constexpr size_t CONV2_OUT_SIZE = CONV2_OUT_C * CONV2_OUT_H * CONV2_OUT_W;  // 5184
  static constexpr size_t CONV2_WEIGHT_SIZE = CONV2_OUT_C * (CONV1_OUT_C * CONV2_K * CONV2_K + 1);

  // Conv3: (64, 9, 9) -> (64, 7, 7)
  static constexpr size_t CONV3_OUT_C = 64;
  static constexpr size_t CONV3_K = 3;
  static constexpr size_t CONV3_S = 1;
  static constexpr size_t CONV3_OUT_H = (CONV2_OUT_H - CONV3_K) / CONV3_S + 1;  // 7
  static constexpr size_t CONV3_OUT_W = (CONV2_OUT_W - CONV3_K) / CONV3_S + 1;  // 7
  static constexpr size_t CONV3_OUT_SIZE = CONV3_OUT_C * CONV3_OUT_H * CONV3_OUT_W;  // 3136
  static constexpr size_t CONV3_WEIGHT_SIZE = CONV3_OUT_C * (CONV2_OUT_C * CONV3_K * CONV3_K + 1);

  // FC1: 3136 -> 512
  static constexpr size_t FC1_IN = CONV3_OUT_SIZE;  // 3136
  static constexpr size_t FC1_OUT = 512;

  // FC2: 512 -> 2
  static constexpr size_t FC2_IN = FC1_OUT;
  static constexpr size_t FC2_OUT = 2;
  /**
   * Constructor with pb_variable_array input.
   */
  DqnGadget(libsnark::protoboard<Fr>& pb,
            libsnark::pb_variable_array<Fr> const& image_input,
            libsnark::pb_variable_array<Fr> const& conv1_weight_vars,
            libsnark::pb_variable_array<Fr> const& conv2_weight_vars,
            libsnark::pb_variable_array<Fr> const& conv3_weight_vars,
            libsnark::pb_variable_array<Fr> const& fc1_weight_vars,
            libsnark::pb_variable_array<Fr> const& fc2_weight_vars,
            const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        conv1_weight_vars_(conv1_weight_vars),
        conv2_weight_vars_(conv2_weight_vars),
        conv3_weight_vars_(conv3_weight_vars),
        fc1_weight_vars_(fc1_weight_vars),
        fc2_weight_vars_(fc2_weight_vars) {
    assert(image_input.size() == IMG_SIZE);

    // Convert pb_variable_array to linear_combination_array
    for (size_t i = 0; i < image_input.size(); ++i) {
      image_input_lc_.emplace_back(image_input[i]);
    }

    init(annotation_prefix);
  }

  /**
   * Constructor with linear_combination_array input.
   * This allows direct chaining from normalization (e.g., pixel * scale_factor)
   * without needing extra variables or constraints.
   */
  DqnGadget(libsnark::protoboard<Fr>& pb,
            libsnark::linear_combination_array<Fr> const& image_input_lc,
            libsnark::pb_variable_array<Fr> const& conv1_weight_vars,
            libsnark::pb_variable_array<Fr> const& conv2_weight_vars,
            libsnark::pb_variable_array<Fr> const& conv3_weight_vars,
            libsnark::pb_variable_array<Fr> const& fc1_weight_vars,
            libsnark::pb_variable_array<Fr> const& fc2_weight_vars,
            const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        image_input_lc_(image_input_lc),
        conv1_weight_vars_(conv1_weight_vars),
        conv2_weight_vars_(conv2_weight_vars),
        conv3_weight_vars_(conv3_weight_vars),
        fc1_weight_vars_(fc1_weight_vars),
        fc2_weight_vars_(fc2_weight_vars) {
    assert(image_input_lc.size() == IMG_SIZE);

    init(annotation_prefix);
  }

  // Note: All gadgets generate constraints in their constructors,
  // so no explicit generate_r1cs_constraints() is needed.

  void generate_r1cs_witness() {
    // Conv1
    conv1_gadget_->generate_r1cs_witness();

    // BatchReLU after Conv1 and copy to Conv2 input (parallelized)
    batch_relu_conv1_->generate_r1cs_witness();
    auto copy_conv1_to_conv2 = [this](int64_t i) {
      this->pb.val(conv2_input_[i]) = this->pb.val(batch_relu_conv1_->ret(i));
    };
    parallel::For(static_cast<int64_t>(CONV1_OUT_SIZE), copy_conv1_to_conv2);

    // Conv2
    conv2_gadget_->generate_r1cs_witness();

    // BatchReLU after Conv2 and copy to Conv3 input (parallelized)
    batch_relu_conv2_->generate_r1cs_witness();
    auto copy_conv2_to_conv3 = [this](int64_t i) {
      this->pb.val(conv3_input_[i]) = this->pb.val(batch_relu_conv2_->ret(i));
    };
    parallel::For(static_cast<int64_t>(CONV2_OUT_SIZE), copy_conv2_to_conv3);

    // Conv3
    conv3_gadget_->generate_r1cs_witness();

    // BatchReLU after Conv3 and copy to FC1 input (parallelized)
    batch_relu_conv3_->generate_r1cs_witness();
    auto copy_conv3_to_fc1 = [this](int64_t i) {
      this->pb.val(fc1_input_[i]) = this->pb.val(batch_relu_conv3_->ret(i));
    };
    parallel::For(static_cast<int64_t>(CONV3_OUT_SIZE), copy_conv3_to_fc1);

    // FC1 + FC2 + Max
    fc1_gadget_->generate_r1cs_witness();
    
    // Copy FC1 output to FC2 input (parallelized)
    auto copy_fc1_to_fc2 = [this](int64_t i) {
      this->pb.val(fc2_input_[i]) = this->pb.val(fc1_gadget_->out_var(i));
    };
    parallel::For(static_cast<int64_t>(FC2_IN), copy_fc1_to_fc2);
    
    fc2_gadget_->generate_r1cs_witness();
    max_gadget_->generate_r1cs_witness();
  }

  /**
   * Get the action chosen by the DQN (0 = no_flap, 1 = flap).
   * Must be called after generate_r1cs_witness().
   */
  int get_action() const {
    auto const& onehot = max_gadget_->ret_array();
    return (this->pb.val(onehot[1]) == Fr(1)) ? 1 : 0;
  }

  /**
   * Get the Q-values output by FC2.
   * Must be called after generate_r1cs_witness().
   */
  std::pair<Fr, Fr> get_q_values() const {
    return {this->pb.val(fc2_gadget_->out_var(0)), 
            this->pb.val(fc2_gadget_->out_var(1))};
  }

  /**
   * Get the action one-hot vector.
   */
  libsnark::pb_variable_array<Fr> const& action_onehot() const {
    return max_gadget_->ret_array();
  }

  /**
   * Get FC2 output variable at index.
   */
  libsnark::pb_variable<Fr> q_value(size_t i) const {
    return fc2_gadget_->out_var(i);
  }

  // Static accessor methods for dimensions
  static constexpr size_t img_size() { return IMG_SIZE; }
  static constexpr size_t conv1_weight_size() { return CONV1_WEIGHT_SIZE; }
  static constexpr size_t conv2_weight_size() { return CONV2_WEIGHT_SIZE; }
  static constexpr size_t conv3_weight_size() { return CONV3_WEIGHT_SIZE; }
  static constexpr size_t fc1_weight_size() { return FC1_OUT * (FC1_IN + 1); }
  static constexpr size_t fc2_weight_size() { return FC2_OUT * (FC2_IN + 1); }
  static constexpr size_t total_weight_size() {
    return CONV1_WEIGHT_SIZE + CONV2_WEIGHT_SIZE + CONV3_WEIGHT_SIZE +
           FC1_OUT * (FC1_IN + 1) + FC2_OUT * (FC2_IN + 1);
  }

 private:
  void init(const std::string& annotation_prefix) {
    // Verify weight array sizes
    assert(conv1_weight_vars_.size() == CONV1_WEIGHT_SIZE);
    assert(conv2_weight_vars_.size() == CONV2_WEIGHT_SIZE);
    assert(conv3_weight_vars_.size() == CONV3_WEIGHT_SIZE);
    assert(fc1_weight_vars_.size() == FC1_OUT * (FC1_IN + 1));
    assert(fc2_weight_vars_.size() == FC2_OUT * (FC2_IN + 1));

    // ---- Conv1: (4, 84, 84) -> (32, 20, 20) ----
    conv1_gadget_.reset(new Conv2dGadget(
        this->pb, IMG_C, IMG_H, IMG_W,
        CONV1_OUT_C, CONV1_K, CONV1_K, CONV1_S, CONV1_S,
        conv1_weight_vars_, image_input_lc_,
        FMT(this->annotation_prefix, " conv1")));

    // ---- BatchReLU after Conv1: 12800 units ----
    {
      libsnark::linear_combination_array<Fr> conv1_out_lc;
      conv1_out_lc.reserve(CONV1_OUT_SIZE);
      for (size_t i = 0; i < CONV1_OUT_SIZE; ++i) {
        conv1_out_lc.emplace_back(conv1_gadget_->out_vars()[i]);
      }
      batch_relu_conv1_.reset(new BatchRelu2Gadget(
          this->pb, conv1_out_lc, ""));
    }

    // Build Conv2 input from BatchReLU1 outputs
    conv2_input_.allocate(this->pb, CONV1_OUT_SIZE, "");

    // ---- Conv2: (32, 20, 20) -> (64, 9, 9) ----
    conv2_gadget_.reset(new Conv2dGadget(
        this->pb, CONV1_OUT_C, CONV1_OUT_H, CONV1_OUT_W,
        CONV2_OUT_C, CONV2_K, CONV2_K, CONV2_S, CONV2_S,
        conv2_weight_vars_, conv2_input_, ""));

    // ---- BatchReLU after Conv2: 5184 units ----
    {
      libsnark::linear_combination_array<Fr> conv2_out_lc;
      conv2_out_lc.reserve(CONV2_OUT_SIZE);
      for (size_t i = 0; i < CONV2_OUT_SIZE; ++i) {
        conv2_out_lc.emplace_back(conv2_gadget_->out_vars()[i]);
      }
      batch_relu_conv2_.reset(new BatchRelu2Gadget(
          this->pb, conv2_out_lc, ""));
    }

    // Build Conv3 input from BatchReLU2 outputs
    conv3_input_.allocate(this->pb, CONV2_OUT_SIZE, "");

    // ---- Conv3: (64, 9, 9) -> (64, 7, 7) ----
    conv3_gadget_.reset(new Conv2dGadget(
        this->pb, CONV2_OUT_C, CONV2_OUT_H, CONV2_OUT_W,
        CONV3_OUT_C, CONV3_K, CONV3_K, CONV3_S, CONV3_S,
        conv3_weight_vars_, conv3_input_, ""));

    // ---- BatchReLU after Conv3: 3136 units ----
    {
      libsnark::linear_combination_array<Fr> conv3_out_lc;
      conv3_out_lc.reserve(CONV3_OUT_SIZE);
      for (size_t i = 0; i < CONV3_OUT_SIZE; ++i) {
        conv3_out_lc.emplace_back(conv3_gadget_->out_vars()[i]);
      }
      batch_relu_conv3_.reset(new BatchRelu2Gadget(
          this->pb, conv3_out_lc, ""));
    }

    // Build FC1 input from flattened Conv3+BatchReLU output
    fc1_input_.allocate(this->pb, FC1_IN, "");

    // ---- FC1: 3136 -> 512 with ReLU ----
    fc1_gadget_.reset(new LinearReluGadget(
        this->pb, FC1_IN, FC1_OUT,
        fc1_weight_vars_, fc1_input_, ""));

    // ---- FC2: 512 -> 2 (no ReLU) ----
    fc2_input_.allocate(this->pb, FC2_IN, "");
    fc2_gadget_.reset(new LinearGadgetNoRelu(
        this->pb, FC2_IN, FC2_OUT,
        fc2_weight_vars_, fc2_input_, ""));

    // ---- Max: 2 -> action index (one-hot) ----
    libsnark::linear_combination_array<Fr> max_input_lc = fc2_gadget_->out_lc_array();
    max_gadget_.reset(new Max2Gadget(
        this->pb, max_input_lc, ""));
  }

  // Input (stored as linear_combination_array for flexibility)
  libsnark::linear_combination_array<Fr> image_input_lc_;
  libsnark::pb_variable_array<Fr> const& conv1_weight_vars_;
  libsnark::pb_variable_array<Fr> const& conv2_weight_vars_;
  libsnark::pb_variable_array<Fr> const& conv3_weight_vars_;
  libsnark::pb_variable_array<Fr> const& fc1_weight_vars_;
  libsnark::pb_variable_array<Fr> const& fc2_weight_vars_;

  // Intermediate variables
  libsnark::pb_variable_array<Fr> conv2_input_;
  libsnark::pb_variable_array<Fr> conv3_input_;
  libsnark::pb_variable_array<Fr> fc1_input_;
  libsnark::pb_variable_array<Fr> fc2_input_;

  // Conv layers
  std::unique_ptr<Conv2dGadget> conv1_gadget_;
  std::unique_ptr<Conv2dGadget> conv2_gadget_;
  std::unique_ptr<Conv2dGadget> conv3_gadget_;

  // Batch ReLU after each conv layer
  std::unique_ptr<BatchRelu2Gadget> batch_relu_conv1_;
  std::unique_ptr<BatchRelu2Gadget> batch_relu_conv2_;
  std::unique_ptr<BatchRelu2Gadget> batch_relu_conv3_;

  // FC1
  std::unique_ptr<LinearReluGadget> fc1_gadget_;

  // FC2
  std::unique_ptr<LinearGadgetNoRelu> fc2_gadget_;

  // Max
  std::unique_ptr<Max2Gadget> max_gadget_;
};

}  // namespace circuit::flappybird
