#pragma once

#include "circuit/fixed_point/fixed_point.h"
#include "circuit/fixed_point/linear_gadget.h"
#include "circuit/fixed_point/conv2d_gadget.h"
#include "circuit/fixed_point/max2_gadget.h"
#include "log/tick.h"
#include "parallel/parallel.h"

namespace circuit::pong {

/**
 * PongDqnGadget: implements the CNN-based Deep Q-Network for Pong as R1CS
 * constraints.
 *
 * CNN Architecture (matching train_pong_fast.py FastPongDQN):
 *   Input: (batch, 2, 42, 42) - 2 frames of 42x42 grayscale images
 *   Conv1: Conv2d(2, 16, kernel=8, stride=4) -> ReLU  => (16, 9, 9)
 *   Conv2: Conv2d(16, 32, kernel=4, stride=2) -> ReLU => (32, 3, 3)
 *   Flatten: (32, 3, 3) -> (288,)
 *   FC1:   Linear(288, 128) -> ReLU
 *   FC2:   Linear(128, 3)
 *   Max:   argmax -> action one-hot [stay, left, right]
 *
 * Key differences from FlappyBird DqnGadget:
 *   - Smaller input: 2x42x42 (not 4x84x84)
 *   - Only 2 conv layers with fewer channels
 *   - FC1: 288 -> 128 (not 3136 -> 512)
 *   - FC2: 128 -> 3 (not 512 -> 2)
 *   - 3 actions: stay(0), left(1), right(2)
 *   - Total params: ~47K (vs ~1.7M for FlappyBird)
 *
 * Template parameters:
 *   D, N: fixed-point precision (D=integer bits, N=fractional bits)
 *
 * IMPORTANT: All weights (conv and FC) are witness variables, NOT constants.
 * This ensures the model parameters are part of the secret witness.
 */
template <size_t D, size_t N>
class PongDqnGadget : public libsnark::gadget<Fr> {
  static constexpr size_t N2 = 2 * N;  // Double precision for intermediate results

  typedef fixed_point::Relu2Gadget<D, N2, N> Relu2Gadget;
  typedef fixed_point::MaxGadget<D, N2> MaxGadget;
  typedef fixed_point::Max2Gadget<D, N2> Max2Gadget;
  typedef fixed_point::SignGadget<D, N2> SignGadget;
  typedef fixed_point::LinearGadget<D, N, false> LinearGadgetNoRelu;
  typedef fixed_point::LinearReluGadget<D, N> LinearReluGadget;
  typedef fixed_point::Conv2dGadget<D, N> Conv2dGadget;

  // CNN dimensions (FastPongDQN: 2 frames of 42x42)
  static constexpr size_t IMG_C = 2;
  static constexpr size_t IMG_H = 42;
  static constexpr size_t IMG_W = 42;
  static constexpr size_t IMG_SIZE = IMG_C * IMG_H * IMG_W;  // 3528

  // Conv1: (2, 42, 42) -> (16, 9, 9)
  static constexpr size_t CONV1_OUT_C = 16;
  static constexpr size_t CONV1_K = 8;
  static constexpr size_t CONV1_S = 4;
  static constexpr size_t CONV1_OUT_H = (IMG_H - CONV1_K) / CONV1_S + 1;  // 9
  static constexpr size_t CONV1_OUT_W = (IMG_W - CONV1_K) / CONV1_S + 1;  // 9
  static constexpr size_t CONV1_OUT_SIZE = CONV1_OUT_C * CONV1_OUT_H * CONV1_OUT_W;  // 1296
  static constexpr size_t CONV1_WEIGHT_SIZE = CONV1_OUT_C * (IMG_C * CONV1_K * CONV1_K + 1);  // 16*129 = 2064

  // Conv2: (16, 9, 9) -> (32, 3, 3)
  static constexpr size_t CONV2_OUT_C = 32;
  static constexpr size_t CONV2_K = 4;
  static constexpr size_t CONV2_S = 2;
  static constexpr size_t CONV2_OUT_H = (CONV1_OUT_H - CONV2_K) / CONV2_S + 1;  // 3
  static constexpr size_t CONV2_OUT_W = (CONV1_OUT_W - CONV2_K) / CONV2_S + 1;  // 3
  static constexpr size_t CONV2_OUT_SIZE = CONV2_OUT_C * CONV2_OUT_H * CONV2_OUT_W;  // 288
  static constexpr size_t CONV2_WEIGHT_SIZE = CONV2_OUT_C * (CONV1_OUT_C * CONV2_K * CONV2_K + 1);  // 32*257 = 8224

  // No Conv3 for Pong DQN!

  // FC1: 288 -> 128
  static constexpr size_t FC1_IN = CONV2_OUT_SIZE;  // 288
  static constexpr size_t FC1_OUT = 128;

  // FC2: 128 -> 3
  static constexpr size_t FC2_IN = FC1_OUT;
  static constexpr size_t FC2_OUT = 3;  // 3 actions: stay, left, right

 public:
  /**
   * Constructor for PongDqnGadget.
   *
   * @param pb                 Protoboard for R1CS constraints
   * @param image_input        Image input as pb_variable_array [IMG_SIZE = 2 * 42 * 42]
   * @param conv1_weight_vars  Conv1 weight variables [CONV1_WEIGHT_SIZE]
   * @param conv2_weight_vars  Conv2 weight variables [CONV2_WEIGHT_SIZE]
   * @param fc1_weight_vars    FC1 weight variables [FC1_OUT * (FC1_IN + 1)]
   * @param fc2_weight_vars    FC2 weight variables [FC2_OUT * (FC2_IN + 1)]
   * @param annotation_prefix  Annotation prefix for debugging
   */
  PongDqnGadget(libsnark::protoboard<Fr>& pb,
                libsnark::pb_variable_array<Fr> const& image_input,
                libsnark::pb_variable_array<Fr> const& conv1_weight_vars,
                libsnark::pb_variable_array<Fr> const& conv2_weight_vars,
                libsnark::pb_variable_array<Fr> const& fc1_weight_vars,
                libsnark::pb_variable_array<Fr> const& fc2_weight_vars,
                const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        image_input_(image_input),
        conv1_weight_vars_(conv1_weight_vars),
        conv2_weight_vars_(conv2_weight_vars),
        fc1_weight_vars_(fc1_weight_vars),
        fc2_weight_vars_(fc2_weight_vars) {

    // Verify array sizes
    assert(image_input.size() == IMG_SIZE);
    assert(conv1_weight_vars.size() == CONV1_WEIGHT_SIZE);
    assert(conv2_weight_vars.size() == CONV2_WEIGHT_SIZE);
    assert(fc1_weight_vars.size() == FC1_OUT * (FC1_IN + 1));
    assert(fc2_weight_vars.size() == FC2_OUT * (FC2_IN + 1));

    // ---- Conv1: (2, 42, 42) -> (16, 9, 9) ----
    conv1_gadget_.reset(new Conv2dGadget(
        this->pb, IMG_C, IMG_H, IMG_W,
        CONV1_OUT_C, CONV1_K, CONV1_K, CONV1_S, CONV1_S,
        conv1_weight_vars_, image_input_,
        FMT(this->annotation_prefix, " conv1")));

    // ---- ReLU after Conv1: 1296 units ----
    relu_conv1_.reserve(CONV1_OUT_SIZE);
    for (size_t i = 0; i < CONV1_OUT_SIZE; ++i) {
      relu_conv1_.emplace_back(new Relu2Gadget(
          this->pb, conv1_gadget_->out_vars()[i],
          FMT(this->annotation_prefix, " relu1_%zu", i)));
    }

    // Build Conv2 input from ReLU1 outputs
    for (size_t i = 0; i < CONV1_OUT_SIZE; ++i) {
      conv2_input_lc_.emplace_back(relu_conv1_[i]->ret());
    }

    // ---- Conv2: (16, 9, 9) -> (32, 3, 3) ----
    conv2_gadget_.reset(new Conv2dGadget(
        this->pb, CONV1_OUT_C, CONV1_OUT_H, CONV1_OUT_W,
        CONV2_OUT_C, CONV2_K, CONV2_K, CONV2_S, CONV2_S,
        conv2_weight_vars_, conv2_input_lc_,
        FMT(this->annotation_prefix, " conv2")));

    // ---- ReLU after Conv2: 288 units ----
    relu_conv2_.reserve(CONV2_OUT_SIZE);
    for (size_t i = 0; i < CONV2_OUT_SIZE; ++i) {
      relu_conv2_.emplace_back(new Relu2Gadget(
          this->pb, conv2_gadget_->out_vars()[i],
          FMT(this->annotation_prefix, " relu2_%zu", i)));
    }

    // Build FC1 input from flattened Conv2+ReLU output
    for (size_t i = 0; i < FC1_IN; ++i) {
      fc1_input_lc_.emplace_back(relu_conv2_[i]->ret());
    }

    // ---- FC1: 288 -> 128 with ReLU ----
    fc1_gadget_.reset(new LinearReluGadget(
        this->pb, FC1_IN, FC1_OUT,
        fc1_weight_vars_, fc1_input_lc_,
        FMT(this->annotation_prefix, " fc1")));

    // ---- FC2: 128 -> 3 (no ReLU) ----
    fc2_gadget_.reset(new LinearGadgetNoRelu(
        this->pb, FC2_IN, FC2_OUT,
        fc2_weight_vars_, fc1_gadget_->out_lc_array(),
        FMT(this->annotation_prefix, " fc2")));

    // ---- Max: 3 -> action index (one-hot) ----
    libsnark::linear_combination_array<Fr> max_input_lc;
    for (size_t i = 0; i < FC2_OUT; ++i) {
      max_input_lc.emplace_back(fc2_gadget_->linear_out_vars()[i]);
    }
    max_gadget_.reset(new Max2Gadget(
        this->pb, max_input_lc,
        FMT(this->annotation_prefix, " max")));
  }

  // Note: All gadgets generate constraints in their constructors,
  // so no explicit generate_r1cs_constraints() is needed.

  void generate_r1cs_witness() {
    // Conv1
    conv1_gadget_->generate_r1cs_witness();

    // ReLU after Conv1
    for (size_t i = 0; i < CONV1_OUT_SIZE; ++i) {
      relu_conv1_[i]->generate_r1cs_witness();
    }

    // Conv2
    conv2_gadget_->generate_r1cs_witness();

    // ReLU after Conv2
    for (size_t i = 0; i < CONV2_OUT_SIZE; ++i) {
      relu_conv2_[i]->generate_r1cs_witness();
    }

    // FC1 + FC2 + Max
    fc1_gadget_->generate_r1cs_witness();
    fc2_gadget_->generate_r1cs_witness();
    max_gadget_->generate_r1cs_witness();
  }

  /**
   * Get the action chosen by the DQN.
   *   0 = stay, 1 = left, 2 = right
   * Must be called after generate_r1cs_witness().
   */
  int get_action() const {
    auto const& onehot = max_gadget_->ret_array();
    for (size_t i = 0; i < FC2_OUT; ++i) {
      if (this->pb.val(onehot[i]) == Fr(1)) {
        return static_cast<int>(i);
      }
    }
    return 0;  // default: stay
  }

  /**
   * Get the Q-values output by FC2.
   * Must be called after generate_r1cs_witness().
   * Returns a vector of 3 Q-values: [Q(stay), Q(left), Q(right)]
   */
  std::vector<Fr> get_q_values() const {
    std::vector<Fr> q_vals(FC2_OUT);
    for (size_t i = 0; i < FC2_OUT; ++i) {
      q_vals[i] = this->pb.val(fc2_gadget_->linear_out_vars()[i]);
    }
    return q_vals;
  }

  /**
   * Get the action one-hot vector.
   */
  libsnark::pb_variable_array<Fr> const& action_onehot() const {
    return max_gadget_->ret_array();
  }

  /**
   * Get FC2 output variables (Q-values).
   */
  libsnark::pb_variable_array<Fr> const& q_value_vars() const {
    return fc2_gadget_->linear_out_vars();
  }

  /**
   * Get human-readable action name.
   */
  static const char* action_name(int action) {
    switch (action) {
      case 0: return "stay";
      case 1: return "left";
      case 2: return "right";
      default: return "unknown";
    }
  }

  // Static accessor methods for dimensions
  static constexpr size_t img_size() { return IMG_SIZE; }
  static constexpr size_t num_actions() { return FC2_OUT; }
  static constexpr size_t conv1_weight_size() { return CONV1_WEIGHT_SIZE; }
  static constexpr size_t conv2_weight_size() { return CONV2_WEIGHT_SIZE; }
  static constexpr size_t fc1_weight_size() {
    return FC1_OUT * (FC1_IN + 1);
  }
  static constexpr size_t fc2_weight_size() {
    return FC2_OUT * (FC2_IN + 1);
  }
  static constexpr size_t total_weight_size() {
    return CONV1_WEIGHT_SIZE + CONV2_WEIGHT_SIZE +
           FC1_OUT * (FC1_IN + 1) + FC2_OUT * (FC2_IN + 1);
  }

  // Dimension accessors for intermediate layers
  static constexpr size_t conv1_out_size() { return CONV1_OUT_SIZE; }
  static constexpr size_t conv2_out_size() { return CONV2_OUT_SIZE; }
  static constexpr size_t fc1_in_size() { return FC1_IN; }
  static constexpr size_t fc1_out_size() { return FC1_OUT; }
  static constexpr size_t fc2_in_size() { return FC2_IN; }
  static constexpr size_t fc2_out_size() { return FC2_OUT; }
  
  /**
   * Get Conv1 output variables (before ReLU)
   */
  libsnark::pb_variable_array<Fr> const& conv1_out_vars() const {
    return conv1_gadget_->out_vars();
  }
  
  /**
   * Get Conv2 output variables (before ReLU)
   */
  libsnark::pb_variable_array<Fr> const& conv2_out_vars() const {
    return conv2_gadget_->out_vars();
  }
  
  /**
   * Get FC1 output variables (before ReLU)
   */
  libsnark::pb_variable_array<Fr> const& fc1_out_vars() const {
    return fc1_gadget_->linear_out_vars();
  }

 private:
  // Input references
  libsnark::pb_variable_array<Fr> const& image_input_;
  libsnark::pb_variable_array<Fr> const& conv1_weight_vars_;
  libsnark::pb_variable_array<Fr> const& conv2_weight_vars_;
  libsnark::pb_variable_array<Fr> const& fc1_weight_vars_;
  libsnark::pb_variable_array<Fr> const& fc2_weight_vars_;

  // Intermediate linear_combination arrays (no extra variable allocation)
  libsnark::linear_combination_array<Fr> conv2_input_lc_;
  libsnark::linear_combination_array<Fr> fc1_input_lc_;

  // Conv1
  std::unique_ptr<Conv2dGadget> conv1_gadget_;
  std::vector<std::unique_ptr<Relu2Gadget>> relu_conv1_;

  // Conv2
  std::unique_ptr<Conv2dGadget> conv2_gadget_;
  std::vector<std::unique_ptr<Relu2Gadget>> relu_conv2_;

  // FC1
  std::unique_ptr<LinearReluGadget> fc1_gadget_;

  // FC2
  std::unique_ptr<LinearGadgetNoRelu> fc2_gadget_;

  // Max
  std::unique_ptr<Max2Gadget> max_gadget_;
};

}  // namespace circuit::pong
