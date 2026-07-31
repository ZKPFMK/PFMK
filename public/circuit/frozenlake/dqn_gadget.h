#pragma once

#include "../fixed_point/fixed_point.h"
#include "../fixed_point/linear_gadget.h"
#include "../fixed_point/max2_gadget.h"

namespace circuit::frozenlake {

/**
 * DqnGadget: implements the fully-connected DQN inference as R1CS constraints.
 *
 * Network Architecture:
 *   in_state (64-dim one-hot, integer values 0 or 1)
 *     -> Convert to fixed-point (multiply by kFrN)
 *     -> Dense1 (64->12, with bias) + ReLU  [LinearReluGadget]
 *     -> Dense2 (12->8, with bias)  + ReLU  [LinearReluGadget]
 *     -> Dense3 (8->4, with bias)           [LinearGadget, no ReLU]
 *     -> Max2 (argmax -> action one-hot)    [Max2Gadget]
 *
 * IMPORTANT: All weights are witness variables, NOT constants.
 * This ensures the model parameters are part of the secret witness.
 *
 * Input Format:
 *   - in_state: 64-dim one-hot state vector with INTEGER values (0 or 1)
 *   - The gadget internally converts to fixed-point format for linear layers
 *
 * Weight layout (flat pb_variable_array per layer):
 *   dense1_weight_vars: [12 * (64 + 1)] = [12 * 65] = 780
 *     For output j: weight_vars[j * 65 + i] = weight[i][j], weight_vars[j * 65 + 64] = bias[j]
 *   dense2_weight_vars: [8 * (12 + 1)] = [8 * 13] = 104
 *   dense3_weight_vars: [4 * (8 + 1)]  = [4 * 9]  = 36
 *
 * Input:  64-dim one-hot state vector (externally allocated pb_variable_array, integer values)
 * Output: 4-dim action one-hot vector (via Max2Gadget, integer values 0 or 1)
 */
class DqnGadget : public libsnark::gadget<Fr> {
  static constexpr size_t D = 8;
  static constexpr size_t N = 24;
  static constexpr size_t N2 = 2 * N;

  typedef fixed_point::LinearReluGadget<D, N> LinearReluGadget;
  typedef fixed_point::LinearGadget<D, N, false> LinearGadgetNoRelu;
  typedef fixed_point::Max2Gadget<D, N2> Max2Gadget;

  // Network dimensions
  static constexpr size_t IN_DIM = 64;
  static constexpr size_t DENSE1_OUT = 12;
  static constexpr size_t DENSE2_OUT = 8;
  static constexpr size_t DENSE3_OUT = 4;

 public:
  /**
   * @param pb                   Protoboard for R1CS constraints
   * @param in_state             External 64-dim input variables (integer values 0 or 1)
   * @param dense1_weight_vars   Flat weight variables [DENSE1_OUT * (IN_DIM + 1)]
   * @param dense2_weight_vars   Flat weight variables [DENSE2_OUT * (DENSE1_OUT + 1)]
   * @param dense3_weight_vars   Flat weight variables [DENSE3_OUT * (DENSE2_OUT + 1)]
   * @param annotation_prefix    Annotation prefix for debugging
   */
  DqnGadget(libsnark::protoboard<Fr>& pb,
            libsnark::pb_variable_array<Fr> const& in_state,
            libsnark::pb_variable_array<Fr> const& dense1_weight_vars,
            libsnark::pb_variable_array<Fr> const& dense2_weight_vars,
            libsnark::pb_variable_array<Fr> const& dense3_weight_vars,
            const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        in_state_(in_state),
        dense1_weight_vars_(dense1_weight_vars),
        dense2_weight_vars_(dense2_weight_vars),
        dense3_weight_vars_(dense3_weight_vars) {

    assert(in_state.size() == IN_DIM);
    assert(dense1_weight_vars.size() == dense1_weight_size());
    assert(dense2_weight_vars.size() == dense2_weight_size());
    assert(dense3_weight_vars.size() == dense3_weight_size());

    // ---- Convert integer input to fixed-point format ----
    // in_state_fp[i] = in_state[i] * kFrN
    // This allows the input to be integer (0 or 1) while the linear layer expects fixed-point
    fixed_point::RationalConst<D, N> rc;
    for (size_t i = 0; i < IN_DIM; ++i) {
      in_state_fp_.emplace_back(in_state_[i] * rc.kFrN);
    }

    // ---- Dense1 + ReLU1: 64 -> 12 ----
    dense1_gadget_.reset(new LinearReluGadget(
        this->pb, IN_DIM, DENSE1_OUT,
        dense1_weight_vars_, in_state_fp_,
        FMT(this->annotation_prefix, " dense1")));

    // ---- Dense2 + ReLU2: 12 -> 8 (直接使用 Dense1 输出，无需 bridge 变量) ----
    dense2_gadget_.reset(new LinearReluGadget(
        this->pb, DENSE1_OUT, DENSE2_OUT,
        dense2_weight_vars_, dense1_gadget_->out_lc_array(),
        FMT(this->annotation_prefix, " dense2")));

    // ---- Dense3 (no ReLU): 8 -> 4 (直接使用 Dense2 输出，无需 bridge 变量) ----
    dense3_gadget_.reset(new LinearGadgetNoRelu(
        this->pb, DENSE2_OUT, DENSE3_OUT,
        dense3_weight_vars_, dense2_gadget_->out_lc_array(),
        FMT(this->annotation_prefix, " dense3")));

    // ---- Max2: 4 -> action one-hot ----
    max_gadget_.reset(new Max2Gadget(
        this->pb, dense3_gadget_->out_lc_array(),
        FMT(this->annotation_prefix, " max")));

    // Note: All gadgets generate constraints in their constructors
  }

  /**
   * Generate witness for the DQN inference.
   * Assumes in_state_ and weight variables have already been assigned by the caller.
   */
  void generate_r1cs_witness() {
    dense1_gadget_->generate_r1cs_witness();
    dense2_gadget_->generate_r1cs_witness();
    dense3_gadget_->generate_r1cs_witness();
    max_gadget_->generate_r1cs_witness();
  }

  /**
   * Get the action one-hot vector (4-dim, integer values 0 or 1).
   */
  libsnark::pb_variable_array<Fr> const& action_onehot() const {
    return max_gadget_->ret_array();
  }

  // Static accessor methods for weight array sizes
  static constexpr size_t dense1_weight_size() { return DENSE1_OUT * (IN_DIM + 1); }
  static constexpr size_t dense2_weight_size() { return DENSE2_OUT * (DENSE1_OUT + 1); }
  static constexpr size_t dense3_weight_size() { return DENSE3_OUT * (DENSE2_OUT + 1); }
  static constexpr size_t total_weight_size() {
    return dense1_weight_size() + dense2_weight_size() + dense3_weight_size();
  }

 private:
  // External input state reference (integer values 0 or 1)
  libsnark::pb_variable_array<Fr> const& in_state_;

  // Weight variable references
  libsnark::pb_variable_array<Fr> const& dense1_weight_vars_;
  libsnark::pb_variable_array<Fr> const& dense2_weight_vars_;
  libsnark::pb_variable_array<Fr> const& dense3_weight_vars_;

  // Fixed-point converted input (in_state * kFrN)
  libsnark::linear_combination_array<Fr> in_state_fp_;

  // Dense1 + ReLU1
  std::unique_ptr<LinearReluGadget> dense1_gadget_;

  // Dense2 + ReLU2
  std::unique_ptr<LinearReluGadget> dense2_gadget_;

  // Dense3 (no ReLU)
  std::unique_ptr<LinearGadgetNoRelu> dense3_gadget_;

  // Max2: argmax -> action one-hot
  std::unique_ptr<Max2Gadget> max_gadget_;
};

}  // namespace circuit::frozenlake
