#pragma once

#include "./dqn_gadget.h"
#include "./env_gadget.h"

namespace circuit::frozenlake {

/**
 * DqnEnvGadget: combines DQN inference and environment state transition
 * into a single R1CS circuit (iterated function).
 *
 * Pipeline per iteration:
 *   in_state (64-dim one-hot, integer values 0 or 1)
 *     -> DqnGadget (Dense1->ReLU->Dense2->ReLU->Dense3->Max2)
 *     -> action one-hot (4-dim, integer 0/1)
 *     -> EnvGadget (state transition, integer arithmetic)
 *     -> out_state_pack (integer position)
 *
 * All model weights are witness variables (not constants).
 * For the iterated function R1CS (A12 protocol):
 *   - Public input x_{j-1} = in_state_pack (integer)
 *   - Public output x_j    = out_state_pack (integer)
 *   - Witness w_j           = all intermediate variables
 */
class DqnEnvGadget : public libsnark::gadget<Fr> {
 public:
  /**
   * @param pb                   Protoboard for R1CS constraints
   * @param in_state_pack        External packed state variable (integer position 0..63)
   * @param dense1_weight_vars   Flat weight variables [12 * 65]
   * @param dense2_weight_vars   Flat weight variables [8 * 13]
   * @param dense3_weight_vars   Flat weight variables [4 * 9]
   * @param annotation_prefix    Annotation prefix for debugging
   */
  DqnEnvGadget(libsnark::protoboard<Fr>& pb,
               libsnark::pb_variable<Fr> const& in_state_pack,
               libsnark::pb_variable_array<Fr> const& dense1_weight_vars,
               libsnark::pb_variable_array<Fr> const& dense2_weight_vars,
               libsnark::pb_variable_array<Fr> const& dense3_weight_vars,
               const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        in_state_pack_(in_state_pack),
        dense1_weight_vars_(dense1_weight_vars),
        dense2_weight_vars_(dense2_weight_vars),
        dense3_weight_vars_(dense3_weight_vars) {

    // onehot_gadget: from in_state_pack_ generate in_state one-hot bits
    in_onehot_gadget_.reset(new ::circuit::onehot_gadget(
        this->pb, in_state_pack_, 64,
        FMT(this->annotation_prefix, " in_onehot")));

    // ---- DqnGadget: DQN inference (in_state -> action one-hot) ----
    dqn_gadget_.reset(new DqnGadget(
        this->pb, in_onehot_gadget_->bits,
        dense1_weight_vars_, dense2_weight_vars_, dense3_weight_vars_,
        FMT(this->annotation_prefix, " dqn")));

    // ---- EnvGadget: state transition (integer arithmetic) ----
    env_gadget_.reset(new EnvGadget(
        this->pb, in_onehot_gadget_->bits, dqn_gadget_->action_onehot(), in_state_pack_,
        FMT(this->annotation_prefix, " env")));
  }

  /**
   * Assign a packed state (integer position) and run the full DQN+Env pipeline.
   * @param state_pack integer position (0..63)
   */
  void Assign(int state_pack) {
    this->pb.val(in_state_pack_) = state_pack;
    generate_r1cs_witness();
  }

  libsnark::pb_variable<Fr> in_pack() const { return in_state_pack_; }
  libsnark::pb_variable<Fr> out_pack() const { return env_gadget_->ret(); }

  size_t in_pack_index() const { return in_state_pack_.index; }
  size_t out_pack_index() const { return env_gadget_->ret().index; }

  void generate_r1cs_witness() {
    // Generate one-hot bits from in_state_pack_
    in_onehot_gadget_->generate_r1cs_witness();

    // DQN inference
    dqn_gadget_->generate_r1cs_witness();

    // Environment state transition
    env_gadget_->AssignFromExternal();
  }

 private:
  // Weight variable references
  libsnark::pb_variable_array<Fr> const& dense1_weight_vars_;
  libsnark::pb_variable_array<Fr> const& dense2_weight_vars_;
  libsnark::pb_variable_array<Fr> const& dense3_weight_vars_;

  // Input state pack (externally owned)
  libsnark::pb_variable<Fr> const& in_state_pack_;
  std::unique_ptr<::circuit::onehot_gadget> in_onehot_gadget_;

  // DQN inference
  std::unique_ptr<DqnGadget> dqn_gadget_;

  // Environment state transition
  std::unique_ptr<EnvGadget> env_gadget_;
};

}  // namespace circuit::frozenlake
