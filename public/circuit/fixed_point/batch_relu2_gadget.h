#pragma once

#include "circuit/basic/circuit.h"
#include "circuit/basic/pack_gadget.h"
#include "circuit/basic/select_gadget.h"
#include "./fixed_point.h"
#include "./misc.h"

namespace circuit::fixed_point {

/**
 * BatchRelu2Gadget: batch version of Relu2Gadget for improved build performance.
 *
 * Processes multiple ReLU activations at once using batch gadgets
 * (pack_batch_gadget, select_batch_gadget) instead of creating thousands
 * of individual Relu2Gadget objects.
 *
 * Each element: ret[i] = a[i] >= 0 ? ReducePrecision(a[i]) : 0
 *
 * Internally combines:
 *   1. BatchPrecisionGadget: batch bit-decomposition via pack_batch_gadget
 *   2. select_batch_gadget: batch conditional selection
 *
 * Template parameters:
 *   D: integer bits
 *   N: input fractional bits (typically 2*M for double precision)
 *   M: output fractional bits
 */
template <size_t D, size_t N, size_t M>
class BatchRelu2Gadget : public libsnark::gadget<Fr> {
  static_assert(D + N < 253, "invalid D,N");
  static_assert(N > M, "invalid N or M");

  static constexpr size_t NUM_BITS = D + N + 1;

 public:
  /**
   * Constructor
   * @param pb protoboard
   * @param inputs array of linear_combinations to apply ReLU on
   * @param annotation_prefix annotation
   */
  BatchRelu2Gadget(libsnark::protoboard<Fr>& pb,
                   libsnark::linear_combination_array<Fr> const& inputs,
                   const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        batch_size_(inputs.size()) {

    // Step 1: Offset inputs to make them non-negative: a_off = a + kFrDN
    Fr kFrDN = RationalConst<D, N>().kFrDN;
    libsnark::linear_combination_array<Fr> offset_inputs;
    offset_inputs.reserve(batch_size_);
    for (size_t i = 0; i < batch_size_; ++i) {
      offset_inputs.emplace_back(inputs[i] + kFrDN);
    }

    // Step 2: Batch bit-decomposition using pack_batch_gadget
    pack_batch_.reset(new circuit::pack_batch_gadget(
        pb, offset_inputs, NUM_BITS, ""));

    // Step 3: Allocate packed variables for reduced precision
    packed_.allocate(pb, batch_size_, "");

    // Step 4: For each element, pack high bits [N-M .. D+N] into packed_[i]
    // This is D+M+1 bits
    Fr kFrDM = RationalConst<D, M>().kFrDN;
    for (size_t i = 0; i < batch_size_; ++i) {
      Fr pow2 = 1;
      libsnark::linear_combination<Fr> sum_lc;
      for (size_t bit = N - M; bit <= D + N; ++bit) {
        sum_lc.add_term(pack_batch_->ret(i, bit), pow2);
        pow2 *= 2;
      }
      pb.add_r1cs_constraint(
          libsnark::r1cs_constraint<Fr>(1, sum_lc, packed_[i]), "");
    }

    // Step 5: Build sign and ret linear_combination_arrays
    // sign[i] = bit[D+N] of element i (1 = positive, 0 = negative)
    // ret_precision[i] = packed_[i] - kFrDM
    libsnark::linear_combination_array<Fr> signs;
    libsnark::linear_combination_array<Fr> precision_rets;
    libsnark::linear_combination_array<Fr> zeros;
    signs.reserve(batch_size_);
    precision_rets.reserve(batch_size_);
    zeros.reserve(batch_size_);

    for (size_t i = 0; i < batch_size_; ++i) {
      signs.emplace_back(pack_batch_->ret(i, D + N));
      precision_rets.emplace_back(
          libsnark::linear_combination<Fr>(packed_[i]) - kFrDM);
      zeros.emplace_back(Fr(0));
    }

    // Step 6: Batch select: ret[i] = sign[i] ? precision_ret[i] : 0
    select_batch_.reset(new circuit::select_batch_gadget(
        pb, signs, precision_rets, zeros, ""));
  }

  void generate_r1cs_witness() {
    // 1. Bit decomposition
    pack_batch_->generate_r1cs_witness();

    // 2. Compute packed values from bits
    for (size_t i = 0; i < batch_size_; ++i) {
      mpz_class v(0);
      Fr pow2_fr = 1;
      for (size_t bit = N - M; bit <= D + N; ++bit) {
        if (this->pb.val(pack_batch_->ret(i, bit)) == Fr(1)) {
          v += pow2_fr.getMpz();
        }
        pow2_fr *= 2;
      }
      this->pb.val(packed_[i]).setMpz(v);
    }

    // 3. Select
    select_batch_->generate_r1cs_witness();
  }

  libsnark::pb_variable<Fr> ret(size_t i) const {
    return select_batch_->ret(i);
  }

  libsnark::pb_variable_array<Fr> ret_array() const {
    return select_batch_->ret();
  }

  size_t size() const { return batch_size_; }

 private:
  size_t batch_size_;
  std::unique_ptr<circuit::pack_batch_gadget> pack_batch_;
  libsnark::pb_variable_array<Fr> packed_;
  std::unique_ptr<circuit::select_batch_gadget> select_batch_;
};

}  // namespace circuit::fixed_point
