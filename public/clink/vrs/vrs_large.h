#pragma once

#include "./vrs_basic.h"

namespace clink {

template <typename Scheme, typename Policy>
struct VrsLarge {
  using R1cs = typename clink::ParallelR1cs<Policy>;
  using HyraxA = typename Policy::HyraxA;
  using ProveInput = typename VrsBasic<Scheme, Policy>::ProveInput;
  using Proof = typename VrsBasic<Scheme, Policy>::Proof;
  using ProveOutput = typename VrsBasic<Scheme, Policy>::ProveOutput;
  using VerifyInput = typename VrsBasic<Scheme, Policy>::VerifyInput;
  using VerifyOutput = typename VrsBasic<Scheme, Policy>::VerifyOutput;

  typedef std::unique_ptr<ProveInput> ProveInputUPtr;
  typedef std::unique_ptr<VerifyInput> VerifyInputUPtr;

  static ProveInput CreateSubProveInput(
      ProveInput const& input, typename VrsPub<Scheme>::Item const& item,
      Fr const& k_com_r, Fr const& vw_com_r) {
    auto sub_get_p = [&input, &item](int64_t j) -> Fr const& {
      return input.get_p(item.begin + j);
    };
    auto sub_get_w = [&input, &item](int64_t j) -> Fr const& {
      return input.get_w(item.begin + j);
    };
    return ProveInput(item.n(), input.k, k_com_r, std::move(sub_get_p),
                      std::move(sub_get_w), vw_com_r, input.gvw);
  }

  static Fr Prove(std::vector<Proof>& proofs, ProveOutput& output, h256_t seed,
                  ProveInput&& input,
                  std::vector<std::vector<G1>>&& cached_var_coms,
                  std::vector<std::vector<Fr>>&& cached_var_coms_r) {
    Tick tick(__FN__);
    assert(cached_var_coms.size() == cached_var_coms_r.size());

    auto items = VrsPub<Scheme>::SplitLargeTask(input.n); //将n以32进行划分
    auto size = (int64_t)items.size();
    std::vector<Fr> vw_com_rs = SplitFr(input.vw_com_r, size);
    std::vector<Fr> k_com_rs(size);

    if (cached_var_coms_r.empty()) {
      k_com_rs = SplitFr(input.k_com_r, size);
    } else {
      assert((int64_t)cached_var_coms_r.size() == size);
      for (int64_t i = 0; i < size; ++i) {
        auto constexpr kPrimaryInputSize = Scheme::kPrimaryInputSize;
        k_com_rs[i] = cached_var_coms_r[i][kPrimaryInputSize];
      }
      assert(std::accumulate(k_com_rs.begin(), k_com_rs.end(), FrZero()) ==
             input.k_com_r);
    }

    proofs.resize(size);
    std::vector<ProveOutput> outputs(size);
    std::vector<Fr> vws(size);
    cached_var_coms.resize(size);
    cached_var_coms_r.resize(size);
    auto parallel_f = [&input, &items, &k_com_rs, &vw_com_rs, &vws, &seed,
                       &proofs, &outputs, &cached_var_coms,
                       &cached_var_coms_r](int64_t i) {
      auto sub_input =
          CreateSubProveInput(input, items[i], k_com_rs[i], vw_com_rs[i]);

      vws[i] = VrsBasic<Scheme, Policy>::Prove(
          proofs[i], outputs[i], seed, std::move(sub_input),
          std::move(cached_var_coms[i]), std::move(cached_var_coms_r[i]));
    };
    parallel::For(size, parallel_f);

    MergeOutputs(output, outputs);

    Fr vw = parallel::Accumulate(vws.begin(), vws.end(), FrZero());

    assert(pc::ComputeCom(input.gvw, vw, input.vw_com_r) ==
           SumProofsComVw(proofs));

    assert(output.h * input.k_com_r + output.g * input.k == output.key_com);

    return vw;
  }

  static VerifyInput CreateSubVerifyInput(
      VerifyInput const& input, typename VrsPub<Scheme>::Item const& item) {
    auto sub_get_p = [&input, &item](int64_t j) -> Fr const& {
      return input.get_p(item.begin + j);
    };
    auto sub_get_w = [&input, &item](int64_t j) -> Fr const& {
      return input.get_w(item.begin + j);
    };
    return VerifyInput(item.n(), std::move(sub_get_p), std::move(sub_get_w),
                       input.gvw);
  }

  static bool Verify(VerifyOutput& output, std::vector<Proof> const& proofs,
                     h256_t seed, VerifyInput&& input) {
    auto items = VrsPub<Scheme>::SplitLargeTask(input.n);
    auto size = (int64_t)items.size();
    if (proofs.size() != items.size()) {
      assert(false);
      return false;
    }

    bool all_success = false;
    std::vector<VerifyOutput> outputs(size);
    auto parallel_f = [&seed, &proofs, &outputs, &input, &items](int64_t i) {
      auto const& item = items[i];
      auto sub_input = CreateSubVerifyInput(input, item);
      return VrsBasic<Scheme, Policy>::Verify(outputs[i], proofs[i], seed,
                                              std::move(sub_input));
    };
    parallel::For(&all_success, size, parallel_f);

    if (!all_success) {
      assert(false);
      return false;
    }

    MergeOutputs(output, outputs);
    return true;
  }

  static G1 SumProofsComVw(std::vector<Proof> const& proofs) {
    return parallel::Accumulate(
        proofs.begin(), proofs.end(), G1Zero(),
        [](G1 const& a, Proof const& b) { return a + b.vw_com; });
  }

  static bool Test(int64_t n);

 private:
  template <typename Output>
  static void MergeOutputs(Output& output, std::vector<Output> const& outputs) {
    output.h = outputs[0].h;
    output.g = parallel::Accumulate(
        outputs.begin(), outputs.end(), G1Zero(),
        [](G1 const& a, Output const& b) { return a + b.g; });
    output.key_com = parallel::Accumulate(
        outputs.begin(), outputs.end(), G1Zero(),
        [](G1 const& a, Output const& b) { return a + b.key_com; });
  }
};

template <typename Scheme, typename Policy>
bool VrsLarge<Scheme, Policy>::Test(int64_t n) {
  Tick tick(__FN__);
  auto seed = misc::RandH256();
  std::vector<Fr> p(n); //明文
  FrRand(p);
  Fr k = FrRand(); //密钥
  Fr k_com_r = FrRand(); //密钥blind
  std::vector<Fr> w(n); //随机数
  FrRand(w);
  Fr vw_com_r = FrRand();
  G1 gvw = pc::PcU();
  std::vector<std::vector<G1>> icached_var_coms;
  std::vector<std::vector<Fr>> icached_var_coms_r;
  ProveInput prove_input(
      n, k, k_com_r, [&p](int64_t i) -> Fr const& { return p[i]; },
      [&w](int64_t i) -> Fr const& { return w[i]; }, vw_com_r, gvw);

  std::vector<Proof> proofs;
  ProveOutput prove_output;
  Prove(proofs, prove_output, seed, std::move(prove_input),
        std::move(icached_var_coms), std::move(icached_var_coms_r));

#ifndef DISABLE_SERIALIZE_CHECK
  // serialize to buffer
  yas::mem_ostream os;
  yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
  oa.serialize(proofs);
  std::cout << "proofs size: " << os.get_shared_buffer().size << "\n";
  // serialize from buffer
  yas::mem_istream is(os.get_intrusive_buffer());
  yas::binary_iarchive<yas::mem_istream, YasBinF()> ia(is);
  std::vector<Proof> proofs2;
  ia.serialize(proofs2);
  if (proofs != proofs2) {
    assert(false);
    std::cout << "oops, serialize check failed\n";
    return false;
  }
#endif

  VerifyInput verify_input(
      n, [&p](int64_t i) -> Fr const& { return p[i]; },
      [&w](int64_t i) -> Fr const& { return w[i]; }, gvw);
  VerifyOutput verify_output;
  bool success = Verify(verify_output, proofs, seed, std::move(verify_input));
  if (success) {
    assert(prove_output.g == verify_output.g);
    assert(prove_output.h == verify_output.h);
    assert(prove_output.key_com == verify_output.key_com);
    success = VrsPub<Scheme>::VerifySecret(prove_output.h, prove_output.g,
                                           prove_output.key_com, k_com_r, k);
  }
  std::cout << __FILE__ << " " << __FN__ << ": " << success << "\n\n\n\n\n\n";
  return success;
}
}  // namespace clink