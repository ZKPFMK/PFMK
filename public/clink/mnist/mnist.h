#pragma once

#include "../details.h"
#include "./demo.h"
#include "circuit/mnist/mnist.h"
#include "argument/a7.h"
#include "argument/a9.h"

// verifiable mnist prediction
extern std::vector<std::vector<Fr>> relu_a;
extern std::vector<std::vector<Fr>> relu_b;
extern std::vector<std::vector<Fr>> relu_c;

namespace clink::mnist {
std::vector<std::vector<Fr>> conv_a, conv_b, conv_c;

struct Mnist {
  struct Para {
    std::array<std::array<Fr, 10>, 5> conv;
    std::array<std::array<Fr, 13 * 13 * 5 + 1>, 10> dense1;
    std::array<std::array<Fr, 10 + 1>, 10> dense2;
  };

  struct ParaCommitmentPub {
    // G1 all;
    std::array<G1, 10> conv;
    std::array<G1, 10> dense1;
    std::array<G1, 10> dense2;
  };

  struct ParaCommitmentSec {
    // Fr all;
    std::array<Fr, 10> conv;
    std::array<Fr, 10> dense1;
    std::array<Fr, 10> dense2;
  };

  static void ComputeParaCom(ParaCommitmentPub& com_pub,
                             ParaCommitmentSec& com_sec, Para const& para) {
    std::array<G1, 5> conv_g1;
    auto parallel_g = [&conv_g1](int64_t i) {
      conv_g1[i] = G1Zero();
      auto const& g = pc::PcG();
      for (size_t j = 0; j < 13 * 13; ++j) {
        conv_g1[i] += g[i + j * 5];
      }
    };
    parallel::For(5, parallel_g);

    //每个卷积核对应位置上的元素进行承诺
    auto parallel_f = [&para, &com_sec, &com_pub, &conv_g1](int64_t i) { //卷积核的第i个位置
      com_sec.conv[i] = FrRand();
      auto get_g = [&conv_g1](size_t j) -> G1 const& {
        return j == 0 ? pc::PcH() : conv_g1[j - 1];
      };
      auto get_f = [&com_sec, i, &para](size_t j) -> Fr const& {
        return j == 0 ? com_sec.conv[i] : para.conv[j - 1][i];
      };
      com_pub.conv[i] = MultiExpBdlo12<G1>(get_g, get_f, 6);

      com_sec.dense1[i] = FrRand();
      com_pub.dense1[i] = pc::ComputeCom(13 * 13 * 5 + 1, para.dense1[i].data(),
                                         com_sec.dense1[i]);

      com_sec.dense2[i] = FrRand();
      com_pub.dense2[i] =
          pc::ComputeCom(10 + 1, para.dense2[i].data(), com_sec.dense2[i]);
    };
    parallel::For(10, parallel_f);
  }

  struct ProveConvInput {
    typedef circuit::mnist::ConvGadget<8, 24, 4, 4, 3, 3> ConvGadget;
    ProveConvInput(std::array<Fr, 28 * 28> const& data, Para const& para,
                   ParaCommitmentPub const& para_com_pub,
                   ParaCommitmentSec const& para_com_sec)
        : data(data),
          para(para),
          para_com_pub(para_com_pub),
          para_com_sec(para_com_sec) {
      namespace fp = circuit::fp;
      libsnark::protoboard<Fr> pb;
      ConvGadget gadget(pb, "Mnist Gadget");

      r1cs_ret_index = gadget.ret().index;  // see protoboard<FieldT>::val
      s = pb.num_variables()+1;
      w.resize(s, std::vector<Fr>(n));

      // public input
      std::array<std::array<Fr, 4 * 4>, n> public_inputs;
      for (size_t k = 0; k < 13 * 13; ++k) {
        auto& view = public_inputs[k * 5];
        size_t i = (k / 13) * 2;
        size_t j = (k % 13) * 2;

        for (size_t v = 0; v < view.size(); ++v) {
          size_t r = v / (3 + 1);
          size_t c = v % (3 + 1);
          view[v] = data[i * 28 + j + r * 28 + c];
        }

        for (size_t ii = 1; ii < 5; ++ii) {
          public_inputs[k * 5 + ii] = view;
        }
      }

      // secret input
      std::array<std::array<Fr, 3 * 3 + 1>, n> secret_inputs;
      for (size_t k = 0; k < 13 * 13; ++k) {
        for (size_t i = 0; i < 5; ++i) {
          secret_inputs[k * 5 + i] = para.conv[i];
        }
      }
      auto parallel_f = [this, &public_inputs, &secret_inputs](size_t j){
        libsnark::protoboard<Fr> pb;
        ConvGadget gadget(pb, "Mnist Gadget");
        gadget.Assign(public_inputs[j], secret_inputs[j]);
        assert(pb.is_satisfied());
        auto v = pb.full_variable_assignment();
        CopyRowToLine(w, v, j, true);
      };
      parallel::For(n, parallel_f);
    }
    std::array<Fr, 28 * 28> const& data;
    Para const& para;
    ParaCommitmentPub const& para_com_pub;
    ParaCommitmentSec const& para_com_sec;
    static int64_t constexpr n = 13 * 13 * 5;
    std::vector<std::vector<Fr>> w;
    size_t s;
    int64_t r1cs_ret_index;
  };

  struct ConvProof {
    argument::A7::Proof r1cs_proof;
    std::vector<G1> com_w;

    bool operator==(ConvProof const& b) const {
      return r1cs_proof == b.r1cs_proof && com_w == b.com_w;
    }

    bool operator!=(ConvProof const& b) const { return !(*this == b); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("conv.p", ("r1cs", r1cs_proof), ("w", com_w));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("conv.p", ("r1cs", r1cs_proof), ("w", com_w));
    }
  };

  struct ProveOutput {
    Fr com_r;
    G1 com;
    std::vector<Fr> data;
  };

  static void ProveConv(ConvProof& proof, ProveOutput& output, h256_t seed,
                        ProveConvInput const& input) {
    Tick tick(__FN__);
    namespace fp = circuit::fp;
    std::vector<G1> com_w(input.s);
    std::vector<Fr> com_w_r(input.s);

    std::cout << "compute com(witness)\n";
    auto parallel_f = [&com_w_r, &com_w, &input](int64_t i) {
      if(i == 0){ //常数1的承诺
        com_w_r[i] = FrZero();
        com_w[i] = pc::ComputeSigmaG(0, input.n);
      }else if (i < 4 * 4 + 1) { //图片的承诺
        com_w_r[i] = FrZero();
        com_w[i] = pc::ComputeCom(input.w[i], com_w_r[i], true);
      } else if (i >= 4 * 4 + 1 && i < 4 * 4 + 3 * 3 + 2) {
        com_w[i] = input.para_com_pub.conv[i - 4 * 4 - 1];
        com_w_r[i] = input.para_com_sec.conv[i - 4 * 4 - 1];
      } else {
        com_w_r[i] = FrRand();
        com_w[i] = pc::ComputeCom(input.w[i], com_w_r[i], true);
      }
    };
    parallel::For<int64_t>(input.s, parallel_f);

    proof.com_w = std::move(com_w);
    UpdateSeed(seed, proof.com_w);

    std::vector<std::vector<Fr>> wa, wb, wc;
    std::vector<Fr> r_com_wa, r_com_wb, r_com_wc;
    ComputeWitness(input.w, conv_a, conv_b, conv_c, wa, wb, wc, com_w_r, r_com_wa, r_com_wb, r_com_wc);
    argument::A7::CommitmentSec a7_sec(r_com_wa, r_com_wb, r_com_wc);
    argument::A7::ProveInput a7_input(wa, wb, wc, pc::kGetRefG1);
    argument::A7::Prove(proof.r1cs_proof, seed, a7_input, a7_sec);

    output.data = input.w[input.r1cs_ret_index];
    output.com_r = com_w_r[input.r1cs_ret_index];
    output.com = proof.com_w[input.r1cs_ret_index];
  }

  struct VerifyConvInput {
    VerifyConvInput(std::array<Fr, 28 * 28> const& data,
                    ParaCommitmentPub const& para_com_pub)
        : data(data), para_com_pub(para_com_pub) {
      typedef circuit::mnist::ConvGadget<8, 24, 4, 4, 3, 3> ConvGadget;
      libsnark::protoboard<Fr> pb;
      ConvGadget gadget(pb, "Mnist Gadget");

      r1cs_ret_index = gadget.ret().index;
      m = pb.num_constraints();
      s = pb.num_variables() + 1;

      // public input
      std::array<std::array<Fr, 4 * 4>, n> public_inputs;
      for (size_t k = 0; k < 13 * 13; ++k) {
        auto& view = public_inputs[k * 5];
        size_t i = (k / 13) * 2;
        size_t j = (k % 13) * 2;

        for (size_t v = 0; v < view.size(); ++v) {
          size_t r = v / (3 + 1);
          size_t c = v % (3 + 1);
          view[v] = data[i * 28 + j + r * 28 + c];
        }

        for (size_t ii = 1; ii < 5; ++ii) {
          public_inputs[k * 5 + ii] = view;
        }
      }

      // public_w
      public_w.resize(17, std::vector<Fr>(n, FrOne()));
      for (size_t k = 0; k < 4 * 4; ++k) {
        for (size_t i = 0; i < n; ++i) {
          public_w[k+1][i] = public_inputs[i][k];
        }
      }
    }
    static constexpr int64_t n = 13 * 13 * 5;
    std::array<Fr, 28 * 28> const& data;
    ParaCommitmentPub const& para_com_pub;
    size_t r1cs_ret_index;
    int64_t m;
    int64_t s;
    std::vector<std::vector<Fr>> public_w;
  };

  static bool VerifyConv(ConvProof const& proof, h256_t seed,
                         VerifyConvInput const& input) {
    Tick tick(__FN__);
    if ((int64_t)proof.com_w.size() != input.s) {
      assert(false);
      return false;
    }

    // Check com of secret input
    for (size_t i = 0; i < 3 * 3 + 1; ++i) {
      if (proof.com_w[i + 4 * 4 + 1] != input.para_com_pub.conv[i]) {
        assert(false);
        return false;
      }
    }

    if(proof.com_w[0] != pc::ComputeSigmaG(0, input.n)) return false;
    for(size_t i=1; i<=16; i++){
      if(proof.com_w[i] != pc::ComputeCom(input.public_w[i], FrZero())){
        assert(false);
        return false;
      }
    }
    UpdateSeed(seed, proof.com_w);

    return argument::A7::Verify(input.n, proof.r1cs_proof, seed, conv_a, conv_b, conv_c, proof.com_w, pc::kGetRefG1);
  }

  template <size_t M, size_t N>
  struct ProveDenseInput {
    ProveDenseInput(std::array<std::array<Fr, M + 1>, N> const& para_dense,
                    std::array<G1, N> const& com_para_dense,
                    std::array<Fr, N> const& com_para_dense_r,
                    ProveOutput&& last_output)
        : para_dense(para_dense),
          com_para_dense(com_para_dense),
          com_para_dense_r(com_para_dense_r),
          com_data_r(last_output.com_r),
          com_data(last_output.com),
          data(std::move(last_output.data)) {
      namespace fp = circuit::fp;
      CHECK(data.size() == M, "");
      this->data.push_back(fp::RationalConst<8, 24>().kFrN);
      this->com_data += pc::PcG(M) * data.back();
    }
    std::array<std::array<Fr, M + 1>, N> const& para_dense;
    std::array<G1, N> const& com_para_dense;
    std::array<Fr, N> const& com_para_dense_r;
    Fr com_data_r;
    G1 com_data;
    std::vector<Fr> data;
  };

  struct DenseProof {
    G1 com;
    argument::A9::Proof sub_proof;

    bool operator==(DenseProof const& b) const {
      return com == b.com && sub_proof == b.sub_proof;
    }

    bool operator!=(DenseProof const& b) const { return !(*this == b); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("d.p", ("c", com), ("p", sub_proof));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("d.p", ("c", com), ("p", sub_proof));
    }
  };

  template <size_t M, size_t N>
  static void ProveDense(DenseProof& proof, ProveOutput& output, h256_t seed,
                         ProveDenseInput<M, N> const& input) {
    Tick tick(__FN__);
    namespace fp = circuit::fp;
    assert(input.para_dense.size() == N);
    assert(input.data.size() == M + 1);

    if (M == 10) {
      std::cout << "data:\n";
      for (auto const& i : input.data) {
        double ret = fp::RationalToDouble<8, 24>(i);
        std::cout << std::right << std::setw(12) << std::setfill(' ') << ret;
      }
      std::cout << "\n";
    }

    // build output
    output.data.resize(N);
    auto parallel_f = [&input, &output](int64_t i) {
      assert(input.para_dense[i].size() == M + 1);
      output.data[i] =
          std::inner_product(input.data.begin(), input.data.end(),
                             input.para_dense[i].begin(), FrZero());
    };
    parallel::For(N, parallel_f);

    output.com_r = FrRand();
    output.com = pc::ComputeCom(output.data, output.com_r);
    proof.com = output.com;

    // prove
    std::vector<Fr> e(N);
    ComputeFst(seed, "Mnist Dense", e);

    std::vector<Fr> w = std::vector<Fr>(input.para_dense[0].begin(), input.para_dense[0].end()) * e[0];
    for(size_t i=1; i<N; i++){
      w += std::vector<Fr>(input.para_dense[i].begin(), input.para_dense[i].end()) * e[i];;
    }

    std::vector<std::vector<Fr>> a = {input.data, output.data};
    std::vector<std::vector<Fr>> b = {w, -e};
    std::vector<Fr> r_com_a = {input.com_data_r, output.com_r};
    std::vector<Fr> r_com_b = {InnerProduct(e.data(), input.com_para_dense_r.data(), e.size()), FrZero()};
    Fr c = 0, r_com_c = 0;
    argument::A9::ProveInput a9_in(a, b, c, pc::kGetRefG1, pc::kGetRefG1(0));
    argument::A9::CommitmentSec a9_sec(r_com_a, r_com_b, r_com_c);
    argument::A9::Prove(proof.sub_proof, seed, a9_in, a9_sec);
  }

  template <size_t M, size_t N>
  struct VerifyDenseInput {
    VerifyDenseInput(G1 const& com_data,
                     std::array<G1, N> const& com_para_dense)
        : com_data(com_data), com_para_dense(com_para_dense) {
      namespace fp = circuit::fp;
      this->com_data += pc::PcG(M) * fp::RationalConst<8, 24>().kFrN;
    }
    G1 com_data;
    std::array<G1, N> const& com_para_dense;
  };

  template <size_t M, size_t N>
  static bool VerifyDense(DenseProof const& proof, h256_t seed,
                          VerifyDenseInput<M, N> const& input) {
    Tick tick(__FN__);

    std::vector<Fr> e(N);
    ComputeFst(seed, "Mnist Dense", e);

    G1 com_w = G1Zero();
    for(size_t i=0; i<N; i++){
      com_w += input.com_para_dense[i] * e[i];
    }
    std::vector<G1> com_a = {input.com_data, proof.com};
    std::vector<G1> com_b = {com_w, -pc::ComputeCom(e, FrZero())};
    G1 com_c = G1Zero();
    argument::A9::CommitmentPub a9_pub(com_a, com_b, com_c);
    argument::A9::VerifyInput a9_in(M+1, a9_pub, pc::kGetRefG1, pc::kGetRefG1(0));
    return argument::A9::Verify(proof.sub_proof, seed, a9_in);
  }

  // the dense output is FixedPoint<D, 2N>
  template <size_t N>
  struct ProveRelu2Input {
    typedef circuit::fixed_point::Relu2Gadget<8, 24 * 2, 24> Relu2Gadget;
    ProveRelu2Input(ProveOutput&& last_output)
        : data(std::move(last_output.data)),
          com(last_output.com),
          com_r(last_output.com_r) {
      namespace fp = circuit::fp;
      assert(data.size() == N);

      libsnark::protoboard<Fr> pb;
      Relu2Gadget gadget(pb, "Mnist Relu2Gadget");
      r1cs_ret_index = gadget.ret().index;  // see protoboard<FieldT>::val
      s = pb.num_variables() + 1;
      w.resize(s, std::vector<Fr>(N));

      auto parallel_f = [this](size_t j){
        libsnark::protoboard<Fr> pb;
        Relu2Gadget gadget(pb, "Mnist Relu2Gadget");
        gadget.Assign(data[j]);
        assert(pb.is_satisfied());
        auto v = pb.full_variable_assignment();
        CopyRowToLine(w, v, j, true);
      };
      parallel::For(N, parallel_f);
    }

    std::vector<Fr> data;
    G1 com;
    Fr com_r;
    int64_t s;
    std::vector<std::vector<Fr>> mutable w;
    int64_t r1cs_ret_index;
  };

  struct Relu2Proof {
    argument::A7::Proof r1cs_proof;
    std::vector<G1> com_w;
    bool operator==(Relu2Proof const& b) const {
      return r1cs_proof == b.r1cs_proof && com_w == b.com_w;
    }

    bool operator!=(Relu2Proof const& b) const { return !(*this == b); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("dr.p", ("r1cs", r1cs_proof), ("w", com_w));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("dr.p", ("r1cs", r1cs_proof), ("w", com_w));
    }
  };

  template <size_t N>
  static void ProveRelu2(Relu2Proof& proof, ProveOutput& output, h256_t seed,
                         ProveRelu2Input<N> const& input) {
    Tick tick(__FN__);
    namespace fp = circuit::fp;
    std::vector<G1> com_w(input.s);
    std::vector<Fr> com_w_r(input.s);

    std::cout << "compute com(witness)\n";
    auto parallel_f = [&com_w_r, &com_w, &input](int64_t i) {
      if(i == 0){ 
        com_w_r[i] = FrZero();
        com_w[i] = pc::ComputeSigmaG(0, input.w[0].size());
      }else if (i == 1) {
        com_w_r[i] = input.com_r;
        com_w[i] = input.com;
      } else {
        com_w_r[i] = FrRand();
        com_w[i] = pc::ComputeCom(input.w[i], com_w_r[i], true);
      }
    };
    parallel::For<int64_t>(input.s, parallel_f);

    // save output for next step
    output.com_r = com_w_r[input.r1cs_ret_index];
    output.com = com_w[input.r1cs_ret_index];
    output.data = input.w[input.r1cs_ret_index];

    proof.com_w = std::move(com_w);
    UpdateSeed(seed, proof.com_w);

    std::vector<std::vector<Fr>> wa, wb, wc;
    std::vector<Fr> r_com_wa, r_com_wb, r_com_wc;
    ComputeWitness(input.w, relu_a, relu_b, relu_c, wa, wb, wc, com_w_r, r_com_wa, r_com_wb, r_com_wc);
    argument::A7::CommitmentSec a7_sec(r_com_wa, r_com_wb, r_com_wc);
    argument::A7::ProveInput a7_input(wa, wb, wc, pc::kGetRefG1);
    argument::A7::Prove(proof.r1cs_proof, seed, a7_input, a7_sec);
  }

  struct VerifyRelu2Input {
    VerifyRelu2Input(G1 const& com) : com(com) {
      typedef circuit::fixed_point::Relu2Gadget<8, 24 * 2, 24> Relu2Gadget;
      libsnark::protoboard<Fr> pb;
      Relu2Gadget gadget(pb, "Mnist Relu2Gadget");
      r1cs_ret_index = gadget.ret().index;
      s = pb.num_variables() + 1;
    }
    static constexpr int64_t n = 10;
    G1 const& com;
    size_t r1cs_ret_index;
    int64_t s;
  };

  static bool VerifyRelu2(Relu2Proof const& proof, h256_t seed,
                          VerifyRelu2Input const& input) {
    Tick tick(__FN__);
    if ((int64_t)proof.com_w.size() != input.s) {
      assert(false);
      return false;
    }

    // Check com of secret input
    if (proof.com_w[1] != input.com && proof.com_w[0] != pc::ComputeSigmaG(0, input.n)) {
      assert(false);
      return false;
    }

    UpdateSeed(seed, proof.com_w);
    return argument::A7::Verify(input.n, proof.r1cs_proof, seed, relu_a, relu_b, relu_c, proof.com_w, pc::kGetRefG1);
  }

  template <typename ProofT>
  static void UpdateSeed(h256_t& seed, ProofT const& proof) {
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    yas::mem_ostream os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
    oa.serialize(proof);
    auto buf = os.get_shared_buffer();
    HashUpdate(hash, buf.data.get(), buf.size);
    hash.Final(seed.data());
  }

  struct Proof {
    ConvProof conv;          // conv,relu,flatten
    DenseProof dense1;       // dense1
    Relu2Proof dense1_relu;  // relu2 for dense1
    DenseProof dense2;       // dense2

    bool operator==(Proof const& b) const {
      return conv == b.conv && dense1 == b.dense1 &&
             dense1_relu == b.dense1_relu && dense2 == b.dense2;
    }

    bool operator!=(Proof const& b) const { return !(*this == b); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("mnist.p", ("c", conv), ("d1", dense1),
                         ("dr", dense1_relu), ("d2", dense2));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("mnist.p", ("c", conv), ("d1", dense1),
                         ("dr", dense1_relu), ("d2", dense2));
    }
  };

  static void Prove(h256_t seed, Proof& proof,
                    std::array<Fr, 28 * 28> const& data, Para const& para,
                    ParaCommitmentPub const& para_com_pub,
                    ParaCommitmentSec const& para_com_sec) {
    Tick tick(__FN__);
    // prove conv
    ProveConvInput conv_input(data, para, para_com_pub, para_com_sec);
    ProveOutput conv_output;
    ProveConv(proof.conv, conv_output, seed, conv_input);
    UpdateSeed(seed, proof.conv);

    // prove dense1
    ProveDenseInput<13 * 13 * 5, 10> dense1_input(
        para.dense1, para_com_pub.dense1, para_com_sec.dense1,
        std::move(conv_output));
    ProveOutput dense1_output;
    ProveDense<13 * 13 * 5, 10>(proof.dense1, dense1_output, seed,
                                dense1_input);
    UpdateSeed(seed, proof.dense1);

    // prove dense1 relu
    ProveRelu2Input<10> dense1_relu_input(std::move(dense1_output));
    ProveOutput dense1_relu_output;
    ProveRelu2<10>(proof.dense1_relu, dense1_relu_output, seed,
                   dense1_relu_input);
    UpdateSeed(seed, proof.dense1_relu);

    // prove dense2
    ProveDenseInput<10, 10> dense2_input(para.dense2, para_com_pub.dense2,
                                         para_com_sec.dense2,
                                         std::move(dense1_relu_output));
    ProveOutput dense2_output;
    ProveDense<10, 10>(proof.dense2, dense2_output, seed, dense2_input);
  }

  static bool Verify(h256_t seed, Proof const& proof,
                     std::array<Fr, 28 * 28> const& data,
                     ParaCommitmentPub const& para_com_pub) {
    Tick tick(__FN__);
    // verify conv
    VerifyConvInput conv_input(data, para_com_pub);
    if (!VerifyConv(proof.conv, seed, conv_input)) {
      assert(false);
      std::cout << "conv verify:false!\n";
      return false;
    }
    UpdateSeed(seed, proof.conv);

    // verify dense1
    VerifyDenseInput<13 * 13 * 5, 10> dense1_input(
        proof.conv.com_w[conv_input.r1cs_ret_index], para_com_pub.dense1);
    if (!VerifyDense<13 * 13 * 5, 10>(proof.dense1, seed, dense1_input)) {
      assert(false);
      return false;
    }
    UpdateSeed(seed, proof.dense1);

    // verify dense1 relu
    VerifyRelu2Input dense1_relu_input(proof.dense1.com);
    if (!VerifyRelu2(proof.dense1_relu, seed, dense1_relu_input)) {
      assert(false);
      return false;
    }
    UpdateSeed(seed, proof.dense1_relu);

    // verify dense2
    VerifyDenseInput<10, 10> dense2_input(
        proof.dense1_relu.com_w[dense1_relu_input.r1cs_ret_index],
        para_com_pub.dense2);
    if (!VerifyDense<10, 10>(proof.dense2, seed, dense2_input)) {
      assert(false);
      return false;
    }

    // now we need to pod the data which commit by proof.dense2.com
    return true;
  }

  static void LoadPara(mnist::dbl::Para const& dbl_para, Para& para) {
    namespace fp = circuit::fp;
    const size_t D = 8, N = 24;
    for (size_t k = 0; k < dbl_para.conv.size(); ++k) {
      for (size_t i = 0; i < 9; ++i) {
        para.conv[k][i] = fp::DoubleToRational<D, N>(dbl_para.conv[k].coef[i]);
      }
      para.conv[k].back() = fp::DoubleToRational<D, N>(dbl_para.conv[k].bias);
    }
    for (size_t k = 0; k < dbl_para.dense1.size(); ++k) {
      for (size_t i = 0; i < 13 * 13 * 5; ++i) {
        para.dense1[k][i] =
            fp::DoubleToRational<D, N>(dbl_para.dense1[k].coef[i]);
      }
      para.dense1[k].back() =
          fp::DoubleToRational<D, N>(dbl_para.dense1[k].bias);
    }
    for (size_t k = 0; k < dbl_para.dense2.size(); ++k) {
      for (size_t i = 0; i < 10; ++i) {
        para.dense2[k][i] =
            fp::DoubleToRational<D, N>(dbl_para.dense2[k].coef[i]);
      }
      para.dense2[k].back() =
          fp::DoubleToRational<D, N>(dbl_para.dense2[k].bias);
    }
  }

  // convert double to fr
  static void LoadImage(mnist::dbl::UniData const& dbl_uni_data,
                        std::array<Fr, 28 * 28>& data) {
    namespace fp = circuit::fp;
    const size_t D = 8, N = 24;
    for (size_t i = 0; i < 28 * 28; ++i) {
      data[i] = fp::DoubleToRational<D, N>(dbl_uni_data[i]);
    }
  }

  static bool Test();

  static bool TestSerialize(Proof const& proof);
};

bool Mnist::TestSerialize(Proof const& proof) {
  {
    yas::mem_ostream os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
    oa.serialize(proof.conv);
    std::cout << "proof conv size: " << os.get_shared_buffer().size << "\n";
  }
  {
    yas::mem_ostream os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
    oa.serialize(proof.dense1);
    std::cout << "proof dense1 size: " << os.get_shared_buffer().size << "\n";
  }
  {
    yas::mem_ostream os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
    oa.serialize(proof.dense1_relu);
    std::cout << "proof dense1_relu size: " << os.get_shared_buffer().size
              << "\n";
  }
  {
    yas::mem_ostream os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
    oa.serialize(proof.dense2);
    std::cout << "proof dense2 size: " << os.get_shared_buffer().size << "\n";
  }

  // serialize to buffer
  yas::mem_ostream os;
  yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
  oa.serialize(proof);
  std::cout << "proof size: " << os.get_shared_buffer().size << "\n";
  // serialize from buffer
  yas::mem_istream is(os.get_intrusive_buffer());
  yas::binary_iarchive<yas::mem_istream, YasBinF()> ia(is);
  Proof proof2;
  ia.serialize(proof2);
  if (proof != proof2) {
    assert(false);
    std::cout << "oops, serialize check failed\n";
    return false;
  }
  return true;
}

bool Mnist::Test() {
  std::unique_ptr<Para> para(new Para);
  LoadPara(mnist::demo::GetDblPara(), *para);

  std::array<Fr, 28 * 28> data;
  LoadImage(mnist::demo::GetDblUniData(), data);

  // compute com of para
  std::unique_ptr<ParaCommitmentPub> para_com_pub(new ParaCommitmentPub);
  std::unique_ptr<ParaCommitmentSec> para_com_sec(new ParaCommitmentSec);
  ComputeParaCom(*para_com_pub, *para_com_sec, *para);

  Tick tick(__FN__);

  auto seed = misc::RandH256();

  Proof proof;
  Prove(seed, proof, data, *para, *para_com_pub, *para_com_sec);
  bool success = Verify(seed, proof, data, *para_com_pub);

#ifndef DISABLE_SERIALIZE_CHECK
  success = success && TestSerialize(proof);
#endif

  std::cout << __FILE__ << " " << __FN__ << ": " << success << "\n\n\n\n\n\n";

  return success;
}
}  // namespace clink