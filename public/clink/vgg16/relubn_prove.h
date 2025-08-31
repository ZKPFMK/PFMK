#pragma once

#include "./relubn_pub.h"

namespace clink::vgg16 {

inline void ReluBnBuildPara(ProveContext const& context, std::vector<Fr>& alpha,
                            std::vector<Fr>& beta, std::vector<Fr>& mu) {
  Tick tick(__FN__);
  for (size_t order = 0; order < kReluBnLayers.size(); ++order) { //第几个ReluBn
    auto layer = kReluBnLayers[order];
    size_t C = kImageInfos[layer].C;
    size_t D = kImageInfos[layer].D;
    size_t DD = D * D;
    auto const& para = context.para().bn_layer(order);
    if (C != para.alpha.size()) throw std::runtime_error("oops");
    for (size_t j = 0; j < DD; ++j) {
        alpha.insert(alpha.end(), para.alpha.begin(), para.alpha.end());
        beta.insert(beta.end(), para.beta.begin(), para.beta.end());
        mu.insert(mu.end(), para.mu.begin(), para.mu.end());
    }
  }
}

inline void ComputeReluBnWitness(ProveContext const& context, std::vector<std::vector<Fr>> & w){
  Tick tick(__FN__);

  std::vector<Fr> in, out;
  ReluBnBuildImages(context, in, out);

  libsnark::protoboard<Fr> pb;
  circuit::vgg16::ReluBnGadget<8, 24> gadget(pb, "vgg16 relubn gadget");

  size_t m = pb.num_variables(), n = in.size();
  
  w.resize(m+1, std::vector<Fr>(n)); //第一行为全1
  std::vector<Fr> alpha, beta, mu;

  alpha.reserve(n);
  beta.reserve(n);
  mu.reserve(n);
  ReluBnBuildPara(context, alpha, beta, mu);

  auto parallel_f = [&w, &alpha, &beta, &mu, &in](size_t j){
    libsnark::protoboard<Fr> pb;
    circuit::vgg16::ReluBnGadget<8, 24> gadget(pb, "vgg16 relubn gadget");
    gadget.Assign(in[j], alpha[j], beta[j], mu[j]);
    auto v = pb.full_variable_assignment();
    CopyRowToLine(w, v, j, true);
  };
  parallel::For(w[0].size(), parallel_f);
}

inline void ComputeReluBnWitCom(R1csSec & r1cs_sec,
                                std::vector<G1> & com_w){
  auto & w = r1cs_sec.w;
  auto & r_com_w = r1cs_sec.r_com_w;

  com_w.resize(w.size() - 6); //0为常量1, 1为image, 2为image, 3为alpha, 4为beta, 5为mu
  r_com_w.resize(w.size() - 6);
  auto parallel_f = [&w, &com_w, &r_com_w](int64_t i) {
    size_t j = i + 6;
    r_com_w[i] = FrRand();
    com_w[i] = pc::ComputeCom(w[j], r_com_w[i]);
  };
  parallel::For(w.size() - 6, parallel_f);
}

inline void DoReluBnProve(h256_t & seed,
                         ReluBnProof & proof,
                         ProveContext const& context,
                         R1csSec const& r1cs_sec,
                         AdaptProveItem & prove_item,
                         std::unique_ptr<argument::A4::ProveInput> & in1,
                         std::unique_ptr<argument::A4::CommitmentSec> & sec1,
                         std::unique_ptr<argument::A4::ProveInput> & in2,
                         std::unique_ptr<argument::A4::CommitmentSec> & sec2){
  Tick tick(__FN__);
  std::vector<std::vector<Fr>> wa, wb, wc;
  std::vector<std::vector<Fr>> const& w = r1cs_sec.w;

  std::vector<Fr> r_com_w(w.size() + 6);
  r_com_w[0] = r_com_w[1] = r_com_w[2] = 0;
  r_com_w[3] = context.para_com_sec().bn.r_com_alpha;
  r_com_w[4] = context.para_com_sec().bn.r_com_beta;
  r_com_w[5] = context.para_com_sec().bn.r_com_mu;
  std::copy(r1cs_sec.r_com_w.begin(), r1cs_sec.r_com_w.end(), r_com_w.begin()+6);

  ComputeWitness(r1cs_sec.w, rlbn_a, rlbn_b, rlbn_c, wa, wb, wc);

  size_t m = wa.size(), n = wa[0].size();
  size_t lm = misc::Log2UB(m), ln = misc::Log2UB(n);
  
  argument::A7::HPProveInput hp_in(wa, wb, wc, pc::kGetRefG1);
  argument::A7::HPProveOutput hp_out;
  argument::A7::Prove(seed, hp_in, hp_out);

  size_t len = (kReluBnLayers.size()<<1) + 1;
  std::vector<Fr> r_com_a1(len), r_com_a2(len);
  std::vector<std::vector<Fr>> a1(len), b1(len);
  std::vector<std::vector<Fr>> a2(len), b2(len);

  auto c1 = hp_out.a, c2 = hp_out.b;
  auto const& r_com_c1 = hp_out.r_com_a;
  auto const& r_com_c2 = hp_out.r_com_b;
  auto const& r1 = hp_out.sl_hat_l, &r2 = hp_out.sl_hat_r, & r3 = hp_out.sr_hat;
  auto const& s1 = hp_out.sl_chk_l, &s2 = hp_out.sl_chk_r, & s3 = hp_out.sr_chk;

  Fr ra1 = InnerProduct(r1, rlbn_a, 1) + InnerProduct(r2, rlbn_c, 1);
  Fr ra2 = InnerProduct(r1, rlbn_a, 2) + InnerProduct(r2, rlbn_c, 2);
  std::vector<Fr> u1 = r3 * ra1;
  std::vector<Fr> u2 = r3 * ra2;

  Fr sb1 = InnerProduct(s1, rlbn_b, 1);
  Fr sb2 = InnerProduct(s1, rlbn_b, 2);
  std::vector<Fr> v1 = s3 * sb1;
  std::vector<Fr> v2 = s3 * sb2;

  auto j1 = u1.begin(), j2 = u2.begin(), j3 = v1.begin(), j4 = v2.begin();
  for(size_t i=0, k1=0, k2=0; i<kReluBnLayers.size(); i++, j1+=k1, j2+=k2, j3+=k1, j4+=k2){
    auto const& in = context.const_images()[kReluBnLayers[i]]->data;
    auto const& out = context.const_images()[kReluBnLayers[i]+1]->data;
    auto const& r_com_in = context.image_com_sec().r_com_x[kReluBnLayers[i]];
    auto const& r_com_out = context.image_com_sec().r_com_x[kReluBnLayers[i]+1];

    size_t i1 = i <<  1, i2 = i1 + 1;
    k1 = in.size();
    k2 = out.size();

    a1[i1] = in;
    a1[i2] = out;
    r_com_a1[i1] = r_com_in;
    r_com_a1[i2] = r_com_out;
    b1[i1] = std::vector<Fr>(j1, j1 + k1);
    b1[i2] = std::vector<Fr>(j2, j2 + k2);

    a2[i1] = in;
    a2[i2] = out;
    r_com_a2[i1] = r_com_in;
    r_com_a2[i2] = r_com_out;
    b2[i1] = std::vector<Fr>(j3, j3 + k1);
    b2[i2] = std::vector<Fr>(j4, j4 + k2);
  }

  len--;
  b1[len] = r3;
  a1[len] = MatrixVectorMul(r1, wa) + MatrixVectorMul(r2, wc) - w[1] * ra1 - w[2] * ra2;
  r_com_a1[len] = InnerProduct(MatrixVectorMul(r1, rlbn_a)+MatrixVectorMul(r2, rlbn_c), r_com_w);

  b2[len] = s3;
  a2[len] = MatrixVectorMul(s1, wb) - w[1] * sb1 - w[2] * sb2;
  r_com_a2[len] = InnerProduct(MatrixVectorMul(s1, rlbn_b), r_com_w);

  c2 += Sum(s2) * Sum(s3);
  assert(InnerProduct(a1, b1) == c1);
  assert(InnerProduct(a2, b2) == c2);

  sec1 = std::make_unique<argument::A4::CommitmentSec>(r_com_a1, r_com_c1);
  in1 = std::make_unique<argument::A4::ProveInput>(a1, b1, c1, pc::kGetRefG1, pc::kGetRefG1(0));

  sec2 = std::make_unique<argument::A4::CommitmentSec>(r_com_a2, r_com_c2);
  in2 = std::make_unique<argument::A4::ProveInput>(a2, b2, c2, pc::kGetRefG1, pc::kGetRefG1(0));

  proof.com_t0 = std::move(hp_out.com_t0);
  proof.com_t2 = std::move(hp_out.com_t2);
  proof.com_ab = std::move(hp_out.com_ab);
  proof.sm_proof = std::move(hp_out.sm_proof);
}

inline void ReluBnProve(h256_t seed,
                        ProveContext const& context,
                        ReluBnProof & proof,
                        AdaptProveItem & prove_item,
                        std::unique_ptr<argument::A4::ProveInput> & in1,
                        std::unique_ptr<argument::A4::CommitmentSec> & sec1,
                        std::unique_ptr<argument::A4::ProveInput> & in2,
                        std::unique_ptr<argument::A4::CommitmentSec> & sec2) {
  Tick tick(__FN__);

  R1csSec r1cs_sec;
  
  ComputeReluBnWitness(context, r1cs_sec.w);

  ComputeReluBnWitCom(r1cs_sec, proof.com_w);
  
  UpdateSeed(seed, proof.com_w);
  
  DoReluBnProve(seed, proof, context, r1cs_sec, prove_item, in1, sec1, in2, sec2);
}

inline bool ReluBnVerify(h256_t seed,
                         VerifyContext const& context,
                         ReluBnProof const& proof,
                         AdaptVerifyItem & item) {
  Tick tick(__FN__);

  size_t m = rlbn_a.size(), n = 0;
  for(size_t i=0; i<kBnLayerInfos.size(); i++){
    n += kImageInfos[kReluBnLayers[i]].size();
  }

  UpdateSeed(seed, proof.com_w);

  bool ret = false;
  std::vector<G1> com_w(proof.com_w.size()+6);
  com_w[0] = pc::ComputeSigmaG(pc::kGetRefG1, n);
  com_w[1] = com_w[2] = G1Zero();
  com_w[3] = context.para_com_pub().bn.com_alpha;
  com_w[4] = context.para_com_pub().bn.com_beta;
  com_w[5] = context.para_com_pub().bn.com_mu;
  std::copy(proof.com_w.begin(), proof.com_w.end(), com_w.begin()+6);

  argument::A7::HPVerifyOutput hp_out;
  argument::A7::HPVerifyInput hp_in(m, n, proof.com_t0, proof.com_t2);
  argument::A7::Verify(seed, hp_in, hp_out);

  G1 com_c1 = proof.com_ab[0], com_c2 = proof.com_ab[1];
  argument::A1::CommitmentPub a1_pub(com_c1, com_c2, hp_out.com_c);
  argument::A1::VerifyInput a1_in(a1_pub);
  ret = argument::A1::Verify(proof.sm_proof, seed, a1_in);

  auto const& r1 = hp_out.sl_hat_l, &r2 = hp_out.sl_hat_r, & r3 = hp_out.sr_hat;
  auto const& s1 = hp_out.sl_chk_l, &s2 = hp_out.sl_chk_r, & s3 = hp_out.sr_chk;

  size_t len = (kReluBnLayers.size()<<1) + 1;
  std::vector<G1> com_a1(len), com_a2(len);
  std::vector<std::vector<Fr>> b1(len), b2(len);

  Fr ra1 = InnerProduct(r1, rlbn_a, 1) + InnerProduct(r2, rlbn_c, 1);
  Fr ra2 = InnerProduct(r1, rlbn_a, 2) + InnerProduct(r2, rlbn_c, 2);
  std::vector<Fr> u1 = r3 * ra1;
  std::vector<Fr> u2 = r3 * ra2;

  Fr sb1 = InnerProduct(s1, rlbn_b, 1);
  Fr sb2 = InnerProduct(s1, rlbn_b, 2);
  std::vector<Fr> v1 = s3 * sb1;
  std::vector<Fr> v2 = s3 * sb2;

 auto j1 = u1.begin(), j2 = u2.begin(), j3 = v1.begin(), j4 = v2.begin();
  for(size_t i=0, k1=0, k2=0; i<kReluBnLayers.size(); i++, j1+=k1, j2+=k2, j3+=k1, j4+=k2){
    auto const& in = context.const_images()[kReluBnLayers[i]]->data;
    auto const& out = context.const_images()[kReluBnLayers[i]+1]->data;
    auto const& com_in = context.image_com_pub().com_x[kReluBnLayers[i]];
    auto const& com_out = context.image_com_pub().com_x[kReluBnLayers[i]+1];

    size_t i1 = i <<  1, i2 = i1 + 1;
    k1 = in.size();
    k2 = out.size();

    com_a1[i1] = com_in;
    com_a1[i2] = com_out;
    b1[i1] = std::vector<Fr>(j1, j1 + k1);
    b1[i2] = std::vector<Fr>(j2, j2 + k2);

    com_a2[i1] = com_in;
    com_a2[i2] = com_out;
    b2[i2] = std::vector<Fr>(j3, j3 + k1);
    b2[i2] = std::vector<Fr>(j4, j4 + k2);
  }

  len--;
  b1[len] = r3;
  com_a1[len] = MultiExpBdlo12(com_w, MatrixVectorMul(r1, rlbn_a) + MatrixVectorMul(r2, rlbn_c));
  
  b2[len] = s3;
  com_a2[len] = MultiExpBdlo12(com_w, MatrixVectorMul(s1, rlbn_b));

  com_c2 += pc::kGetRefG1(0) * (Sum(s2) * Sum(s3));
  
  argument::A4::CommitmentPub a4_pub1(com_a1, com_c1);
  item.in[2] = std::make_unique<argument::A4::VerifyInput>(b1, a4_pub1, pc::kGetRefG1, pc::kGetRefG1(0));

  argument::A4::CommitmentPub a4_pub2(com_a2, com_c2);
  item.in[3] = std::make_unique<argument::A4::VerifyInput>(b2, a4_pub2, pc::kGetRefG1, pc::kGetRefG1(0));
  return ret;
}
};  // namespace clink::vgg16