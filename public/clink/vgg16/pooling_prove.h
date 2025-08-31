#pragma once
#
#include "./pooling_pub.h"

namespace clink::vgg16 {
  
inline void ComputePoolingWitness(ProveContext const& context,
                                  std::vector<std::vector<Fr>> & w){
  Tick tick(__FN__);

  libsnark::protoboard<Fr> pb; 
  circuit::vgg16::PoolingGadget<8, 24> gadget(pb, "vgg16 pooling gadget");
  
  w.resize(4);
  PoolingImageToAbcd(context, w[0], w[1], w[2], w[3]);

  size_t m = pb.num_variables(), n = w[0].size();
  w.resize(m+1, std::vector<Fr>(n));
  
  auto parallel_f = [&w](size_t j){
    libsnark::protoboard<Fr> pb; 
    circuit::vgg16::PoolingGadget<8, 24> gadget(pb, "vgg16 pooling gadget");
    std::array<Fr const*, 4> data = {&w[0][j], &w[1][j], &w[2][j], &w[3][j]};
    gadget.Assign(data);
    auto v = pb.full_variable_assignment();
    CopyRowToLine(w, v, j, true);
  };
  parallel::For(w[0].size(), parallel_f);

  if(DEBUG_CHECK){;
    auto j = w[5].begin();
    for(size_t i=0, k=0; i<kPoolingLayers.size(); i++, j+=k){
      std::vector<Fr> out = context.const_images()[kPoolingLayers[i]+1]->data;
      k = out.size();
      assert(std::vector<Fr>(j, j+k) == out);
    }
  }
  
}

inline void ComputePoolingWitCom(R1csSec & r1cs_sec,
                                 std::vector<G1> & com_w){
  auto & w = r1cs_sec.w;
  auto & r_com_w = r1cs_sec.r_com_w;

  com_w.resize(w.size() - 6); //0为常量1, 1-4为image, 5为image
  r_com_w.resize(w.size() - 6);
  auto parallel_f = [&w, &com_w, &r_com_w](int64_t i) {
    size_t j = i + 6;
    r_com_w[i] = FrRand();
    com_w[i] = pc::ComputeCom(w[j], r_com_w[i]);
  };
  parallel::For(w.size() - 6, parallel_f);
}

inline void DoPoolingProve(h256_t & seed,
                          PoolingProof & proof,
                          ProveContext const& context,
                          R1csSec const& r1cs_sec,
                          std::unique_ptr<argument::A4::ProveInput> & in1,
                          std::unique_ptr<argument::A4::CommitmentSec> & sec1,
                          std::unique_ptr<argument::A4::ProveInput> & in2,
                          std::unique_ptr<argument::A4::CommitmentSec> & sec2) {
  Tick tick(__FN__);

  std::vector<std::vector<Fr>> wa, wb, wc;
  std::vector<std::vector<Fr>> const& w = r1cs_sec.w;

  std::vector<Fr> r_com_w(w.size() + 6);
  r_com_w[0] = r_com_w[1] = r_com_w[2] = r_com_w[3] = r_com_w[4] = r_com_w[5] = 0;
  std::copy(r1cs_sec.r_com_w.begin(), r1cs_sec.r_com_w.end(), r_com_w.begin()+6);

  ComputeWitness(r1cs_sec.w, pool_a, pool_b, pool_c, wa, wb, wc);

  size_t m = wa.size(), n = wa[0].size();
  size_t lm = misc::Log2UB(m), ln = misc::Log2UB(n);

  argument::A7::HPProveInput hp_in(wa, wb, wc, pc::kGetRefG1);
  argument::A7::HPProveOutput hp_out;
  argument::A7::Prove(seed, hp_in, hp_out);

  size_t len = (kPoolingLayers.size()<<1) + 1;
  std::vector<Fr> r_com_a1(len), r_com_a2(len);
  std::vector<std::vector<Fr>> a1(len), b1(len);
  std::vector<std::vector<Fr>> a2(len), b2(len);

  auto c1 = hp_out.a, c2 = hp_out.b;
  auto const& r_com_c1 = hp_out.r_com_a;
  auto const& r_com_c2 = hp_out.r_com_b;
  auto const& r1 = hp_out.sl_hat_l, &r2 = hp_out.sl_hat_r, & r3 = hp_out.sr_hat;
  auto const& s1 = hp_out.sl_chk_l, &s2 = hp_out.sl_chk_r, & s3 = hp_out.sr_chk;

  Fr ra1 = InnerProduct(r1, pool_a, 1) + InnerProduct(r2, pool_c, 1);
  Fr ra2 = InnerProduct(r1, pool_a, 2) + InnerProduct(r2, pool_c, 2);
  Fr ra3 = InnerProduct(r1, pool_a, 3) + InnerProduct(r2, pool_c, 3);
  Fr ra4 = InnerProduct(r1, pool_a, 4) + InnerProduct(r2, pool_c, 4);
  Fr ra5 = InnerProduct(r1, pool_a, 5) + InnerProduct(r2, pool_c, 5);
  std::vector<Fr> u1 = r3 * ra1;
  std::vector<Fr> u2 = r3 * ra2;
  std::vector<Fr> u3 = r3 * ra3;
  std::vector<Fr> u4 = r3 * ra4;
  std::vector<Fr> u_out = r3 * ra5;
  std::vector<std::vector<Fr>> u_in;
  PoolingAbcdToData(u1, u2, u3, u4, u_in);

  Fr sb1 = InnerProduct(s1, pool_b, 1);
  Fr sb2 = InnerProduct(s1, pool_b, 2);
  Fr sb3 = InnerProduct(s1, pool_b, 3);
  Fr sb4 = InnerProduct(s1, pool_b, 4);
  Fr sb5 = InnerProduct(s1, pool_b, 5);
  std::vector<Fr> v1 = s3 * sb1;
  std::vector<Fr> v2 = s3 * sb2;
  std::vector<Fr> v3 = s3 * sb3;
  std::vector<Fr> v4 = s3 * sb4;
  std::vector<Fr> v5 = s3 * sb5;
  std::vector<Fr> v_out = s3 * sb5;
  std::vector<std::vector<Fr>> v_in;
  PoolingAbcdToData(v1, v2, v3, v4, v_in);

  auto j1 = u_out.begin(), j2 = v_out.begin();
  for(size_t i=0, k=0; i<kPoolingLayers.size(); i++, j1+=k, j2+=k){
    auto const& in = context.const_images()[kPoolingLayers[i]]->data;
    auto const& out = context.const_images()[kPoolingLayers[i]+1]->data;
    auto const& r_com_in = context.image_com_sec().r_com_x[kPoolingLayers[i]];
    auto const& r_com_out = context.image_com_sec().r_com_x[kPoolingLayers[i]+1];

    size_t i1 = i <<  1, i2 = i1 + 1;
    k = out.size();

    a1[i1] = in;
    a1[i2] = out;
    r_com_a1[i1] = r_com_in;
    r_com_a1[i2] = r_com_out;
    b1[i1] = u_in[i];
    b1[i2] = std::vector<Fr>(j1, j1 + k);

    a2[i1] = in;
    a2[i2] = out;
    r_com_a2[i1] = r_com_in;
    r_com_a2[i2] = r_com_out;
    b2[i1] = v_in[i];
    b2[i2] = std::vector<Fr>(j2, j2 + k);
  }

  len--;
  b1[len] = r3;
  a1[len] = MatrixVectorMul(r1, wa) + MatrixVectorMul(r2, wc) - w[1] * ra1 - w[2] * ra2 - w[3] * ra3 - w[4] * ra4 - w[5] * ra5;
  r_com_a1[len] = InnerProduct(MatrixVectorMul(r1, pool_a)+MatrixVectorMul(r2, pool_c), r_com_w);

  b2[len] = s3;
  a2[len] = MatrixVectorMul(s1, wb) - w[1] * sb1 - w[2] * sb2 - w[3] * sb3 - w[4] * sb4 - w[5] * sb5;
  r_com_a2[len] = InnerProduct(MatrixVectorMul(s1, pool_b), r_com_w);

  c2 += Sum(s2) * Sum(s3);
  assert(c1 == InnerProduct(a1, b1));
  assert(c2 == InnerProduct(a2, b2));

  sec1 = std::make_unique<argument::A4::CommitmentSec>(r_com_a1, r_com_c1);
  in1 = std::make_unique<argument::A4::ProveInput>(a1, b1, c1, pc::kGetRefG1, pc::kGetRefG1(0));

  sec2 = std::make_unique<argument::A4::CommitmentSec>(r_com_a2, r_com_c2);
  in2 = std::make_unique<argument::A4::ProveInput>(a2, b2, c2, pc::kGetRefG1, pc::kGetRefG1(0));

  proof.com_t0 = std::move(hp_out.com_t0);
  proof.com_t2 = std::move(hp_out.com_t2);
  proof.com_ab = std::move(hp_out.com_ab);
  proof.sm_proof = std::move(hp_out.sm_proof);
}

inline void PoolingProve(h256_t seed,
                        ProveContext const& context,
                        PoolingProof& proof,
                        std::unique_ptr<argument::A4::ProveInput> & in1,
                        std::unique_ptr<argument::A4::CommitmentSec> & sec1,
                        std::unique_ptr<argument::A4::ProveInput> & in2,
                        std::unique_ptr<argument::A4::CommitmentSec> & sec2) {
  Tick tick(__FN__);

  R1csSec r1cs_sec;

  ComputePoolingWitness(context, r1cs_sec.w);

  ComputePoolingWitCom(r1cs_sec, proof.com_w);

  UpdateSeed(seed, proof.com_w);

  DoPoolingProve(seed, proof, context, r1cs_sec, in1, sec1, in2, sec2);
}

inline bool PoolingVerify(h256_t seed,
                          VerifyContext const& context,
                          PoolingProof const& proof,
                          AdaptVerifyItem & item) {
  Tick tick(__FN__);

  size_t m = pool_a.size(), n = 0;
  for(size_t i=0; i<kPoolingLayers.size(); i++){
    n += kImageInfos[kPoolingLayers[i]].size();
  }
  n /= 4;

  UpdateSeed(seed, proof.com_w);

  bool ret = false;
  std::vector<G1> com_w(proof.com_w.size()+6);
  com_w[0] = pc::ComputeSigmaG(pc::kGetRefG1, n);
  com_w[1] = com_w[2] = com_w[3] = com_w[4] = com_w[5] = G1Zero();
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

  size_t len = (kPoolingLayers.size()<<1) + 1;
  std::vector<G1> com_a1(len), com_a2(len);
  std::vector<std::vector<Fr>> b1(len), b2(len);

  Fr ra1 = InnerProduct(r1, pool_a, 1) + InnerProduct(r2, pool_c, 1);
  Fr ra2 = InnerProduct(r1, pool_a, 2) + InnerProduct(r2, pool_c, 2);
  Fr ra3 = InnerProduct(r1, pool_a, 3) + InnerProduct(r2, pool_c, 3);
  Fr ra4 = InnerProduct(r1, pool_a, 4) + InnerProduct(r2, pool_c, 4);
  Fr ra5 = InnerProduct(r1, pool_a, 5) + InnerProduct(r2, pool_c, 5);
  std::vector<Fr> u1 = r3 * ra1;
  std::vector<Fr> u2 = r3 * ra2;
  std::vector<Fr> u3 = r3 * ra3;
  std::vector<Fr> u4 = r3 * ra4;
  std::vector<Fr> u_out = r3 * ra5;
  std::vector<std::vector<Fr>> u_in;
  PoolingAbcdToData(u1, u2, u3, u4, u_in);

  Fr sb1 = InnerProduct(s1, pool_b, 1);
  Fr sb2 = InnerProduct(s1, pool_b, 2);
  Fr sb3 = InnerProduct(s1, pool_b, 3);
  Fr sb4 = InnerProduct(s1, pool_b, 4);
  Fr sb5 = InnerProduct(s1, pool_b, 5);
  std::vector<Fr> v1 = s3 * sb1;
  std::vector<Fr> v2 = s3 * sb2;
  std::vector<Fr> v3 = s3 * sb3;
  std::vector<Fr> v4 = s3 * sb4;
  std::vector<Fr> v5 = s3 * sb5;
  std::vector<Fr> v_out = s3 * sb5;
  std::vector<std::vector<Fr>> v_in;
  PoolingAbcdToData(v1, v2, v3, v4, v_in);

  auto j1 = u_out.begin(), j2 = v_out.begin();
  for(size_t i=0, k=0; i<kPoolingLayers.size(); i++, j1+=k, j2+=k){
    auto const& com_in = context.image_com_pub().com_x[kPoolingLayers[i]];
    auto const& com_out = context.image_com_pub().com_x[kPoolingLayers[i]+1];

    size_t i1 = i <<  1, i2 = i1 + 1;
    k = kImageInfos[kPoolingLayers[i]+1].size();
    
    com_a1[i1] = com_in;
    com_a1[i2] = com_out;
    b1[i1] = u_in[i];
    b1[i2] = std::vector<Fr>(j1, j1 + k);

    com_a2[i1] = com_in;
    com_a2[i2] = com_out;
    b2[i1] = v_in[i];
    b2[i2] = std::vector<Fr>(j2, j2 + k);
  }

  len--;
  b1[len] = r3;
  com_a1[len] = MultiExpBdlo12(com_w, MatrixVectorMul(r1, pool_a)+MatrixVectorMul(r2, pool_c));

  b2[len] = s3;
  com_a2[len] = MultiExpBdlo12(com_w, MatrixVectorMul(s1, pool_b));

  com_c2 += pc::kGetRefG1(0) * Sum(s2) * Sum(s3);

  argument::A4::CommitmentPub a4_pub1(com_a1, com_c1);
  item.in[4] = std::make_unique<argument::A4::VerifyInput>(b1, a4_pub1, pc::kGetRefG1, pc::kGetRefG1(0));

  argument::A4::CommitmentPub a4_pub2(com_a2, com_c2);
  item.in[5] = std::make_unique<argument::A4::VerifyInput>(b2, a4_pub2, pc::kGetRefG1, pc::kGetRefG1(0));

  return ret;
}

}  // namespace clink::vgg16