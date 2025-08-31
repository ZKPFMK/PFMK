#pragma once

#include "./conv_pub.h"

namespace clink::vgg16 {

/**
 * a1: (conv输入 + conv输出)_{i=1}^13 + bias
 * a2: coef
 * 
 */
inline void PrepareConvAdaptItem(ProveContext const& context,
                                  std::vector<std::vector<Fr>> const& rx_rw_hat,
                                  std::vector<Fr> const& e,
                                  std::vector<std::vector<Fr>> & a1,
                                  std::vector<std::vector<Fr>> & b1,
                                  std::vector<std::vector<Fr>> & b2,
                                  std::vector<Fr> & r_com_a1){
  Tick tick(__FN__);

  a1.resize(kConvLayers.size() * 3);
  b1.resize(kConvLayers.size() * 3); 
  b2.resize(kConvLayers.size() << 1);
  r_com_a1.resize(kConvLayers.size() * 3);
 
  std::vector<Fr> e_hat = misc::BuildE(e);
  std::vector<Fr> e_chk(e_hat.rbegin(), e_hat.rend());
  std::vector<std::vector<Fr>> e_hat_seg1(kConvLayers.size()), e_hat_seg2(kConvLayers.size());
  std::vector<std::vector<Fr>> e_chk_seg1(kConvLayers.size()), e_chk_seg2(kConvLayers.size());

  auto j1 = e_hat.begin();
  auto j2 = e_chk.begin();
  for(size_t i=0, k=0; i<kConvLayers.size(); i++, j1+=k, j2+=k){
    k = context.const_images()[kConvLayers[i]]->matrix[0].size();
    e_hat_seg1[i] = std::vector<Fr>(j1, j1 + k);
    e_chk_seg1[i] = std::vector<Fr>(j2, j2 + k);
  }

  for(size_t i=0, k=0; i<kConvLayers.size(); i++, j1+=k, j2+=k){
    k = context.para().conv_layer(i).bias.size();
    e_hat_seg2[i] = std::vector<Fr>(j1, j1 + k);
    e_chk_seg2[i] = std::vector<Fr>(j2, j2 + k);
  }

  auto parallel_f = [&context, &rx_rw_hat, &e_hat, &a1, &b1, &b2, &r_com_a1, &e_hat_seg1, &e_hat_seg2, &e_chk_seg1, &e_chk_seg2](size_t i){
    auto const& bias = context.para().conv_layer(i).bias;
    auto const& in_img = *context.const_images()[kConvLayers[i]];
    auto const& out_img = *context.const_images()[kConvLayers[i]+1];
    auto const& r_com_bias = context.para_com_sec().conv.r_com_bias[i];
    auto const& r_com_in = context.image_com_sec().r_com_x[kConvLayers[i]];
    auto const& r_com_out = context.image_com_sec().r_com_x[kConvLayers[i]+1];

    size_t m = in_img.matrix.size();
    size_t k = in_img.matrix[0].size();

    std::vector<Fr> const&l = rx_rw_hat[i];
    std::vector<Fr> const&r = e_hat_seg1[i];
    
    std::vector<std::vector<Fr>> lr;
    OuterProduct(l, r, lr);

    a1[i << 1] = in_img.data;
    a1[(i << 1)+1] = out_img.data;
    a1[i + (kConvLayers.size() << 1)] = bias;

    b1[i << 1] = in_img.rev_transform(lr);
    OuterProduct(-l, e_hat_seg2[i], b1[(i << 1)+1]);
    b1[i + (kConvLayers.size() << 1)] = e_hat_seg2[i] * Sum(l);

    r_com_a1[i << 1] = r_com_in;
    r_com_a1[(i << 1) + 1] = r_com_out;
    r_com_a1[i + (kConvLayers.size() << 1)] = r_com_bias;

    b2[i] = e_chk_seg1[i];
    b2[i + kConvLayers.size()] = e_chk_seg2[i];
  };
  parallel::For(kConvLayers.size(), parallel_f);
}

inline void PrepareConvAdaptItem(VerifyContext const& context,
                                  std::vector<std::vector<Fr>> const& rx_rw_hat,
                                  std::vector<Fr> const& ry_hat,
                                  std::vector<Fr> const& e,
                                  std::vector<G1> & com_a1,
                                  std::vector<std::vector<Fr>> & b1,
                                  std::vector<G1> & com_a2,
                                  std::vector<std::vector<Fr>> & b2,
                                  G1 & com_t1, G1 & com_t2){
  Tick tick(__FN__);

  com_a1.resize(kConvLayers.size() * 3);
  com_a2.resize(kConvLayers.size());

  b1.resize(kConvLayers.size() * 3); 
  b2.resize(kConvLayers.size());

  Fr t1 = 0, t2 = 0;
 
  std::vector<Fr> e_hat = misc::BuildE(e);
  std::vector<Fr> e_chk(e_hat.rbegin(), e_hat.rend());
  std::vector<std::vector<Fr>> e_hat_seg1(kConvLayers.size()), e_hat_seg2(kConvLayers.size());
  std::vector<std::vector<Fr>> e_chk_seg1(kConvLayers.size()), e_chk_seg2(kConvLayers.size());

  auto j1 = e_hat.begin();
  auto j2 = e_chk.begin();
  for(size_t i=0, k=0; i<kConvLayers.size(); i++, j1+=k, j2+=k){
    k = kConvLayerInfos[i].C * 9;
    e_hat_seg1[i] = std::vector<Fr>(j1, j1 + k);
    e_chk_seg1[i] = std::vector<Fr>(j2, j2 + k);
  }

  for(size_t i=0, k=0; i<kConvLayers.size(); i++, j1+=k, j2+=k){
    k = kConvLayerInfos[i].K;
    e_hat_seg2[i] = std::vector<Fr>(j1, j1 + k);
    e_chk_seg2[i] = std::vector<Fr>(j2, j2 + k);
  }

  auto parallel_f = [&context, &rx_rw_hat, &ry_hat, &e_hat, &com_a1, &b1, &t1, &com_a2, &b2, &t2, &e_hat_seg1, &e_hat_seg2, &e_chk_seg1, &e_chk_seg2](size_t i){
    auto const& com_bias = context.para_com_pub().conv.com_bias[i];
    auto const& com_coef = context.para_com_pub().conv.com_coef[i];
    auto const& com_in = context.image_com_pub().com_x[kConvLayers[i]];
    auto const& com_out = context.image_com_pub().com_x[kConvLayers[i]+1];

    std::vector<Fr> const&l = rx_rw_hat[i];
    std::vector<Fr> const&r = e_hat_seg1[i];
    
    std::vector<std::vector<Fr>> lr;
    OuterProduct(l, r, lr);

    com_a1[i << 1] = com_in;
    com_a1[(i << 1)+1] = com_out;
    com_a1[i + (kConvLayers.size() << 1)] = com_bias;

    b1[i << 1] = context.const_images()[kConvLayers[i]]->rev_transform(lr);
    OuterProduct(-l, e_hat_seg2[i], b1[(i << 1)+1]);
    b1[i + (kConvLayers.size() << 1)] = e_hat_seg2[i] * Sum(l);

    com_a2[i] = MultiExpBdlo12(com_coef, ry_hat);
    b2[i] = e_chk_seg1[i];

    t2 += InnerProduct(ry_hat, e_chk_seg2[i]);
  };
  parallel::For(kConvLayers.size(), parallel_f, true);

  t1 += InnerProduct(context.const_images()[0]->data, b1[0]);
  com_a1.erase(com_a1.begin());
  b1.erase(b1.begin());

  com_t1 -= pc::kGetRefG1(0) * t1;
  com_t2 -= pc::kGetRefG1(0) * t2;
}

inline void PrepareConvIPInput(ProveContext const& context,
                                 std::vector<std::vector<Fr>> const& rx_rw_hat,
                                 std::vector<Fr> const& ry_hat,
                                 std::vector<Fr> & a,
                                 std::vector<Fr> & b,
                                 std::vector<std::vector<Fr>> & u,
                                 std::vector<Fr> & r_com_u){
  Tick tick(__FN__);
  u.resize(kConvLayers.size() << 1);
  r_com_u.resize(kConvLayers.size() << 1);
  std::vector<std::vector<Fr>> a1(kConvLayers.size()), a2(kConvLayers.size());
  std::vector<std::vector<Fr>> b1(kConvLayers.size()), b2(kConvLayers.size());
  auto parallel_f = [&context, &rx_rw_hat, &ry_hat, &a1, &a2, &b1, &b2, &u, &r_com_u](size_t i){
    auto const& w3 = context.para().conv_layer(i).bias;
    auto const& w2 = context.para().conv_layer(i).coefs;
    auto const& w1 = context.const_images()[kConvLayers[i]]->matrix;   //二维
    auto const& w4 = context.const_images()[kConvLayers[i] + 1]->reshape();
    auto const& r_com_w2 = context.para_com_sec().conv.r_com_coef[i];

    size_t m = w1.size(), k = w1[0].size(), n = w2[0].size();

    std::vector<Fr> const&l = rx_rw_hat[i];
    std::vector<Fr> r(ry_hat.begin(), ry_hat.begin()+n);

    a1[i] = MatrixVectorMul(l, w1);
    b1[i] = MatrixVectorMul(w2, r);
    a2[i] = w3 * Sum(l) - MatrixVectorMul(l, w4);
    b2[i] = r;

    u[i] = b1[i];
    u[i + kConvLayers.size()] = r;
    r_com_u[i] = InnerProduct(r_com_w2, r);
    r_com_u[i + kConvLayers.size()] = FrZero();

    assert(InnerProduct(a1[i], b1[i]) + InnerProduct(a2[i], b2[i]) == 0);
  };
  parallel::For(kConvLayers.size(), parallel_f, true);

  for(size_t i=0; i<kConvLayers.size(); i++){
    a.insert(a.end(), a1[i].begin(), a1[i].end());
    b.insert(b.end(), b1[i].begin(), b1[i].end());
  }
  for(size_t i=0; i<kConvLayers.size(); i++){
    a.insert(a.end(), a2[i].begin(), a2[i].end());
    b.insert(b.end(), b2[i].begin(), b2[i].end());
  }
  assert(InnerProduct(a, b) == 0);
}


inline void ConvProve(h256_t seed,
                      ProveContext const& context,
                      ConvProof & proof,
                      std::unique_ptr<argument::A4::ProveInput> & in1,
                      std::unique_ptr<argument::A4::CommitmentSec> & sec1,
                      std::unique_ptr<argument::A4::ProveInput> & in2,
                      std::unique_ptr<argument::A4::CommitmentSec> & sec2) {
  Tick tick(__FN__);

  size_t m = 1024, n = 512, w = 13; //k为卷积的个数, m为输矩阵的最大长度, n为输出矩阵的最大宽度
  size_t lm = misc::Log2UB(m), ln = misc::Log2UB(n), lw = misc::Log2UB(w);

  std::vector<Fr> rx(lm), ry(ln), rw(lw);
  std::vector<Fr> rx_hat(1 << lm), ry_hat(1 << ln), rw_hat(w);

  auto parallel_f1 = [&seed, &rx, &ry, &rw, &rx_hat, &ry_hat, &rw_hat](size_t i){
    if(i == 0) {
      ComputeFst(seed, "relubn rx", rx); //包含了conv个数的随机数
      misc::BuildR(rx_hat, rx);
    }else if(i == 1) {
      ComputeFst(seed, "relubn ry", ry);
      misc::BuildR(ry_hat, ry);
    }else if(i == 2) {
      ComputeFst(seed, "relubn rw", rw);
      misc::BuildR(rw_hat, rw);
    }
  };
  parallel::For(3, parallel_f1);

  std::vector<std::vector<Fr>> rx_rw_hat(w);
  auto parallel_f = [&rx_hat, &rw_hat, &rx_rw_hat, &context](size_t i){
    size_t m = context.const_images()[kConvLayers[i]]->matrix.size();
    std::vector<Fr> a(rx_hat.begin(), rx_hat.begin()+m);
    rx_rw_hat[i] = a * rw_hat[i];
  };
  parallel::For(w, parallel_f);

  std::vector<std::vector<Fr>> u1, u2;
  std::vector<std::vector<Fr>> v1, v2;
  std::vector<Fr> r_com_u1, r_com_u2;

  Fr c=0, r_com_c=0;
  std::vector<Fr> a, b, e;
  PrepareConvIPInput(context, rx_rw_hat, ry_hat, a, b, u2, r_com_u2);
  argument::SumCheck::Prove(misc::Log2UB(a.size()), misc::Pow2UB(a.size()), proof.com_t0, proof.com_t2, e, seed, a, b, c, r_com_c, pc::kGetRefG1(0));
  
  assert(a[0] * b[0] == c);

  Fr r_com_a = FrRand(), r_com_b = FrRand();
  proof.com_u[0] = pc::ComputeCom(a[0], r_com_a);
  proof.com_u[1]=  pc::ComputeCom(b[0], r_com_b);

  argument::A1::ProveInput a1_in(a[0], b[0], c);
  argument::A1::CommitmentSec a1_sec(r_com_a, r_com_b, r_com_c);
  argument::A1::Prove(proof.sm_proof, seed, a1_in, a1_sec);

  PrepareConvAdaptItem(context, rx_rw_hat, e, u1, v1, v2, r_com_u1);
  assert(InnerProduct(u1, v1) == a[0]);
  assert(InnerProduct(u2, v2) == b[0]);

  a[0] -= InnerProduct(u1[0], v1[0]);
  r_com_u1.erase(r_com_u1.begin());
  u1.erase(u1.begin());
  v1.erase(v1.begin());
  
  for(size_t i=0, j=kConvLayers.size(); i<kConvLayers.size(); i++, j++){
    b[0] -= InnerProduct(u2[j], v2[j]);
  }
  
  u2.resize(kConvLayers.size());
  v2.resize(kConvLayers.size());
  r_com_u2.resize(kConvLayers.size());

  assert(InnerProduct(u1, v1) == a[0]);
  assert(InnerProduct(u2, v2) == b[0]);

  in1.reset(new argument::A4::ProveInput(u1, v1, a[0], pc::kGetRefG1, pc::kGetRefG1(0)));
  sec1.reset(new argument::A4::CommitmentSec(r_com_u1, r_com_a));

  in2.reset(new argument::A4::ProveInput(u2, v2, b[0], pc::kGetRefG1, pc::kGetRefG1(0)));
  sec2.reset(new argument::A4::CommitmentSec(r_com_u2, r_com_b));
}

inline bool ConvVerify(h256_t seed,
                      VerifyContext const& context,
                      ConvProof const& proof,
                      AdaptVerifyItem & item) {
  Tick tick(__FN__);
  bool ret = false;
  size_t m = 1024, n = 512, w = 13; //k为卷积的个数, m为输矩阵的最大长度, n为输出矩阵的最大宽度
  size_t lm = misc::Log2UB(m), ln = misc::Log2UB(n), lw = misc::Log2UB(w);

  std::vector<Fr> rx(lm), ry(ln), rw(lw);
  std::vector<Fr> rx_hat(1 << lm), ry_hat(1 << ln), rw_hat(w);

  auto parallel_f1 = [&seed, &rx, &ry, &rw, &rx_hat, &ry_hat, &rw_hat](size_t i){
    if(i == 0) {
      ComputeFst(seed, "relubn rx", rx); //包含了conv个数的随机数
      misc::BuildR(rx_hat, rx);
    }else if(i == 1) {
      ComputeFst(seed, "relubn ry", ry);
      misc::BuildR(ry_hat, ry);
    }else if(i == 2) {
      ComputeFst(seed, "relubn rw", rw);
      misc::BuildR(rw_hat, rw);
    }
  };
  parallel::For(3, parallel_f1);

  std::vector<std::vector<Fr>> rx_rw_hat(w);
  auto parallel_f = [&rx_hat, &rw_hat, &rx_rw_hat](size_t i){
    size_t m = kConvLayerInfos[i].D * kConvLayerInfos[i].D;
    std::vector<Fr> a(rx_hat.begin(), rx_hat.begin()+m);
    rx_rw_hat[i] = a * rw_hat[i];
  };
  parallel::For(w, parallel_f);


  G1 com_c=G1Zero();
  std::vector<G1> com_u1, com_u2;
  std::vector<std::vector<Fr>> v1, v2;

  std::vector<Fr>  e;
  argument::SumCheck::Verify(proof.com_t0, proof.com_t2, seed, com_c, e);

  argument::A1::CommitmentPub a1_pub(proof.com_u[0], proof.com_u[1], com_c);
  argument::A1::VerifyInput a1_in(a1_pub);
  ret = argument::A1::Verify(proof.sm_proof, seed, a1_in);

  G1 com_t1 = proof.com_u[0], com_t2 = proof.com_u[1];
  PrepareConvAdaptItem(context, rx_rw_hat, ry_hat, e, com_u1, v1, com_u2, v2, com_t1, com_t2);

  argument::A4::CommitmentPub a4_pub1(com_u1, com_t1);
  item.in[0] = std::make_unique<argument::A4::VerifyInput>(v1, a4_pub1, pc::kGetRefG1, pc::kGetRefG1(0));

  argument::A4::CommitmentPub a4_pub2(com_u2, com_t2);
  item.in[1] = std::make_unique<argument::A4::VerifyInput>(v2, a4_pub2, pc::kGetRefG1, pc::kGetRefG1(0));

  return ret;
}

}  // namespace clink::vgg16