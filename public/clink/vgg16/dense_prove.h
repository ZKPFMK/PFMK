#pragma once

#include "./context.h"
#include "./image_com.h"
#include "../adapt.h"
#include "argument/argument.h"
namespace clink::vgg16 {

struct ProveDenseInput {
  ProveDenseInput(std::vector<std::vector<Fr>> const& w,
                  std::vector<G1> const& com_w,
                  std::vector<Fr> const& r_com_w,
                  std::vector<Fr> && x,
                  G1 com_x, Fr const& r_com_x,
                  std::vector<Fr> const& y,
                  G1 const& com_y, Fr const& r_com_y)
      : w(w),
        com_w(com_w),
        r_com_w(r_com_w),
        x(std::move(x)),
        com_x(com_x),
        r_com_x(r_com_x),
        y(y),
        com_y(com_y),
        r_com_y(r_com_y) {
    namespace fp = circuit::fp;

    this->x.push_back(fp::RationalConst<8, 24>().kFrN);
    this->com_x = this->com_x + pc::PcG(this->x.size()-1) * this->x.back();
    

    if (DEBUG_CHECK) {
      CHECK(w.size() == y.size(), "");
      for (size_t i=0; i<w.size(); i++) {
        CHECK(w[i].size() == this->x.size(), "");
        CHECK(InnerProduct(w[i], this->x) == y[i], "");
        CHECK(pc::ComputeCom(this->w[i], this->r_com_w[i]) == this->com_w[i], "");
      }
      CHECK(pc::ComputeCom(this->x, this->r_com_x) == this->com_x, "");
      CHECK(pc::ComputeCom(this->y, this->r_com_y) == this->com_y, "");
    }
  }

  size_t m() const {return w.size();};
  size_t n() const {return w[0].size();};
  std::string to_string() const { return std::to_string(m()) + "*" + std::to_string(n());}

  std::vector<std::vector<Fr>> const& w;
  std::vector<Fr> const& r_com_w;
  std::vector<G1> const& com_w;

  std::vector<Fr> x;
  Fr const& r_com_x;
  G1 com_x;
  std::vector<Fr> const& y;
  Fr const& r_com_y;
  G1 const& com_y;
};

struct DenseProof {
  std::vector<G1> com_t0, com_t2;
  std::array<G1, 2> com_ab;

  argument::A1::Proof sm_proof;

  bool operator==(DenseProof const& b) const {
    return com_t0 == b.com_t0 && sm_proof == b.sm_proof &&
           com_t2 == b.com_t2 && com_ab == b.com_ab;
  }

  bool operator!=(DenseProof const& b) const { return !(*this == b); }

  template <typename Ar>
  void serialize(Ar& ar) const {
    ar& YAS_OBJECT_NVP("d.p", ("0", com_t0), ("2", com_t2),
                       ("c", com_ab), ("p", sm_proof));
  }
  template <typename Ar>
  void serialize(Ar& ar) {
    ar& YAS_OBJECT_NVP("d.p", ("0", com_t0), ("2", com_t2),
                       ("c", com_ab), ("p", sm_proof));
  }
};

static void ProveDense(h256_t seed, ProveDenseInput const& input, DenseProof& proof,
                       std::unique_ptr<argument::A4::ProveInput> & in1, std::unique_ptr<argument::A4::CommitmentSec> & sec1,
                       std::unique_ptr<argument::A4::ProveInput> & in2, std::unique_ptr<argument::A4::CommitmentSec> & sec2) {
  Tick tick(__FN__, input.to_string());

  size_t m = input.m(), n = input.n();

  std::vector<Fr> r(input.m()), neg_r, s;
  ComputeFst(seed, "dense", r);

  Fr c = 0, r_com_c = 0;
  std::vector<Fr> d = MatrixVectorMul(r, input.w), a = input.x, b = d;
  
  neg_r = -r;
  a.insert(a.end(), input.y.begin(), input.y.end());
  b.insert(b.end(), neg_r.begin(), neg_r.end());

  size_t round = misc::Log2UB(a.size());
  argument::SumCheck::Prove(round, 1 << round, proof.com_t0, proof.com_t2, s, seed, a, b, c, r_com_c, pc::kGetRefG1(0));

  Fr r_com_a = FrRand(), r_com_b = FrRand();
  proof.com_ab[0] = pc::ComputeCom(a[0], r_com_a);
  proof.com_ab[1] = pc::ComputeCom(b[0], r_com_b);

  argument::A1::ProveInput a1_in(a[0], b[0], c);
  argument::A1::CommitmentSec a1_sec(r_com_a, r_com_b, r_com_c);
  argument::A1::Prove(proof.sm_proof, seed, a1_in, a1_sec);

  std::vector<Fr> s_hat = misc::BuildE(s);
  std::vector<Fr> s_chk(s_hat.rbegin(), s_hat.rend());
  
  std::vector<Fr> r_com_u1(2), r_com_u2(1);
  std::vector<std::vector<Fr>> u1(2), v1(2);
  std::vector<std::vector<Fr>> u2(1), v2(1);
  u1[0] = input.x;
  u1[1] = input.y;
  r_com_u1[0] = input.r_com_x;
  r_com_u1[1] = input.r_com_y;
  v1[0] = std::vector<Fr>(s_hat.begin(), s_hat.begin() + n);
  v1[1] = std::vector<Fr>(s_hat.begin() + n, s_hat.begin() + n + m);

  u2[0] = d;
  r_com_u2[0] = InnerProduct(r, input.r_com_w);
  v2[0] = std::vector<Fr>(s_chk.begin(), s_chk.begin() + n);

  b[0] += InnerProduct(r, std::vector<Fr>(s_chk.begin()+n, s_chk.begin()+n+m));
  assert(InnerProduct(u1, v1) == a[0]);
  assert(InnerProduct(u2, v2) == b[0]);

  in1 = std::make_unique<argument::A4::ProveInput>(u1, v1, a[0], pc::kGetRefG1, pc::kGetRefG1(0));
  sec1 = std::make_unique<argument::A4::CommitmentSec>(r_com_u1, r_com_a);
  in2 = std::make_unique<argument::A4::ProveInput>(u2, v2, b[0], pc::kGetRefG1, pc::kGetRefG1(0));
  sec2 =  std::make_unique<argument::A4::CommitmentSec>(r_com_u2, r_com_b);
}

static bool VerifyDense(h256_t seed, std::vector<G1> const& com_w, G1 const& com_x, G1 const& com_y, DenseProof const& proof, 
                        std::unique_ptr<argument::A4::VerifyInput> & in1, std::unique_ptr<argument::A4::VerifyInput> & in2) {
  size_t m = com_w.size(), n = 513;
  Tick tick(__FN__, std::to_string(m) + "*" + std::to_string(n));
  
  bool ret = false;
  std::vector<Fr> r(m), s;
  ComputeFst(seed, "dense", r);

  G1 com_a = proof.com_ab[0], com_b = proof.com_ab[1], com_c = G1Zero();
  argument::SumCheck::Verify(proof.com_t0, proof.com_t2, seed, com_c, s);

  argument::A1::CommitmentPub a1_pub(com_a, com_b, com_c);
  argument::A1::VerifyInput a1_in(a1_pub);
  ret = argument::A1::Verify(proof.sm_proof, seed, a1_in);

  std::vector<Fr> s_hat = misc::BuildE(s);
  std::vector<Fr> s_chk(s_hat.rbegin(), s_hat.rend());
  
  std::vector<G1> com_u1 = {com_x, com_y}, com_u2 = {MultiExpBdlo12(com_w, r)};
  std::vector<std::vector<Fr>> v1(2), v2(1);

  v1[0] = std::vector<Fr>(s_hat.begin(), s_hat.begin() + n);
  v1[1] = std::vector<Fr>(s_hat.begin() + n, s_hat.begin() + n + m);

  v2[0] = std::vector<Fr>(s_chk.begin(), s_chk.begin() + n);

  com_b = com_b + pc::kGetRefG1(0) * InnerProduct(r, std::vector<Fr>(s_chk.begin()+n, s_chk.begin()+n+m));


  argument::A4::CommitmentPub a4_pub1(com_u1, com_a);
  in1 = std::make_unique<argument::A4::VerifyInput>(v1, a4_pub1, pc::kGetRefG1, pc::kGetRefG1(0));

  argument::A4::CommitmentPub a4_pub2(com_u2, com_b);
  in2 = std::make_unique<argument::A4::VerifyInput>(v2, a4_pub2, pc::kGetRefG1, pc::kGetRefG1(0));

  return ret;
}

template <size_t kOrder>
void DenseProve(h256_t seed, ProveContext const& context, DenseProof& proof,
                std::unique_ptr<argument::A4::ProveInput> & in1,
                std::unique_ptr<argument::A4::CommitmentSec> & sec1,
                std::unique_ptr<argument::A4::ProveInput> & in2,
                std::unique_ptr<argument::A4::CommitmentSec> & sec2) {
  Tick tick(__FN__);

  constexpr size_t kLayer = kDenseLayers[kOrder];
  constexpr ImageInfo const& info_in = kImageInfos[kLayer];
  constexpr ImageInfo const& info_out = kImageInfos[kLayer + 1];

  auto const& para = context.para().dense_layer(kOrder);
  auto const& w = para.weight;
  auto const& com_w = std::vector<G1>(context.para_com_pub().dense.get<kOrder>().begin(), context.para_com_pub().dense.get<kOrder>().end());
  auto const& r_com_w = std::vector<Fr>(context.para_com_sec().dense.get<kOrder>().begin(), context.para_com_sec().dense.get<kOrder>().end());

  std::vector<Fr> x = context.const_images()[kLayer]->data;
  auto const& com_x = context.image_com_pub().com_x[kLayer];
  auto const& r_com_x = context.image_com_sec().r_com_x[kLayer];

  std::vector<Fr> y = context.const_images()[kLayer + 1]->data;
  auto const& com_y = context.image_com_pub().com_x[kLayer + 1];
  auto const& r_com_y = context.image_com_sec().r_com_x[kLayer + 1];

  ProveDenseInput input(w, com_w, r_com_w, std::move(x), com_x, r_com_x, y, com_y, r_com_y);
  
  ProveDense(seed, input, proof, in1, sec1, in2, sec2);
}

template <size_t kOrder>
bool DenseVerify(h256_t seed, VerifyContext const& context, DenseProof const& proof, AdaptVerifyItem & verify) {
  namespace fp = circuit::fp;

  Tick tick(__FN__);

  constexpr size_t kLayer = kDenseLayers[kOrder];
  constexpr ImageInfo const& info_in = kImageInfos[kLayer];
  constexpr ImageInfo const& info_out = kImageInfos[kLayer + 1];

  size_t m = info_out.C, n = info_in.size();

  auto com_x = context.image_com_pub().com_x[kLayer] + pc::PcG(n) * fp::RationalConst<8, 24>().kFrN;
  auto const& com_y = context.image_com_pub().com_x[kLayer + 1];
  auto const& com_w = std::vector<G1>(context.para_com_pub().dense.get<kOrder>().begin(), context.para_com_pub().dense.get<kOrder>().end());

  return VerifyDense(seed, com_w, com_x, com_y, proof, verify.in[6 + (kOrder << 1)], verify.in[7 + (kOrder << 1)]);
}
}  // namespace clink::vgg16