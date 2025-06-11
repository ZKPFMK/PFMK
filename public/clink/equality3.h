#pragma once

#include "./details.h"
#include "hyrax/a5.h"

// proof of equality
// x: secret vector<Fr>
// y: secret vector<Fr>
// open com(gx, x), com(gy, y)
// prove x==y
// NOTE: different g

namespace clink {
struct Equality3 {
  struct ProveInput {
    ProveInput(std::vector<Fr> const& x, GetRefG1 const& get_gx,  GetRefG1 const& get_gy)
        : x(x), get_gx(get_gx), get_gy(get_gy) {
    }
    std::vector<Fr> const x;
    GetRefG1 const get_gx;
    GetRefG1 const get_gy;
  };

  struct CommitmentPub {
    CommitmentPub() {}
    CommitmentPub(G1 const& xi, G1 const& yi) : xi(xi), yi(yi) {}

    G1 xi, yi;
  };

  struct CommitmentSec {
    CommitmentSec() {}
    CommitmentSec(Fr const& x, Fr const& y) : r_xi(x), r_yi(y) {}
    Fr r_xi;
    Fr r_yi;
  };

  struct VerifyInput {
    VerifyInput(int64_t n, CommitmentPub const& com_pub, GetRefG1 const& get_gx,  GetRefG1 const& get_gy)
        : n(n), com_pub(com_pub), get_gx(get_gx), get_gy(get_gy) {
    }
    int64_t n;
    CommitmentPub const& com_pub;
    GetRefG1 const get_gx;
    GetRefG1 const get_gy;
  };


  struct Proof {
    G1 com_a;
    Fr r_com_z;

    hyrax::A5::Proof open_proof;

    bool operator==(Proof const& right) const {
      return com_a == right.com_a && r_com_z == right.r_com_z && open_proof == right.open_proof;
    }
    bool operator!=(Proof const& right) const { return !(*this == right); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("e.p", ("a", com_a), ("z", r_com_z), ("p", open_proof));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("e.p", ("a", com_a), ("z", r_com_z), ("p", open_proof));
    }
  };

  static void UpdateSeed(h256_t& seed, G1 const& com_x, G1 const& com_y,
                         G1 const& alpha, int64_t count) {
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    HashUpdate(hash, com_x);
    HashUpdate(hash, com_y);
    HashUpdate(hash, alpha);
    HashUpdate(hash, count);
    hash.Final(seed.data());
  }

  static void Prove(Proof& proof, h256_t seed, ProveInput input,
                    CommitmentPub com_pub, CommitmentSec com_sec) {
    Tick tick(__FN__);
    assert(com_pub.xi == pc::ComputeCom(input.get_gx, input.x, com_sec.r_xi));
    assert(com_pub.yi == pc::ComputeCom(input.get_gy, input.x, com_sec.r_yi));

    auto & x = input.x;
    auto & com_x = com_pub.xi;
    auto & com_y = com_pub.yi;
    auto & r_com_x = com_sec.r_xi;
    auto & r_com_y = com_sec.r_yi;

    auto & com_a = proof.com_a;
    auto & r_com_z = proof.r_com_z;
    
    std::vector<G1> g(x.size());
    auto parallel_f = [&input, &g](int64_t i){
        g[i] = input.get_gx(i) + input.get_gy(i);
    };
    parallel::For(x.size(), parallel_f);

    GetRefG1 get_g = [&g](int64_t i) -> G1 const& {
        return g[i];
    };
    assert(com_pub.yi + com_pub.xi == pc::ComputeCom(get_g, x, r_com_x+r_com_y));

    std::vector<Fr> a(x.size());
    Fr r_com_a = FrRand();
    FrRand(a);
    
    com_a = pc::ComputeCom(get_g, a, r_com_a);

    UpdateSeed(seed, com_x, com_y, com_a, (int64_t)x.size());
    Fr e = H256ToFr(seed);

    std::vector<Fr> z = a + x * e;
    r_com_z = r_com_a + (r_com_x + r_com_y) * e;
    G1 com_z = com_a + (com_x + com_y) * e - pc::PcH() * r_com_z;
    
    std::vector<Fr> vec_zero (x.size(), FrZero());
    hyrax::A5::ProveInput a5_input("open", z, vec_zero, FrZero(), get_g, pc::PcU());
    hyrax::A5::CommitmentPub a5_com_pub(com_z);
    hyrax::A5::Prove(proof.open_proof, seed, a5_input, a5_com_pub);
  }

  static bool Verify(Proof const& proof, h256_t seed, VerifyInput const& input) {
    auto & n = input.n;

    auto & com_x = input.com_pub.xi;
    auto & com_y = input.com_pub.yi;

    auto & com_a = proof.com_a;
    auto & r_com_z = proof.r_com_z;

    UpdateSeed(seed, com_x, com_y, com_a, n);
    Fr e = H256ToFr(seed);

    std::vector<G1> g(n);
    auto parallel_f = [&input, &g](int64_t i){
        g[i] = input.get_gx(i) + input.get_gy(i);
    };
    parallel::For(n, parallel_f);

    GetRefG1 get_g = [&g](int64_t i) -> G1 const& {
        return g[i];
    };

    G1 com_z = com_a + (com_x + com_y) * e - pc::PcH() * r_com_z;
    std::vector<Fr> vec_zero (n, FrZero());

    hyrax::A5::CommitmentPub com_pub(com_z);
    hyrax::A5::VerifyInput verify_input("test", vec_zero, FrZero(), com_pub, get_g, pc::PcU());

    return hyrax::A5::Verify(proof.open_proof, seed, verify_input);;
  }

  static bool Test(int64_t n);
};

bool Equality3::Test(int64_t n) {
  Tick tick(__FN__, std::to_string(n));

  auto seed = misc::RandH256();

  int64_t gx_offset = 30, gy_offset = 40;

  GetRefG1 get_gx = [gx_offset](int64_t i) -> G1 const& {
    return pc::PcG()[gx_offset + i];
  };
  GetRefG1 get_gy = [gy_offset](int64_t i) -> G1 const& {
    return pc::PcG()[gy_offset + i];
  };

  std::vector<Fr> x(n);
  Fr rx = FrRand();
  Fr ry = FrRand();
  FrRand(x);

  G1 com_x = pc::ComputeCom(get_gx, x, rx);
  G1 com_y = pc::ComputeCom(get_gy, x, ry);

  ProveInput prove_input(x, get_gx, get_gy);
  CommitmentPub com_pub(com_x, com_y);
  CommitmentSec com_sec(rx, ry);


  Proof proof;
  Prove(proof, seed, prove_input, com_pub, com_sec);

#ifndef DISABLE_SERIALIZE_CHECK
  // serialize to buffer
  yas::mem_ostream os;
  yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
  oa.serialize(proof);
  std::cout << Tick::GetIndentString()
            << "proof size: " << os.get_shared_buffer().size << "\n";
  // serialize from buffer
  yas::mem_istream is(os.get_intrusive_buffer());
  yas::binary_iarchive<yas::mem_istream, YasBinF()> ia(is);
  Proof proof2;
  ia.serialize(proof2);
  CHECK(proof == proof2, "");
#endif
  VerifyInput verify_input(n, com_pub, get_gx, get_gy);
  bool success = Verify(proof, seed, verify_input);
  std::cout << Tick::GetIndentString() << success << "\n\n\n\n\n\n";
  return success;
}
}  // namespace clink