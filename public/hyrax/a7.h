#pragma once

#include "./a6.h"
#include "./details.h"

// a_i: public vector<Fr>, i\in[0,m-1], a_i.size() maybe neq a_j.size()
// x_i: secret vector<Fr>, i\in[0,m-1], x_i.size() maybe neq x_j.size()
// a_i.size() must eq x_i.size()
// z: secret Fr
// open: com(gx,x), com(gz,z)
// prove: z = \sum_{i=0}^{m}<x_i,a_i>
// proof size: 2logm+2logn+2 G1 and 4 Fr

namespace hyrax {
struct A7 {
  struct CommitmentPub {
    std::vector<G1> cx;
    G1 cz;
    CommitmentPub(){}
    CommitmentPub(std::vector<G1> const& cx, G1 const& cz)
        : cx(cx),
          cz(cz){}
    bool operator==(CommitmentPub const& right) const {
      return cx == right.cx && cz == right.cz;
    }

    bool operator!=(CommitmentPub const& right) const {
      return !(*this == right);
    }
  };

  struct CommitmentSec {
    std::vector<Fr> r;  // r.size = m
    Fr t;
    CommitmentSec(){}
    CommitmentSec(std::vector<Fr> const& r, Fr const& t)
        : r(r),
          t(t){}

    bool operator==(CommitmentSec const& right) const {
      return r == right.r && t == right.t;
    }

    bool operator!=(CommitmentSec const& right) const {
      return !(*this == right);
    }
  };

  struct VerifyInput {
    VerifyInput(std::string const& tag, CommitmentPub const& com_pub,
                GetRefG1 const& get_gx, std::vector<std::vector<Fr>> const& a,
                G1 const& gz)
        : tag(tag),
          com_pub(com_pub),
          get_gx(get_gx),
          a(a),
          gz(gz) {
      assert(!a.empty() && a.size() == com_pub.cx.size());
    }
    std::string tag;
    CommitmentPub com_pub;
    GetRefG1 const& get_gx;
    std::vector<std::vector<Fr>> a;
    G1 gz;

    int64_t m() const { return a.size(); }
    int64_t n() const { return a[0].size(); }
    std::string to_string() const {
      return tag + ": " + std::to_string(m()) + " " + std::to_string(n());
    }

    void Update(Fr const& e) {
      auto m2 = misc::Pow2UB(m()) >> 1;
      std::vector<std::vector<Fr>> a2(m2);
      auto pf = [this, &a2, &e](int64_t i) {
        int64_t j = i + a2.size();
        if(j >= m()){
          a2[i] = a[i];
        }else{
          a2[i] = a[i] + a[j] * e;
        }
      };
      parallel::For(m2, pf);
      a2.swap(a);
    }
  };

  struct ProveInput {
    std::string tag;
    std::vector<std::vector<Fr>> x;
    std::vector<std::vector<Fr>> a;
    Fr z;
    GetRefG1 const& get_gx;
    G1 const& gz;
    size_t max_n = 0;

    int64_t m() const { return (int64_t)x.size(); }
    int64_t n() const { return (int64_t)x[0].size(); }
    std::string to_string() const {
      return tag + ": " + std::to_string(m()) + "*" + std::to_string(n());
    }
    ProveInput(std::string const& tag, std::vector<std::vector<Fr>> const& x,
               std::vector<std::vector<Fr>> const& a, Fr const& z,
               GetRefG1 const& get_gx, G1 const& gz)
        : tag(tag),
          x(x),
          a(a),
          z(z),
          get_gx(get_gx),
          gz(gz) {
      Check();
    }

    void Update(Fr const& alpha, Fr const& beta, Fr const& e, Fr const& ee) {
      // Tick tick(__FN__, to_string());
      auto m2 = misc::Pow2UB(m()) >> 1;
      std::vector<std::vector<Fr>> x2(m2);
      std::vector<std::vector<Fr>> a2(m2);
      auto pf = [this, &x2, &a2, &e](int64_t i) {
        int64_t j = i + x2.size();
        if(j >= m()){
          x2[i] = x[i] * e;
          a2[i] = a[i];
        }else{
          x2[i] = x[i] * e + x[j];
          a2[i] = a[i] + a[j] * e;
        }
      };
      parallel::For(m2, pf);
      x2.swap(x);
      a2.swap(a);

      z = alpha + z * e + beta * ee;
    }

    void const Check() {
      assert(!x.empty() && x.size() == a.size() && x[0].size() == a[0].size());

      if (DEBUG_CHECK) {
        Fr check_z = FrZero();
        for (int64_t i = 0; i < m(); ++i) {
          assert(x[i].size() == a[i].size());
          check_z += InnerProduct(x[i], a[i]);
        }
        assert(z == check_z);
      }
    }
  };

  struct CommitmentExtPub {
    // 5.3 Recursive
    std::vector<G1> cl;  // size = log(m)
    std::vector<G1> cu;  // size = log(m)

    bool operator==(CommitmentExtPub const& right) const {
      return cl == right.cl && cu == right.cu;
    }

    bool operator!=(CommitmentExtPub const& right) const {
      return !(*this == right);
    }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("a4.cep", ("cl", cl), ("cu", cu));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("a4.cep", ("cl", cl), ("cu", cu));
    }
  };

  struct Proof {
    CommitmentExtPub com_ext_pub;  // 2*log(m) G1
    A6::Proof proof_a6;            // (2+2log(n))G1 + 2Fr

    int64_t aligned_m() const { return 1LL << com_ext_pub.cl.size(); }

    bool operator==(Proof const& right) const {
      return com_ext_pub == right.com_ext_pub && proof_a6 == right.proof_a6;
    }

    bool operator!=(Proof const& right) const { return !(*this == right); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("a4.pf", ("c", com_ext_pub), ("r", proof_a6));
    }

    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("a4.pf", ("c", com_ext_pub), ("r", proof_a6));
    }
  };

  static void ComputeCom(ProveInput const& input, CommitmentPub & com_pub,
                         CommitmentSec & com_sec) {
    Tick tick(__FN__);
    auto const m = input.m();

    com_pub.cx.resize(m);
    com_sec.r.resize(m);

    com_sec.t = FrRand();
    FrRand(com_sec.r);

    com_pub.cz = pc::ComputeCom(input.gz, input.z, com_sec.t);
    auto parallel_f = [&input, &com_pub, &com_sec](int64_t i){
      com_pub.cx[i] = pc::ComputeCom(input.get_gx, input.x[i], com_sec.r[i]);
    };
    parallel::For(m, parallel_f);
  }

  static void ProveFinal(Proof& proof, h256_t const& seed,
                         ProveInput const& input, CommitmentPub const& com_pub,
                         CommitmentSec const& com_sec) {
    Tick tick(__FN__, input.to_string());

    A6::ProveInput input_a6(input.tag, input.x[0], input.a[0], input.z,
                            input.get_gx, input.gz);
    A6::CommitmentPub com_pub_a6(com_pub.cx[0], com_pub.cz);
    A6::CommitmentSec com_sec_a6(com_sec.r[0], com_sec.t);

    A6::Prove(proof.proof_a6, seed, input_a6, com_pub_a6, com_sec_a6);
  }

  static void ComputeSigmaXA(ProveInput const& input, Fr* alpha, Fr* beta) {
    // Tick tick(__FN__, input.to_string());
    auto m2 = misc::Pow2UB(input.m()) >> 1;
    std::vector<Fr> xa1(m2, FrZero());
    std::vector<Fr> xa2(m2, FrZero());
    auto parallel_f = [&input, &xa1, &xa2](int64_t i) {
      int64_t j = i + xa1.size();
      if(j < input.m()){
        xa1[i] = InnerProduct(input.x[j], input.a[i]);
        xa2[i] = InnerProduct(input.x[i], input.a[j]);
      }
    };
    parallel::For(m2, parallel_f);

    *alpha = parallel::Accumulate(xa1.begin(), xa1.end(), FrZero());
    *beta = parallel::Accumulate(xa2.begin(), xa2.end(), FrZero());
  }

  static void UpdateCom(CommitmentPub& com_pub, CommitmentSec& com_sec,
                        Fr const& tl, Fr const& tu, G1 const& cl, G1 const& cu,
                        Fr const& e, Fr const& ee) {
    // Tick tick(__FN__);
    CommitmentPub com_pub2;
    CommitmentSec com_sec2;
    auto m2 = misc::Pow2UB(com_pub.cx.size()) >> 1;
    com_pub2.cx.resize(m2);
    com_sec2.r.resize(m2);

    auto parallel_f = [&com_pub, &com_sec, &com_pub2,
                       &com_sec2, &e](int64_t i) {
      auto& cx2 = com_pub2.cx;
      auto& r2 = com_sec2.r;

      auto const& cx = com_pub.cx;
      auto const& r = com_sec.r;

      int64_t j = i + cx2.size();

      if(j >= cx.size()){
        cx2[i] = cx[i] * e;
        r2[i] = r[i] * e;
      }else{
        cx2[i] = cx[i] * e + cx[j];
        r2[i] = r[i] * e + r[j];
      }
    };
    parallel::For((int64_t)m2, parallel_f);

    com_pub2.cz = cl + com_pub.cz * e + cu * ee;
    com_sec2.t = tl + com_sec.t * e + tu * ee;
    com_pub = std::move(com_pub2);
    com_sec = std::move(com_sec2);
  }

  static Fr ComputeChallenge(h256_t const& seed, std::vector<G1> const& cx,
                            G1 const& cz, G1 const& cl, G1 const& cu) {
    // Tick tick(__FN__);
    CryptoPP::Keccak_256 hash;
    h256_t digest;
    HashUpdate(hash, seed);
    HashUpdate(hash, cl);
    HashUpdate(hash, cu);
    HashUpdate(hash, cx);
    HashUpdate(hash, cz);
    hash.Final(digest.data());
    return H256ToFr(digest);
  }

  static void ProveRecursive(Proof& proof, h256_t & seed, ProveInput &input,
                             CommitmentPub &com_pub, CommitmentSec &com_sec) {
    Tick tick(__FN__, input.to_string());
    
    Fr alpha, beta;
    ComputeSigmaXA(input, &alpha, &beta);

    // compute cl, cu
    Fr tl = FrRand(), tu = FrRand();
    G1 cl = pc::ComputeCom(input.gz, alpha, tl);
    G1 cu = pc::ComputeCom(input.gz, beta, tu);
    proof.com_ext_pub.cl.push_back(cl);
    proof.com_ext_pub.cu.push_back(cu);

    // challenge
    Fr e = ComputeChallenge(seed, com_pub.cx, com_pub.cz, cl, cu);
    Fr ee = e * e;
    seed = FrToBin(e);

    input.Update(alpha, beta, e, ee);

    UpdateCom(com_pub, com_sec, tl, tu, cl, cu, e, ee);
  }

  static void Prove(Proof& proof, h256_t seed, ProveInput const& _input,
                    CommitmentPub const& _com_pub, CommitmentSec const& _com_sec) {
    Tick tick(__FN__, _input.to_string());

    ProveInput input = _input;
    CommitmentPub com_pub = _com_pub;
    CommitmentSec com_sec = _com_sec;

    if(DEBUG_CHECK){
      input.Check();
      for(int i=0; i<_input.m(); i++){ 
        assert(pc::ComputeCom(input.get_gx, input.x[i], com_sec.r[i]) == com_pub.cx[i]);
      }
      assert(pc::ComputeCom(input.gz, input.z, com_sec.t) == com_pub.cz);
    }

    while (input.m() > 1) {
      ProveRecursive(proof, seed, input, com_pub, com_sec);

      // if(DEBUG_CHECK){
      //   input.Check();
      //   for(int i=0; i<input.m(); i++){ 
      //     assert(pc::ComputeCom(input.get_gx, input.x[i], com_sec.r[i]) == com_pub.cx[i]);
      //   }
      //   assert(pc::ComputeCom(input.gz, input.z, com_sec.t) == com_pub.cz);
      // }
    }
    ProveFinal(proof, seed, input, com_pub, com_sec);
  }

  static bool Verify(Proof const& proof, h256_t seed, VerifyInput const& input) {
    Tick tick(__FN__, input.to_string());

    assert(proof.aligned_m() == misc::Pow2UB(input.m()));

    auto const& com_ext_pub = proof.com_ext_pub;
    
    std::vector<std::vector<Fr>> a= input.a;
    std::vector<G1> cx = input.com_pub.cx;
    G1 cz = input.com_pub.cz;

    int64_t m = proof.aligned_m();

    for (size_t loop = 0; loop < com_ext_pub.cl.size(); ++loop) {
      // challenge
      auto const& cl = com_ext_pub.cl[loop];
      auto const& cu = com_ext_pub.cu[loop];

      Fr e = ComputeChallenge(seed, cx, cz, cl, cu);
      Fr ee = e * e;
      seed = FrToBin(e);

      m = m >> 1;

      std::vector<std::vector<Fr>> a2(m);
      std::vector<G1> cx2(m);

      auto parallel_f = [&cx, &cx2, &a, &a2, &e](int64_t i) {
        int64_t j = i + cx2.size();
        if(j >= cx.size()){
          a2[i] = a[i];
          cx2[i] = cx[i] * e;
        }else{
          cx2[i] = cx[i] * e + cx[j];
          a2[i] = a[i] + a[j] * e;
        }
      };
      parallel::For(m, parallel_f);

      cz = cl + cz * e + cu * ee;
      cx.swap(cx2);
      a.swap(a2);
    }
    assert(cx.size() == 1 && a.size() == 1 );

    A6::CommitmentPub com_pub_a6(cx[0], cz);
    A6::VerifyInput verifier_input_a6(input.tag, a[0], com_pub_a6,
                                      input.get_gx, input.gz);
    return A6::Verify(proof.proof_a6, seed, verifier_input_a6);
  }

 public:
  static bool Test(int64_t m, int64_t n) {
    Tick tick(__FN__, std::to_string(m) + " " + std::to_string(n));

    std::vector<std::vector<Fr>> x(m, std::vector<Fr>(n, 0));
    std::vector<std::vector<Fr>> a(m, std::vector<Fr>(n, 0));

    for (int i=0; i<m; i++) {
      FrRand(x[i]);
      FrRand(a[i]);
    }

    Fr z = FrZero();
    for (int64_t i = 0; i < m; ++i) {
      z += InnerProduct(x[i], a[i]);
    }

    h256_t seed = misc::RandH256();

    G1 gy = pc::kGetRefG1(0);
    GetRefG1 get_gx = pc::kGetRefG1;

    auto a_copy = a;
    ProveInput prove_input("test", x, a, z, get_gx, gy);
    CommitmentPub com_pub;
    CommitmentSec com_sec;
    ComputeCom(prove_input, com_pub, com_sec);

    Proof proof;
    Prove(proof, seed, prove_input, com_pub, com_sec);

#ifndef DISABLE_SERIALIZE_CHECK
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
#endif
    VerifyInput verify_input("test", com_pub, get_gx, a, gy);
    bool success = Verify(proof, seed, verify_input);
    std::cout << __FILE__ << " " << __FN__ << ": " << success << "\n\n\n\n\n\n";
    return success;
  }
};
}  // namespace hyrax
