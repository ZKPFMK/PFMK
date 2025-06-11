#pragma once

#include "./details.h"
#include "./sec53b.h"
#include "hyrax/a2.h"
#include "hyrax/a3.h"

// x, y, z: secret matrix<Fr>, size =m*n
// open: a1=com(gx, x1)...am=com(gx, xm)
// open: b1=com(gy, y1)...bm=com(gy, ym)
// open: c1=com(gz, z1)...cm=com(gz, zm)
// prove: z=x o y (o is hadamard product)
// proof size: 2*log(m)+6 G1, 3n+5 Fr
// prove cost: 2*log(m)*mulexp(n)
// verify cost: 2*mulexp(n)
namespace groth09 {

template <typename Sec53, typename HyraxA>
struct Sec43a {
  // input_53's gz can be any value, here just use pc::PcU()
  static G1 const& SelectSec53Gz() { return pc::PcU(); }

  struct CommitmentPub {
    std::vector<G1> a;  // a.size = m
    std::vector<G1> b;  // b.size = m
    std::vector<G1> c;  // c.size = m
  };

  struct CommitmentSec {
    std::vector<Fr> r;  // r.size = m
    std::vector<Fr> s;  // s.size = m
    std::vector<Fr> t;  // t.size = m
  };

  struct Proof {
    typename Sec53::Proof proof_53;  // 2*log(m)+4 G1, 2n+3 Fr

    bool operator==(Proof const& right) const {
      return proof_53 == right.proof_53;
    }
    bool operator!=(Proof const& right) const { return !(*this == right); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("43a.pf", ("53p", proof_53));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("43a.pf", ("53p", proof_53));
    }
  };

  struct ProveInput {
    std::vector<std::vector<Fr>> const& x;  // m*n
    std::vector<std::vector<Fr>> const& y;
    std::vector<std::vector<Fr>> const& z;
    GetRefG1 const& get_g;
  

    int64_t m() const { return x.size(); }
    int64_t n() const { return x[0].size(); }
    std::string to_string() const {
      return std::to_string(m()) + "*" + std::to_string(n());
    }

    ProveInput(std::vector<std::vector<Fr>> const& x,
               std::vector<std::vector<Fr>> const& y,
               std::vector<std::vector<Fr>> const& z,
               GetRefG1 const& get_g)
        : x(x),
          y(y),
          z(z),
          get_g(get_g) {
      Check();
    }

   private:
    void Check() {
      CHECK(!x.empty(), "");
      CHECK(x.size() == y.size() && x.size() == z.size(), "");
      if(DEBUG_CHECK){
        for (auto i = 0LL; i < m(); ++i) {
          CHECK(x[i].size() == x[0].size() && y[i].size() == x[0].size() && z[i].size() == x[0].size(), "");
          CHECK(HadamardProduct(x[i], y[i]) == z[i], "");
        }
      }
    }
  };

  static void ComputeCom(CommitmentPub& com_pub, CommitmentSec& com_sec,
                         ProveInput const& input) {
    Tick tick(__FN__, input.to_string());
    auto const m = input.m();
    com_sec.r.resize(m);
    com_sec.s.resize(m);
    com_sec.t.resize(m);

    com_pub.a.resize(m);
    com_pub.b.resize(m);
    com_pub.c.resize(m);

    FrRand(com_sec.r.data(), m);
    FrRand(com_sec.s.data(), m);
    FrRand(com_sec.t.data(), m);

    auto parallel_f = [&com_sec, &com_pub, &input](int64_t i) {
      std::array<parallel::VoidTask, 3> tasks;
      tasks[0] = [&com_pub, &input, &com_sec, i]() {
        com_pub.a[i] = pc::ComputeCom(input.get_g, input.x[i], com_sec.r[i]);
      };
      tasks[1] = [&com_pub, &input, &com_sec, i]() {
        com_pub.b[i] = pc::ComputeCom(input.get_g, input.y[i], com_sec.s[i]);
      };
      tasks[2] = [&com_pub, &input, &com_sec, i]() {
        com_pub.c[i] = pc::ComputeCom(input.get_g, input.z[i], com_sec.t[i]);
      };
      parallel::Invoke(tasks);
    };
    parallel::For(m, parallel_f);
  }

  static void UpdateSeed(h256_t& seed, CommitmentPub const& com_pub, int64_t m,
                         int64_t n) {
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    HashUpdate(hash, com_pub.a);
    HashUpdate(hash, com_pub.b);
    HashUpdate(hash, com_pub.c);
    HashUpdate(hash, m);
    HashUpdate(hash, n);
    hash.Final(seed.data());
  }

  static void ComputeChallengeKT(h256_t const& seed, std::vector<Fr>& k,
                                 std::vector<Fr>& t) {
    ComputeFst(seed, "gro09::sec43a::k", k);
    ComputeFst(seed, "gro09::sec43a::t", t);
  }

  static void Prove(Proof& proof, h256_t seed,
                    ProveInput const& input,
                    CommitmentPub const& com_pub,
                    CommitmentSec const& com_sec) {
    Tick tick(__FN__, input.to_string());

    auto m = input.m();
    auto n = input.n();

    UpdateSeed(seed, com_pub, m, n);
    std::vector<Fr> k(m);
    std::vector<Fr> t(n);
    ComputeChallengeKT(seed, k, t);

    std::vector<std::vector<Fr>> input_x = input.x;
    std::vector<std::vector<Fr>> input_y = input.y;
    std::vector<std::vector<Fr>> input_yt(m * 2);

    input_x.resize(m * 2);
    input_y.resize(m * 2, std::vector<Fr>(n, -FrOne()));

    {
      Tick tick53(" sec43a->Sec53");

      typename Sec53::CommitmentSec com_sec_53;
      typename Sec53::CommitmentPub com_pub_53;

      auto parallel_f = [&input_x, &input, &k, &m](int64_t i) {
        input_x[i] = input.x[i] * k[i]; 
        input_x[i + m] = input.z[i] * k[i];
      };
      parallel::For(m, parallel_f);

      {
        Tick tickz("Sec53 compute yt");
        auto pf = [&input_yt, &input_y, &t](int64_t i) {
          input_yt[i] = HadamardProduct(input_y[i], t);
        };
        parallel::For(m*2, pf);
      }

      Fr z = FrZero();
      typename Sec53::ProveInput input_53(
              std::move(input_x), std::move(input_y), t, std::move(input_yt), z,
              input.get_g, input.get_g, SelectSec53Gz());

      {
        Tick tickz("Sec53 compute com_sec_53 com_pub_53");

        com_sec_53.r.resize(m*2);
        com_sec_53.s = com_sec.s;
        com_sec_53.t = FrZero();

        com_sec_53.s.resize(m*2, FrZero());
        com_pub_53.a.resize(m*2);

        auto parallel_f2 = [&com_sec, &com_pub, &com_sec_53, &com_pub_53,
                            &k, &m](int64_t i) {
          com_sec_53.r[i] = com_sec.r[i] * k[i];
          com_pub_53.a[i] = com_pub.a[i] * k[i];

          com_sec_53.r[i+m] = com_sec.t[i] * k[i];
          com_pub_53.a[i+m] = com_pub.c[i] * k[i];
        };
        parallel::For(m, parallel_f2);
 
        G1 com_1 = pc::ComputeSigmaG(input.get_g, n) * (-1);
        com_pub_53.b = com_pub.b;
        com_pub_53.b.resize(m*2, com_1);
        com_pub_53.c = G1Zero();
      }

      Sec53::Prove(proof.proof_53, seed, std::move(input_53),
                   std::move(com_pub_53), std::move(com_sec_53));
    }
  }

  struct VerifyInput {
    VerifyInput(size_t const& _n,
                CommitmentPub const& com_pub,
                GetRefG1 const& get_g)
        : com_pub(com_pub),
          get_g(get_g),
          _n(_n) {}

    size_t const& _n;
    CommitmentPub const& com_pub;
    GetRefG1 const& get_g;
    
    size_t m() const { return com_pub.a.size(); }
    size_t n() const { return _n; }
    std::string to_string() const {
      return std::to_string(m()) + "*" + std::to_string(n());
    }
  };

  static bool Verify(Proof const& proof, h256_t seed,
                     VerifyInput const& input) {
    Tick tick(__FN__, input.to_string());
    auto m = input.m();
    auto n = input.n();

    auto const& com_pub = input.com_pub;
    UpdateSeed(seed, com_pub, m, n);
    std::vector<Fr> k(m);
    std::vector<Fr> t(n);
    ComputeChallengeKT(seed, k, t);

    bool ret_53 = false;

    typename Sec53::CommitmentPub com_pub_53;
    com_pub_53.c = G1Zero();

    G1 com_1 = pc::ComputeSigmaG(input.get_g, n) * (-1);
    com_pub_53.b = com_pub.b;
    com_pub_53.b.resize(m*2, com_1);

    com_pub_53.a = com_pub.a;
    com_pub_53.a.resize(m*2, G1Zero());

    auto parallel_f = [&com_pub, &com_pub_53, &k, &m](int64_t i) {
        com_pub_53.a[i] = com_pub.a[i] * k[i];
        com_pub_53.a[i + m] = com_pub.c[i] * k[i];
    };
    parallel::For(m, parallel_f);

    typename Sec53::VerifyInput input_53(std::vector<size_t>(m*2, n), t, std::move(com_pub_53),
                                        input.get_g, input.get_g,
                                        SelectSec53Gz());
    ret_53 = Sec53::Verify(proof.proof_53, seed, std::move(input_53));

    if (!ret_53 ) {
      std::cout << "ret_53: " << ret_53 << "n";
      return false;
    }
    return true;
  }

  static bool Test(int64_t m, int64_t n);
};

template <typename Sec53, typename HyraxA>
bool Sec43a<Sec53, HyraxA>::Test(int64_t m, int64_t n) {
  Tick tick(__FN__, std::to_string(m) + "*" + std::to_string(n));

  std::vector<std::vector<Fr>> x(m, std::vector<Fr>(n));
  std::vector<std::vector<Fr>> y(m, std::vector<Fr>(n));
  std::vector<std::vector<Fr>> z(m, std::vector<Fr>(n));
  
  for (int64_t i = 0; i < m; ++i) {
    FrRand(x[i]);
    FrRand(y[i]);
    z[i] = HadamardProduct(x[i], y[i]);
  }

  h256_t seed = misc::RandH256();

  int64_t g_offset = 0;
  GetRefG1 get_g = [g_offset](int64_t i) -> G1 const& {
    return pc::PcG()[g_offset + i];
  };
  
  ProveInput prove_input(x, y, z, get_g);
  CommitmentPub com_pub;
  CommitmentSec com_sec;
  ComputeCom(com_pub, com_sec, prove_input);

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

  VerifyInput verify_input(n, com_pub, get_g);
  bool success = Verify(proof, seed, verify_input);
  std::cout << Tick::GetIndentString() << success << "\n\n\n\n\n\n";
  return success;
}
}  // namespace groth09
