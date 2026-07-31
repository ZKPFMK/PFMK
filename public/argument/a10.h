#pragma once

#include "./details.h"
#include "./sumcheck.h"
#include "./a3.h"
#include "../ecc/multiexp.h"
#include "../parallel/parallel.h"

// R_{cc}: Copy Constraint
// A, B: commitments to vectors a, b of size n
// l_a, l_b: starting positions (0-indexed) of the copy region
// l: length of the copy region
// prove: forall j in [l], a[l_a + j] = b[l_b + j]
// proof size: 2log(n)+4 G1 and 4 Fr
//
// R_{cc}^A: Amortized Copy Constraint
// Amortizes m instances of R_{cc} into a single execution via random
// linear combination.
namespace argument {

// CopyRange: Describes a single copy constraint region
// z_j[l_a + k] == z_{j+1}[l_b + k] for k in [0, l)
struct CopyRange {
  int64_t l_a;  // source offset in z_j
  int64_t l_b;  // destination offset in z_{j+1}
  int64_t l;    // copy length

  CopyRange() : l_a(0), l_b(0), l(0) {}
  CopyRange(int64_t l_a, int64_t l_b, int64_t l) : l_a(l_a), l_b(l_b), l(l) {}
};

struct A10 {
  struct ProveInput {
    ProveInput(std::vector<Fr> const& a, std::vector<Fr> const& b,
               int64_t l_a, int64_t l_b, int64_t l,
               GetRefG1 const& get_g)
        : a(a), b(b), l_a(l_a), l_b(l_b), l(l), get_g(get_g) {
    }
    int64_t n() const { return (int64_t)a.size(); }
    std::string to_string() const { return std::to_string(n()); }

    std::vector<Fr> const& a;
    std::vector<Fr> const& b;
    int64_t l_a;
    int64_t l_b;
    int64_t l;
    GetRefG1 const& get_g;
  };

  struct CommitmentPub {
    CommitmentPub() {}
    CommitmentPub(G1 const& com_a, G1 const& com_b)
        : com_a(com_a), com_b(com_b) {}
    G1 com_a;
    G1 com_b;

    bool operator==(CommitmentPub const& right) const {
      return com_a == right.com_a && com_b == right.com_b;
    }
    bool operator!=(CommitmentPub const& right) const {
      return !(*this == right);
    }
  };

  struct CommitmentSec {
    CommitmentSec() {}
    CommitmentSec(Fr const& r_com_a, Fr const& r_com_b)
        : r_com_a(r_com_a), r_com_b(r_com_b) {}
    Fr r_com_a;
    Fr r_com_b;
  };

  struct Proof {
    std::vector<G1> sc_com_t0;
    std::vector<G1> sc_com_t2;
    A3::Proof sub_proof;

    size_t FrSize() {
      return sub_proof.FrSize();
    }

    size_t G1Size() {
      return sc_com_t0.size() + sc_com_t2.size() + sub_proof.G1Size();
    }

    bool operator==(Proof const& right) const {
      return sc_com_t0 == right.sc_com_t0 &&
             sc_com_t2 == right.sc_com_t2 &&
             sub_proof == right.sub_proof;
    }
    bool operator!=(Proof const& right) const { return !(*this == right); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("A10.p", ("s0", sc_com_t0), ("s2", sc_com_t2),
                          ("sp", sub_proof));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("A10.p", ("s0", sc_com_t0), ("s2", sc_com_t2),
                          ("sp", sub_proof));
    }
  };

  struct VerifyInput {
    VerifyInput(CommitmentPub const& com_pub,
                int64_t l_a, int64_t l_b, int64_t l, int64_t n,
                GetRefG1 const& get_g)
        : com_pub(com_pub), l_a(l_a), l_b(l_b), l(l), n(n), get_g(get_g) {}
    CommitmentPub const& com_pub;
    int64_t l_a;
    int64_t l_b;
    int64_t l;
    int64_t n;
    GetRefG1 const& get_g;
    std::string to_string() const { return std::to_string(n); }
  };

  static void ComputeCom(CommitmentPub& com_pub, CommitmentSec& com_sec,
                         ProveInput const& input) {
    Tick tick(__FN__, input.to_string());
    std::array<parallel::VoidTask, 2> tasks;
    tasks[0] = [&com_pub, &input, &com_sec]() {
      com_sec.r_com_a = FrRand();
      com_pub.com_a = pc::ComputeCom(input.get_g, input.a, com_sec.r_com_a);
    };
    tasks[1] = [&com_pub, &input, &com_sec]() {
      com_sec.r_com_b = FrRand();
      com_pub.com_b = pc::ComputeCom(input.get_g, input.b, com_sec.r_com_b);
    };
    parallel::Invoke(tasks);
  }

  static void CheckInput(ProveInput const& input) {
    assert(input.a.size() == input.b.size() && !input.a.empty());
    assert(input.l_a >= 0 && input.l_b >= 0 && input.l > 0);
    assert(input.l_a + input.l <= input.n());
    assert(input.l_b + input.l <= input.n());
    for (int64_t j = 0; j < input.l; ++j) {
      assert(input.a[input.l_a + j] == input.b[input.l_b + j]);
    }
  }

  static void CheckCom(ProveInput const& input,
                        CommitmentPub const& com_pub,
                        CommitmentSec const& com_sec) {
    assert(pc::ComputeCom(input.get_g, input.a, com_sec.r_com_a) ==
           com_pub.com_a);
    assert(pc::ComputeCom(input.get_g, input.b, com_sec.r_com_b) ==
           com_pub.com_b);
  }

  static void CheckWitness(ProveInput const& input,
                            CommitmentPub const& com_pub,
                            CommitmentSec const& com_sec) {
    Tick tick(__FN__);
    CheckInput(input);
    CheckCom(input, com_pub, com_sec);
  }

  // Build selection vectors c and d from random challenge r.
  // c[l_a + j] = r[j], d[l_b + j] = -r[j], all others 0.
  static void BuildSelectionVectors(std::vector<Fr>& c_vec,
                                    std::vector<Fr>& d_vec,
                                    std::vector<Fr> const& r_challenge,
                                    int64_t n, int64_t l_a, int64_t l_b,
                                    int64_t l) {
    c_vec.assign(n, FrZero());
    d_vec.assign(n, FrZero());
    for (int64_t j = 0; j < l; ++j) {
      c_vec[l_a + j] = r_challenge[j];
      Fr neg_r;
      Fr::neg(neg_r, r_challenge[j]);
      d_vec[l_b + j] = neg_r;
    }
  }

  // Derive the random challenge vector r of length l via Fiat-Shamir.
  static void DeriveRChallenge(h256_t& seed, int64_t l_a, int64_t l_b,
                               int64_t l, std::vector<Fr>& r_challenge) {
    r_challenge.resize(l);
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    auto hash_int = [&hash](int64_t v) {
      uint64_t buf = (uint64_t)v;
      hash.Update((uint8_t const*)&buf, sizeof(buf));
    };
    hash_int(l_a);
    hash_int(l_b);
    hash_int(l);
    hash.Final(seed.data());

    for (int64_t j = 0; j < l; ++j) {
      r_challenge[j] = H256ToFr(seed);
      CryptoPP::Keccak_256 h2;
      HashUpdate(h2, seed);
      h2.Final(seed.data());
    }
  }

  // R_{cc} single instance: Prove
  static void Prove(Proof& proof, h256_t seed,
                    ProveInput const& input,
                    CommitmentPub const& com_pub,
                    CommitmentSec const& com_sec) {
    Tick tick(__FN__, input.to_string());
    if (DEBUG_CHECK) {
      CheckInput(input);
    }

    int64_t n = input.n();
    int64_t l = input.l;
    int64_t l_a = input.l_a;
    int64_t l_b = input.l_b;

    // Step 1: Derive r challenge vector via Fiat-Shamir
    std::vector<Fr> r_challenge;
    DeriveRChallenge(seed, l_a, l_b, l, r_challenge);

    // Step 2: Build selection vectors c, d in F_p^n
    std::vector<Fr> c_vec, d_vec;
    BuildSelectionVectors(c_vec, d_vec, r_challenge, n, l_a, l_b, l);

    // Step 3: Define u = (a, b) in F_p^{2n}, v = (c, d) in F_p^{2n}
    // w = 0, omega = 0, W = Com(0, 0)
    std::vector<Fr> u_vec(2 * n);
    std::vector<Fr> v_vec(2 * n);
    auto build_f = [&u_vec, &v_vec, &input, &c_vec, &d_vec, n](int64_t i) {
      if (i < n) {
        u_vec[i] = input.a[i];
        v_vec[i] = c_vec[i];
      } else {
        u_vec[i] = input.b[i - n];
        v_vec[i] = d_vec[i - n];
      }
    };
    parallel::For(2 * n, build_f);

    Fr w = FrZero();
    Fr r_com_w = FrZero();
    G1 gc = pc::PcG(0);
    G1 com_w = pc::ComputeCom(gc, w, r_com_w);

    // Step 4: Run ZKSC_1 (one round of zero-knowledge sumcheck)
    auto u_copy = u_vec;
    auto v_copy = v_vec;
    Fr hat_w = w;
    Fr hat_r_com_w = r_com_w;

    auto& sc_com_t0 = proof.sc_com_t0;
    auto& sc_com_t2 = proof.sc_com_t2;

    std::vector<Fr> e_vec;
    int64_t round = 1;
    SumCheck::Prove(round, 2 * n, sc_com_t0, sc_com_t2, e_vec, seed,
                    u_copy, v_copy, hat_w, hat_r_com_w, gc);

    // After ZKSC_1: u_copy = hat_u of size n, v_copy = hat_v of size n
    // hat_u = a + e * b, hat_v = e * c + d
    Fr e = e_vec[0];
    auto& hat_u = u_copy;
    auto& hat_v = v_copy;

    // Step 5: Compute hat_mu = alpha + e * beta
    Fr hat_mu = com_sec.r_com_a + e * com_sec.r_com_b;

    // Step 6: Run PoK for R_{cp}
    // R_{cp}: prove hat_w = <hat_u, hat_v>
    A3::ProveInput cp_input(hat_u, hat_v, hat_w, input.get_g, gc);
    A3::CommitmentSec cp_com_sec(hat_mu, hat_r_com_w);
    A3::Prove(proof.sub_proof, seed, cp_input, cp_com_sec);
  }

  // R_{cc} single instance: Verify
  static bool Verify(Proof const& proof, h256_t seed,
                     VerifyInput const& input) {
    Tick tick(__FN__, input.to_string());

    int64_t n = input.n;
    int64_t l = input.l;
    int64_t l_a = input.l_a;
    int64_t l_b = input.l_b;

    // Step 1: Derive r challenge vector
    std::vector<Fr> r_challenge;
    DeriveRChallenge(seed, l_a, l_b, l, r_challenge);

    // Step 2: Build selection vectors c, d
    std::vector<Fr> c_vec, d_vec;
    BuildSelectionVectors(c_vec, d_vec, r_challenge, n, l_a, l_b, l);

    // Step 3: Verify ZKSC_1
    G1 gc = pc::PcG(0);
    G1 com_w = pc::ComputeCom(gc, FrZero(), FrZero());

    std::vector<Fr> e_vec;
    SumCheck::Verify(proof.sc_com_t0, proof.sc_com_t2, seed, com_w, e_vec);
    assert(e_vec.size() == 1);
    Fr e = e_vec[0];

    // Fold v: hat_v[i] = e * c[i] + d[i]
    std::vector<Fr> hat_v(n);
    auto fold_f = [&hat_v, &c_vec, &d_vec, &e](int64_t i) {
      hat_v[i] = e * c_vec[i] + d_vec[i];
    };
    parallel::For(n, fold_f);

    // Step 4: Compute hat_U = A * B^e
    G1 hat_U = input.com_pub.com_a + input.com_pub.com_b * e;

    // Step 5: Verify R_{cp}
    A3::CommitmentPub cp_com_pub(hat_U, com_w);
    A3::VerifyInput cp_input(hat_v, cp_com_pub, input.get_g, gc);
    return A3::Verify(proof.sub_proof, seed, cp_input);
  }

  // R_{cc}^A: Amortized version - Prove
  static void ProveAmortized(Proof& proof, h256_t seed,
                             std::vector<std::vector<Fr>> const& a_vec,
                             std::vector<std::vector<Fr>> const& b_vec,
                             std::vector<CommitmentPub> const& com_pubs,
                             std::vector<CommitmentSec> const& com_secs,
                             int64_t l_a, int64_t l_b, int64_t l,
                             GetRefG1 const& get_g) {
    Tick tick(__FN__);
    int64_t m = (int64_t)a_vec.size();
    int64_t n = (int64_t)a_vec[0].size();
    assert(m > 0);

    // Step 1: Derive amortization challenge e
    for (int64_t i = 0; i < m; ++i) {
      UpdateSeed(seed, com_pubs[i].com_a, com_pubs[i].com_b);
    }
    Fr e = H256ToFr(seed);

    // Step 2: Precompute e powers vector
    std::vector<Fr> e_powers(m);
    e_powers[0] = FrOne();
    for (int64_t i = 1; i < m; ++i) {
      e_powers[i] = e_powers[i - 1] * e;
    }

    // Step 3: Compute aggregated vectors in parallel
    std::vector<Fr> hat_a(n, FrZero());
    std::vector<Fr> hat_b(n, FrZero());
    auto parallel_aggregate = [&](int64_t j) {
      for (int64_t i = 0; i < m; ++i) {
        hat_a[j] += e_powers[i] * a_vec[i][j];
        hat_b[j] += e_powers[i] * b_vec[i][j];
      }
    };
    parallel::For(n, parallel_aggregate);

    // Step 4: Compute aggregated blinding factors
    Fr hat_alpha = FrZero();
    Fr hat_beta = FrZero();
    for (int64_t i = 0; i < m; ++i) {
      hat_alpha += e_powers[i] * com_secs[i].r_com_a;
      hat_beta += e_powers[i] * com_secs[i].r_com_b;
    }

    // Step 5: Compute aggregated commitments using MultiExp
    auto get_com_a = [&com_pubs](int64_t i) -> G1 const& {
      return com_pubs[i].com_a;
    };
    auto get_com_b = [&com_pubs](int64_t i) -> G1 const& {
      return com_pubs[i].com_b;
    };
    auto get_e_power = [&e_powers](int64_t i) -> Fr const& {
      return e_powers[i];
    };
    G1 hat_A = MultiExpBdlo12Inner<G1>(get_com_a, get_e_power, m);
    G1 hat_B = MultiExpBdlo12Inner<G1>(get_com_b, get_e_power, m);

    // Step 6: Run R_{cc} on the aggregated instance
    CommitmentPub hat_com_pub(hat_A, hat_B);
    CommitmentSec hat_com_sec(hat_alpha, hat_beta);
    ProveInput hat_input(hat_a, hat_b, l_a, l_b, l, get_g);
    Prove(proof, seed, hat_input, hat_com_pub, hat_com_sec);
  }

  // R_{cc}^A: Amortized version - Verify
  static bool VerifyAmortized(Proof const& proof, h256_t seed,
                              std::vector<CommitmentPub> const& com_pubs,
                              int64_t l_a, int64_t l_b, int64_t l, int64_t n,
                              GetRefG1 const& get_g) {
    Tick tick(__FN__);
    int64_t m = (int64_t)com_pubs.size();
    assert(m > 0);

    // Step 1: Derive amortization challenge e
    for (int64_t i = 0; i < m; ++i) {
      UpdateSeed(seed, com_pubs[i].com_a, com_pubs[i].com_b);
    }
    Fr e = H256ToFr(seed);

    // Step 2: Precompute e powers vector
    std::vector<Fr> e_powers(m);
    e_powers[0] = FrOne();
    for (int64_t i = 1; i < m; ++i) {
      e_powers[i] = e_powers[i - 1] * e;
    }

    // Step 3: Compute aggregated commitments using MultiExp
    auto get_com_a = [&com_pubs](int64_t i) -> G1 const& {
      return com_pubs[i].com_a;
    };
    auto get_com_b = [&com_pubs](int64_t i) -> G1 const& {
      return com_pubs[i].com_b;
    };
    auto get_e_power = [&e_powers](int64_t i) -> Fr const& {
      return e_powers[i];
    };
    G1 hat_A = MultiExpBdlo12Inner<G1>(get_com_a, get_e_power, m);
    G1 hat_B = MultiExpBdlo12Inner<G1>(get_com_b, get_e_power, m);

    // Step 4: Verify R_{cc} on the aggregated instance
    CommitmentPub hat_com_pub(hat_A, hat_B);
    VerifyInput hat_input(hat_com_pub, l_a, l_b, l, n, get_g);
    return Verify(proof, seed, hat_input);
  }

  // Multi-range DeriveRChallenge: derive challenge vector for multiple copy ranges
  static void DeriveRChallenge(h256_t& seed,
                               std::vector<CopyRange> const& ranges,
                               std::vector<Fr>& r_challenge) {
    int64_t total_l = 0;
    for (auto const& range : ranges) {
      total_l += range.l;
    }
    r_challenge.resize(total_l);
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    auto hash_int = [&hash](int64_t v) {
      uint64_t buf = (uint64_t)v;
      hash.Update((uint8_t const*)&buf, sizeof(buf));
    };
    for (auto const& range : ranges) {
      hash_int(range.l_a);
      hash_int(range.l_b);
      hash_int(range.l);
    }
    hash.Final(seed.data());

    for (int64_t j = 0; j < total_l; ++j) {
      r_challenge[j] = H256ToFr(seed);
      CryptoPP::Keccak_256 h2;
      HashUpdate(h2, seed);
      h2.Final(seed.data());
    }
  }

  // Multi-range BuildSelectionVectors
  static void BuildSelectionVectors(std::vector<Fr>& c_vec,
                                    std::vector<Fr>& d_vec,
                                    std::vector<Fr> const& r_challenge,
                                    int64_t n,
                                    std::vector<CopyRange> const& ranges) {
    c_vec.assign(n, FrZero());
    d_vec.assign(n, FrZero());
    int64_t r_offset = 0;
    for (auto const& range : ranges) {
      for (int64_t j = 0; j < range.l; ++j) {
        c_vec[range.l_a + j] = r_challenge[r_offset + j];
        Fr neg_r;
        Fr::neg(neg_r, r_challenge[r_offset + j]);
        d_vec[range.l_b + j] = neg_r;
      }
      r_offset += range.l;
    }
  }

  // Multi-range ProveAmortized
  static void ProveAmortized(Proof& proof, h256_t seed,
                             std::vector<std::vector<Fr>> const& a_vec,
                             std::vector<std::vector<Fr>> const& b_vec,
                             std::vector<CommitmentPub> const& com_pubs,
                             std::vector<CommitmentSec> const& com_secs,
                             std::vector<CopyRange> const& ranges,
                             GetRefG1 const& get_g) {
    Tick tick(__FN__);
    int64_t m = (int64_t)a_vec.size();
    int64_t n = (int64_t)a_vec[0].size();
    assert(m > 0);

    for (int64_t i = 0; i < m; ++i) {
      UpdateSeed(seed, com_pubs[i].com_a, com_pubs[i].com_b);
    }
    Fr e = H256ToFr(seed);

    std::vector<Fr> e_powers(m);
    e_powers[0] = FrOne();
    for (int64_t i = 1; i < m; ++i) {
      e_powers[i] = e_powers[i - 1] * e;
    }

    std::vector<Fr> hat_a(n, FrZero());
    std::vector<Fr> hat_b(n, FrZero());
    auto parallel_aggregate = [&](int64_t j) {
      for (int64_t i = 0; i < m; ++i) {
        hat_a[j] += e_powers[i] * a_vec[i][j];
        hat_b[j] += e_powers[i] * b_vec[i][j];
      }
    };
    parallel::For(n, parallel_aggregate);

    Fr hat_alpha = FrZero();
    Fr hat_beta = FrZero();
    for (int64_t i = 0; i < m; ++i) {
      hat_alpha += e_powers[i] * com_secs[i].r_com_a;
      hat_beta += e_powers[i] * com_secs[i].r_com_b;
    }

    auto get_com_a = [&com_pubs](int64_t i) -> G1 const& { return com_pubs[i].com_a; };
    auto get_com_b = [&com_pubs](int64_t i) -> G1 const& { return com_pubs[i].com_b; };
    auto get_e_power = [&e_powers](int64_t i) -> Fr const& { return e_powers[i]; };
    G1 hat_A = MultiExpBdlo12Inner<G1>(get_com_a, get_e_power, m);
    G1 hat_B = MultiExpBdlo12Inner<G1>(get_com_b, get_e_power, m);

    CommitmentPub hat_com_pub(hat_A, hat_B);
    CommitmentSec hat_com_sec(hat_alpha, hat_beta);
    ProveInput hat_input(hat_a, hat_b, ranges[0].l_a, ranges[0].l_b, ranges[0].l, get_g);

    // For multi-range, use the full selection vector approach
    std::vector<Fr> r_challenge;
    DeriveRChallenge(seed, ranges, r_challenge);

    std::vector<Fr> c_vec, d_vec;
    BuildSelectionVectors(c_vec, d_vec, r_challenge, n, ranges);

    std::vector<Fr> u_vec(2 * n);
    std::vector<Fr> v_vec(2 * n);
    auto build_f = [&](int64_t i) {
      if (i < n) {
        u_vec[i] = hat_a[i];
        v_vec[i] = c_vec[i];
      } else {
        u_vec[i] = hat_b[i - n];
        v_vec[i] = d_vec[i - n];
      }
    };
    parallel::For(2 * n, build_f);

    Fr w = FrZero();
    Fr r_com_w = FrZero();
    G1 gc = pc::PcG(0);

    auto u_copy = u_vec;
    auto v_copy = v_vec;
    Fr hat_w = w;
    Fr hat_r_com_w = r_com_w;

    std::vector<Fr> e_vec;
    int64_t round = 1;
    SumCheck::Prove(round, 2 * n, proof.sc_com_t0, proof.sc_com_t2,
                    e_vec, seed, u_copy, v_copy, hat_w, hat_r_com_w, gc);

    Fr e_sc = e_vec[0];
    auto& hat_u = u_copy;
    auto& hat_v = v_copy;

    Fr hat_mu = hat_alpha + e_sc * hat_beta;
    G1 hat_U = hat_A + hat_B * e_sc;

    A3::ProveInput cp_input(hat_u, hat_v, hat_w, get_g, gc);
    A3::CommitmentSec cp_com_sec(hat_mu, hat_r_com_w);
    A3::Prove(proof.sub_proof, seed, cp_input, cp_com_sec);
  }

  // Multi-range VerifyAmortized
  static bool VerifyAmortized(Proof const& proof, h256_t seed,
                              std::vector<CommitmentPub> const& com_pubs,
                              std::vector<CopyRange> const& ranges,
                              int64_t n,
                              GetRefG1 const& get_g) {
    Tick tick(__FN__);
    int64_t m = (int64_t)com_pubs.size();
    assert(m > 0);

    for (int64_t i = 0; i < m; ++i) {
      UpdateSeed(seed, com_pubs[i].com_a, com_pubs[i].com_b);
    }
    Fr e = H256ToFr(seed);

    std::vector<Fr> e_powers(m);
    e_powers[0] = FrOne();
    for (int64_t i = 1; i < m; ++i) {
      e_powers[i] = e_powers[i - 1] * e;
    }

    auto get_com_a = [&com_pubs](int64_t i) -> G1 const& { return com_pubs[i].com_a; };
    auto get_com_b = [&com_pubs](int64_t i) -> G1 const& { return com_pubs[i].com_b; };
    auto get_e_power = [&e_powers](int64_t i) -> Fr const& { return e_powers[i]; };
    G1 hat_A = MultiExpBdlo12Inner<G1>(get_com_a, get_e_power, m);
    G1 hat_B = MultiExpBdlo12Inner<G1>(get_com_b, get_e_power, m);

    std::vector<Fr> r_challenge;
    DeriveRChallenge(seed, ranges, r_challenge);

    std::vector<Fr> c_vec, d_vec;
    BuildSelectionVectors(c_vec, d_vec, r_challenge, n, ranges);

    G1 gc = pc::PcG(0);
    G1 com_w = pc::ComputeCom(gc, FrZero(), FrZero());

    std::vector<Fr> e_vec;
    SumCheck::Verify(proof.sc_com_t0, proof.sc_com_t2, seed, com_w, e_vec);
    assert(e_vec.size() == 1);
    Fr e_sc = e_vec[0];

    std::vector<Fr> hat_v(n);
    auto fold_f = [&hat_v, &c_vec, &d_vec, &e_sc](int64_t i) {
      hat_v[i] = e_sc * c_vec[i] + d_vec[i];
    };
    parallel::For(n, fold_f);

    G1 hat_U = hat_A + hat_B * e_sc;

    A3::CommitmentPub cp_com_pub(hat_U, com_w);
    A3::VerifyInput cp_input(hat_v, cp_com_pub, get_g, gc);
    return A3::Verify(proof.sub_proof, seed, cp_input);
  }

  // Test function for multi-range copy constraints.
  static bool TestMultiRange(int64_t n,
                             std::vector<CopyRange> const& ranges,
                             int64_t m_amort = 1) {
    std::cout << "\n=== A10::TestMultiRange n=" << n
              << " ranges=" << ranges.size() << " m_amort=" << m_amort << " ===\n";

    std::vector<std::vector<Fr>> a_vec(m_amort), b_vec(m_amort);
    std::vector<CommitmentPub> com_pubs(m_amort);
    std::vector<CommitmentSec> com_secs(m_amort);

    for (int64_t k = 0; k < m_amort; ++k) {
      a_vec[k].resize(n);
      b_vec[k].resize(n);
      for (int64_t i = 0; i < n; ++i) {
        a_vec[k][i] = FrRand();
      }
      for (int64_t i = 0; i < n; ++i) {
        b_vec[k][i] = a_vec[k][i];
      }
      for (auto const& range : ranges) {
        for (int64_t j = 0; j < range.l; ++j) {
          b_vec[k][range.l_b + j] = a_vec[k][range.l_a + j];
        }
      }
      com_secs[k].r_com_a = FrRand();
      com_secs[k].r_com_b = FrRand();
      com_pubs[k].com_a = pc::ComputeCom(pc::kGetRefG1, a_vec[k], com_secs[k].r_com_a, true);
      com_pubs[k].com_b = pc::ComputeCom(pc::kGetRefG1, b_vec[k], com_secs[k].r_com_b, true);
    }

    h256_t seed = misc::RandH256();
    Proof proof;
    if (m_amort == 1) {
      ProveInput input(a_vec[0], b_vec[0], ranges[0].l_a, ranges[0].l_b, ranges[0].l, pc::kGetRefG1);
      Prove(proof, seed, input, com_pubs[0], com_secs[0]);
    } else {
      ProveAmortized(proof, seed, a_vec, b_vec, com_pubs, com_secs, ranges, pc::kGetRefG1);
    }

    bool result;
    if (m_amort == 1) {
      VerifyInput input(com_pubs[0], ranges[0].l_a, ranges[0].l_b, ranges[0].l, n, pc::kGetRefG1);
      result = Verify(proof, seed, input);
    } else {
      result = VerifyAmortized(proof, seed, com_pubs, ranges, n, pc::kGetRefG1);
    }

    std::cout << "A10::TestMultiRange result: " << result << "\n";
    return result;
  }
};

}  // namespace argument
