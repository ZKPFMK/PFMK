#pragma once

#include "./details.h"
#include "./sumcheck.h"
#include "./a1.h"
#include "./a3.h"
#include "./a5.h"
#include "../ecc/multiexp.h"
#include "../parallel/parallel.h"

// R_{bp}: Bilinear Inner-Product (Batch Product)
// Public input: matrices A, B in F_p^{m x m}, commitment T,
//               commitments {C_j, D_j}_{j in [n]}
// P's private input: column vectors {c_j, d_j}_{j in [n]},
//                    blinding factors {theta_j, delta_j}_{j in [n]},
//                    scalar t, blinding factor tau
// Prove: <AC, BD> = t
//   where C = [c_1 | ... | c_n], D = [d_1 | ... | d_n]
//   C_j = Com(c_j, theta_j), D_j = Com(d_j, delta_j), T = Com(t, tau)
// proof size: (4*l_m + 2*l_n + 9) G1 and 9 Fr
namespace argument {
struct A11 {

  struct ProveInput {
    ProveInput(FlatMatrix const& mat_a,
               FlatMatrix const& mat_b,
               FlatMatrix const& row_c,
               FlatMatrix const& row_d,
               Fr const& t,
               GetRefG1 const& get_g)
        : mat_a(mat_a), mat_b(mat_b), row_c(row_c), row_d(row_d),
          t(t), get_g(get_g) {
    }
    int64_t m() const { return mat_a.rows(); }  // number of constraints
    int64_t n_vars() const { return mat_a.cols(); }  // number of variables
    int64_t n() const { return row_c.cols(); }  // number of instances
    std::string to_string() const {
      return std::to_string(m()) + "x" + std::to_string(n());
    }

    FlatMatrix const& mat_a;  // m x n_vars
    FlatMatrix const& mat_b;  // m x n_vars
    FlatMatrix const& row_c;  // n_vars x n
    FlatMatrix const& row_d;  // n_vars x n
    Fr const& t;
    GetRefG1 const& get_g;
  };

  struct CommitmentPub {
    CommitmentPub() {}
    G1 com_t;
    std::vector<G1> com_c;  // commitments to rows of C
    std::vector<G1> com_d;  // commitments to rows of D

    bool operator==(CommitmentPub const& right) const {
      return com_t == right.com_t && com_c == right.com_c &&
             com_d == right.com_d;
    }
    bool operator!=(CommitmentPub const& right) const {
      return !(*this == right);
    }
  };

  struct CommitmentSec {
    CommitmentSec() {}
    Fr r_com_t;
    std::vector<Fr> r_com_c;  // blinding factors for rows of C
    std::vector<Fr> r_com_d;  // blinding factors for rows of D
  };

  struct Proof {
    // SumCheck proof
    std::vector<G1> sc_com_t0;
    std::vector<G1> sc_com_t2;
    // Commitments hat_U, hat_V
    G1 hat_U;
    G1 hat_V;
    // R_{sm} sub-proof
    A1::Proof sm_proof;
    // R_{cp}^A amortized sub-proof for two instances
    A5::Proof cp_proof;

    size_t FrSize() {
      return sm_proof.FrSize() + cp_proof.FrSize();
    }

    size_t G1Size() {
      return sc_com_t0.size() + sc_com_t2.size() + 2 +
             sm_proof.G1Size() + cp_proof.G1Size();
    }

    bool operator==(Proof const& right) const {
      return sc_com_t0 == right.sc_com_t0 && sc_com_t2 == right.sc_com_t2 &&
             hat_U == right.hat_U && hat_V == right.hat_V &&
             sm_proof == right.sm_proof &&
             cp_proof == right.cp_proof;
    }
    bool operator!=(Proof const& right) const { return !(*this == right); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("A11.p", ("s0", sc_com_t0), ("s2", sc_com_t2),
                          ("hu", hat_U), ("hv", hat_V),
                          ("sm", sm_proof), ("cp", cp_proof));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("A11.p", ("s0", sc_com_t0), ("s2", sc_com_t2),
                          ("hu", hat_U), ("hv", hat_V),
                          ("sm", sm_proof), ("cp", cp_proof));
    }
  };

  struct VerifyInput {
    VerifyInput(FlatMatrix const& mat_a,
                FlatMatrix const& mat_b,
                CommitmentPub const& com_pub,
                int64_t n_val,
                GetRefG1 const& get_g)
        : mat_a(mat_a), mat_b(mat_b), com_pub(com_pub), n_val_(n_val), get_g(get_g) {}
    FlatMatrix const& mat_a;
    FlatMatrix const& mat_b;
    CommitmentPub const& com_pub;
    int64_t n_val_;  // number of columns
    GetRefG1 const& get_g;
    int64_t m() const { return mat_a.rows(); }
    int64_t n() const { return n_val_; }
    std::string to_string() const {
      return std::to_string(m()) + "x" + std::to_string(n());
    }
  };

  static void ComputeCom(CommitmentPub& com_pub, CommitmentSec& com_sec,
                         ProveInput const& input) {
    Tick tick(__FN__, input.to_string());
    int64_t n_cols = input.n();
    int64_t n_vars_val = input.n_vars();

    // Data is stored row-wise: row_c[i][j] = C[i][j]
    // But we commit to columns: com_c[j] is commitment to column j
    com_pub.com_c.resize(n_cols);
    com_pub.com_d.resize(n_cols);
    com_sec.r_com_c.resize(n_cols);
    com_sec.r_com_d.resize(n_cols);

    // Commit to each column of C and D in parallel
    auto commit_f = [&](int64_t j) {
      // Extract column j from row-wise data
      std::vector<Fr> col_c_j(n_vars_val);
      std::vector<Fr> col_d_j(n_vars_val);
      for (int64_t i = 0; i < n_vars_val; ++i) {
        col_c_j[i] = input.row_c(i, j);
        col_d_j[i] = input.row_d(i, j);
      }
      com_sec.r_com_c[j] = FrRand();
      com_pub.com_c[j] = pc::ComputeCom(input.get_g, col_c_j,
                                         com_sec.r_com_c[j]);
      com_sec.r_com_d[j] = FrRand();
      com_pub.com_d[j] = pc::ComputeCom(input.get_g, col_d_j,
                                         com_sec.r_com_d[j]);
    };
    parallel::For(n_cols, commit_f);

    // Commit to t
    com_sec.r_com_t = FrRand();
    G1 gc = pc::PcG(0);
    com_pub.com_t = pc::ComputeCom(gc, input.t, com_sec.r_com_t);
  }

  static void CheckInput(ProveInput const& input) {
    int64_t m_val = input.m();
    int64_t n_vars_val = input.n_vars();
    int64_t n_val = input.n();
    assert(m_val > 0 && n_vars_val > 0 && n_val > 0);
    assert(input.mat_b.rows() == m_val);
    assert(input.row_c.rows() == n_vars_val);
    assert(input.row_d.rows() == n_vars_val);

    // Compute AC and BD, then verify <AC, BD> = t
    Fr sum = FrZero();
    for (int64_t i = 0; i < m_val; ++i) {
      for (int64_t j = 0; j < n_val; ++j) {
        Fr ac_ij = FrZero();
        Fr bd_ij = FrZero();
        for (int64_t k = 0; k < n_vars_val; ++k) {
          ac_ij += input.mat_a(i, k) * input.row_c(k, j);
          bd_ij += input.mat_b(i, k) * input.row_d(k, j);
        }
        sum += ac_ij * bd_ij;
      }
    }
    assert(sum == input.t);
  }

  static void Prove(Proof& proof, h256_t seed,
                    ProveInput const& input,
                    CommitmentPub const& com_pub,
                    CommitmentSec const& com_sec) {
    Tick tick(__FN__, input.to_string());
    if (DEBUG_CHECK) {
      CheckInput(input);
    }

    int64_t m_val = input.m();
    int64_t n_vars_val = input.n_vars();
    int64_t n_val = input.n();
    int64_t l_m = (int64_t)misc::Log2UB(m_val);
    int64_t l_n = (int64_t)misc::Log2UB(n_val);
    int64_t l_total = l_m + l_n;
    int64_t mn = m_val * n_val;

    // Step 1: Compute u = flatten(AC), v = flatten(BD) row-wise
    // AC = A * C, BD = B * D, where row_c[i] is the i-th row of C
    // C and D are already stored in row-major format
    
    // Compute AC = A * C, BD = B * D using MatrixMul
    // A is m x n_vars, C is n_vars x n, so AC is m x n
    FlatMatrix mat_ac = MatrixMul(input.mat_a, input.row_c);
    FlatMatrix mat_bd = MatrixMul(input.mat_b, input.row_d);
    
    // Pad matrices to 2^{l_m} x 2^{l_n} size
    int64_t padded_m = 1LL << l_m;
    int64_t padded_n = 1LL << l_n;
    std::vector<Fr> u_vec(padded_m * padded_n, FrZero());
    std::vector<Fr> v_vec(padded_m * padded_n, FrZero());
    // Fill matrices in parallel
    auto fill_f = [&](int64_t i) {
      Fr const* ac_row = mat_ac.row_ptr(i);
      Fr const* bd_row = mat_bd.row_ptr(i);
      for (int64_t j = 0; j < n_val; ++j) {
        u_vec[i * padded_n + j] = ac_row[j];
        v_vec[i * padded_n + j] = bd_row[j];
      }
    };
    parallel::For(m_val, fill_f);

    // Step 2: Run ZKSC for l = l_m + l_n rounds
    G1 gc = pc::PcG(0);
    Fr hat_t = input.t;
    Fr hat_r_com_t = com_sec.r_com_t;

    // Verify input correctness before calling SumCheck
    assert(hat_t == InnerProduct(u_vec, v_vec));

    int64_t padded_mn = padded_m * padded_n;
    std::vector<Fr> e_challenges;
    SumCheck::Prove(l_total, padded_mn, proof.sc_com_t0, proof.sc_com_t2,
                    e_challenges, seed, u_vec, v_vec, hat_t, hat_r_com_t, gc);

    // After ZKSC: u_vec and v_vec are folded to scalars
    assert(u_vec.size() == 1 && v_vec.size() == 1);
    Fr hat_u = u_vec[0];
    Fr hat_v = v_vec[0];

    // Step 3: P commits to hat_u and hat_v
    Fr hat_mu = FrRand();
    Fr hat_nu = FrRand();
    proof.hat_U = pc::ComputeCom(gc, hat_u, hat_mu);
    proof.hat_V = pc::ComputeCom(gc, hat_v, hat_nu);

    UpdateSeed(seed, proof.hat_U, proof.hat_V);

    // Step 4: Compute tensor products from challenges
    std::vector<Fr> acute_e_L, acute_e_R;
    misc::ComputeAcuteTensor(acute_e_L, e_challenges, 0, l_m);
    misc::ComputeAcuteTensor(acute_e_R, e_challenges, l_m, l_n);
    
    // grave_e_L and grave_e_R are reverses of acute_e_L and acute_e_R
    std::vector<Fr> grave_e_L(acute_e_L.rbegin(), acute_e_L.rend());
    std::vector<Fr> grave_e_R(acute_e_R.rbegin(), acute_e_R.rend());

    // hat_a = acute_e_L^T * A (vector of size n_vars)
    // acute_e_L is padded to 2^l_m, we only need the first m_val elements
    std::vector<Fr> acute_e_L_trimmed(acute_e_L.begin(), acute_e_L.begin() + m_val);
    std::vector<Fr> hat_a_vec;
    MatrixVectorMul(acute_e_L_trimmed, input.mat_a, hat_a_vec);

    // hat_b = grave_e_L^T * B (vector of size n_vars)
    // grave_e_L is padded to 2^l_m, we only need the first m_val elements
    std::vector<Fr> grave_e_L_trimmed(grave_e_L.begin(), grave_e_L.begin() + m_val);
    std::vector<Fr> hat_b_vec;
    MatrixVectorMul(grave_e_L_trimmed, input.mat_b, hat_b_vec);

    // Compute C * acute_e_R: matrix-vector multiplication
    // C is n_vars x n (stored row-wise), acute_e_R is padded to 2^l_n
    // We only need the first n_val elements of acute_e_R
    std::vector<Fr> acute_e_R_trimmed(acute_e_R.begin(), acute_e_R.begin() + n_val);
    std::vector<Fr> c_acute_eR;
    MatrixVectorMul(input.row_c, acute_e_R_trimmed, c_acute_eR);

    // Compute D * grave_e_R: matrix-vector multiplication
    // D is n_vars x n (stored row-wise), grave_e_R is padded to 2^l_n
    // We only need the first n_val elements of grave_e_R
    std::vector<Fr> grave_e_R_trimmed(grave_e_R.begin(), grave_e_R.begin() + n_val);
    std::vector<Fr> d_grave_eR;
    MatrixVectorMul(input.row_d, grave_e_R_trimmed, d_grave_eR);

    // Blinding factors for C*acute_e_R and D*grave_e_R
    // com_c[j] is commitment to column j, so:
    // C * acute_e_R = sum_j col_j * acute_e_R[j]
    // r_c_acute = sum_j r_com_c[j] * acute_e_R[j]
    Fr r_c_acute = InnerProduct(com_sec.r_com_c, acute_e_R);
    Fr r_d_grave = InnerProduct(com_sec.r_com_d, grave_e_R);

    // Step 5: Run R_{sm} to prove hat_t = hat_u * hat_v
    A1::ProveInput sm_input(hat_u, hat_v, hat_t);
    A1::CommitmentPub sm_com_pub(proof.hat_U, proof.hat_V,
                                  pc::ComputeCom(gc, hat_t, hat_r_com_t));
    A1::CommitmentSec sm_com_sec(hat_mu, hat_nu, hat_r_com_t);
    A1::Prove(proof.sm_proof, seed, sm_input, sm_com_sec);

    // Step 6: Run R_{cp}^A (amortized) for two instances:
    // hat_u = <hat_a_vec, c_acute_eR> and hat_v = <hat_b_vec, d_grave_eR>
    // Verify the input relationships before calling A5
    assert(hat_u == InnerProduct(hat_a_vec, c_acute_eR));
    assert(hat_v == InnerProduct(hat_b_vec, d_grave_eR));
    
    std::vector<std::vector<Fr>> cp_b_vv = {hat_a_vec, hat_b_vec};
    std::vector<std::vector<Fr>> cp_a_vv = {c_acute_eR, d_grave_eR};
    std::vector<Fr> cp_c = {hat_u, hat_v};
    A5::ProveInput cp_input(cp_a_vv, cp_b_vv, cp_c, input.get_g, gc);
    A5::CommitmentSec cp_com_sec({r_c_acute, r_d_grave}, {hat_mu, hat_nu});
    A5::Prove(proof.cp_proof, seed, cp_input, cp_com_sec);
  }

  static bool Verify(Proof const& proof, h256_t seed,
                     VerifyInput const& input) {
    Tick tick(__FN__, input.to_string());

    int64_t m_val = input.m();
    int64_t n_vars_val = input.mat_a.cols();
    int64_t n_val = input.n();
    int64_t l_m = (int64_t)misc::Log2UB(m_val);
    int64_t l_n = (int64_t)misc::Log2UB(n_val);
    int64_t l_total = l_m + l_n;

    // Step 1: Verify ZKSC
    G1 gc = pc::PcG(0);
    G1 com_t = input.com_pub.com_t;

    std::vector<Fr> e_challenges;
    SumCheck::Verify(proof.sc_com_t0, proof.sc_com_t2, seed, com_t,
                     e_challenges);
    assert((int64_t)e_challenges.size() == l_total);

    // Step 2: Receive hat_U, hat_V
    UpdateSeed(seed, proof.hat_U, proof.hat_V);

    // Step 3: Compute tensor products
    std::vector<Fr> acute_e_L, acute_e_R, grave_e_L, grave_e_R;
    // SumCheck folds from MSB to LSB: e[0] is for MSB, e[l-1] is for LSB
    // But ComputeAcuteTensor expects LSB first, so we need to reverse
    misc::ComputeAcuteTensor(acute_e_L, e_challenges, 0, l_m);
    misc::ComputeAcuteTensor(acute_e_R, e_challenges, l_m, l_n);
    grave_e_L.assign(acute_e_L.rbegin(), acute_e_L.rend());
    grave_e_R.assign(acute_e_R.rbegin(), acute_e_R.rend());

    // hat_a = acute_e_L^T * A (vector of size n_vars)
    // acute_e_L is padded to 2^l_m, we only need the first m_val elements
    std::vector<Fr> acute_e_L_trimmed(acute_e_L.begin(), acute_e_L.begin() + m_val);
    std::vector<Fr> hat_a_vec;
    MatrixVectorMul(acute_e_L_trimmed, input.mat_a, hat_a_vec);

    // hat_b = grave_e_L^T * B (vector of size n_vars)
    // grave_e_L is padded to 2^l_m, we only need the first m_val elements
    std::vector<Fr> grave_e_L_trimmed(grave_e_L.begin(), grave_e_L.begin() + m_val);
    std::vector<Fr> hat_b_vec;
    MatrixVectorMul(grave_e_L_trimmed, input.mat_b, hat_b_vec);

    // hat_C = prod_{j=1}^{n} com_c[j]^{acute_e_R[j]}
    // com_c[j] is commitment to column j
    auto get_com_c = [&input](int64_t j) -> G1 const& {
      return input.com_pub.com_c[j];
    };
    auto get_acute_eR = [&acute_e_R](int64_t j) -> Fr const& {
      return acute_e_R[j];
    };
    G1 hat_C = MultiExpBdlo12Inner<G1>(get_com_c, get_acute_eR, n_val);

    // hat_D = prod_{j=1}^{n} com_d[j]^{grave_e_R[j]}
    auto get_com_d = [&input](int64_t j) -> G1 const& {
      return input.com_pub.com_d[j];
    };
    auto get_grave_eR = [&grave_e_R](int64_t j) -> Fr const& {
      return grave_e_R[j];
    };
    G1 hat_D = MultiExpBdlo12Inner<G1>(get_com_d, get_grave_eR, n_val);

    // Step 4: Verify R_{sm}: hat_t = hat_u * hat_v
    A1::CommitmentPub sm_com_pub(proof.hat_U, proof.hat_V, com_t);
    A1::VerifyInput sm_verify(sm_com_pub);
    bool sm_ret = A1::Verify(proof.sm_proof, seed, sm_verify);
    std::cout << "A1::Verify (R_{sm}) result: " << sm_ret << "\n";

    // Step 5: Verify R_{cp}^A (amortized) for two instances
    std::vector<std::vector<Fr>> cp_b_vv = {hat_a_vec, hat_b_vec};
    A5::CommitmentPub cp_com_pub({hat_C, hat_D}, {proof.hat_U, proof.hat_V});
    A5::VerifyInput cp_verify(cp_b_vv, cp_com_pub, input.get_g, gc);
    bool cp_ret = A5::Verify(proof.cp_proof, seed, cp_verify);
    std::cout << "A5::Verify (R_{cp}^A) result: " << cp_ret << "\n";

    bool ret = sm_ret && cp_ret;
    return ret;
  }

  static bool Test(int64_t m_val, int64_t n_val);
};

bool A11::Test(int64_t m_val, int64_t n_val) {
  Tick tick(__FN__, std::to_string(m_val) + "x" + std::to_string(n_val));

  // Generate random matrices A, B (m x m)
  FlatMatrix mat_a(m_val, m_val);
  FlatMatrix mat_b(m_val, m_val);
  FrRand(mat_a.data_.data(), mat_a.data_.size());
  FrRand(mat_b.data_.data(), mat_b.data_.size());

  // Generate random row vectors for C and D (each row has n elements)
  // C and D are m x n matrices stored row-wise
  FlatMatrix row_c(m_val, n_val);
  FlatMatrix row_d(m_val, n_val);
  FrRand(row_c.data_.data(), row_c.data_.size());
  FrRand(row_d.data_.data(), row_d.data_.size());

  // Compute t = <AC, BD>
  Fr t_val = FrZero();
  for (int64_t i = 0; i < m_val; ++i) {
    for (int64_t j = 0; j < n_val; ++j) {
      Fr ac_ij = FrZero();
      Fr bd_ij = FrZero();
      for (int64_t k = 0; k < m_val; ++k) {
        ac_ij += mat_a(i, k) * row_c(k, j);
        bd_ij += mat_b(i, k) * row_d(k, j);
      }
      t_val += ac_ij * bd_ij;
    }
  }

  h256_t seed = misc::RandH256();
  GetRefG1 get_g = pc::kGetRefG1;

  ProveInput prove_input(mat_a, mat_b, row_c, row_d, t_val, get_g);

  CommitmentPub com_pub;
  CommitmentSec com_sec;
  ComputeCom(com_pub, com_sec, prove_input);

  Proof proof;
  Prove(proof, seed, prove_input, com_pub, com_sec);

#ifndef DISABLE_SERIALIZE_CHECK
  yas::mem_ostream os;
  yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
  oa.serialize(proof);
  std::cout << "proof size: " << os.get_shared_buffer().size << "\n";

  yas::mem_istream is(os.get_intrusive_buffer());
  yas::binary_iarchive<yas::mem_istream, YasBinF()> ia(is);
  Proof proof2;
  ia.serialize(proof2);
  if (proof != proof2) {
    assert(false);
    std::cout << "oops, serialize check failed\n";
    return false;
  }
  std::cout << "FrSize:" << proof.FrSize() << "\t G1Size:" << proof.G1Size()
            << "\n";
#endif

  VerifyInput verify_input(mat_a, mat_b, com_pub, n_val, get_g);
  bool success = Verify(proof, seed, verify_input);
  std::cout << __FILE__ << " " << __FN__ << ": " << success << "\n\n\n\n\n\n";
  return success;
}
}  // namespace argument
