#pragma once

#include "./details.h"
#include "./a3.h"
#include "./a10.h"
#include "./a11.h"
#include "../ecc/multiexp.h"
#include "../parallel/parallel.h"

// R_{if}: Iterated Function
// Public input: R1CS constraint matrices A, B, C in F_p^{m x m},
//               commitments {Z_j}_{j in [n]}
// P's private input: assignment vectors {z_j}_{j in [n]},
//                    blinding factors {zeta_j}_{j in [n]}
// Prove:
//   1. (A * Z) o (B * Z) = C * Z  (R1CS satisfiability for all n instances)
//   2. Copy constraints between consecutive instances (output of j-th = input of (j+1)-th)
// proof size: n + 4*log(m) + 2*log(n) + 14 G1 and 9 Fr
namespace argument {
struct A12 {

  struct CommitmentPub {
    CommitmentPub() {}
    std::vector<G1> com_z;  // commitments to columns of Z

    bool operator==(CommitmentPub const& right) const {
      return com_z == right.com_z;
    }
    bool operator!=(CommitmentPub const& right) const {
      return !(*this == right);
    }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("A12.cpub", ("cz", com_z));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("A12.cpub", ("cz", com_z));
    }
  };

  struct CommitmentSec {
    CommitmentSec() {}
    std::vector<Fr> r_com_z;  // blinding factors for columns of Z

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("A12.csec", ("rz", r_com_z));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("A12.csec", ("rz", r_com_z));
    }
  };

  struct Proof {
    G1 com_t;  // commitment to t
    // R_{bp} sub-proof
    A11::Proof bp_proof;
    // R_{cp} sub-proof for <hat_c, hat_r> = t
    A3::Proof cp_proof;
    // R_{cc}^A sub-proof for copy constraints
    A10::Proof cc_proof;

    size_t FrSize() {
      return bp_proof.FrSize() + cp_proof.FrSize() + cc_proof.FrSize();
    }

    size_t G1Size() {
      return 1 + bp_proof.G1Size() + cp_proof.G1Size() + cc_proof.G1Size();
    }

    bool operator==(Proof const& right) const {
      return com_t == right.com_t && bp_proof == right.bp_proof &&
             cp_proof == right.cp_proof && cc_proof == right.cc_proof;
    }
    bool operator!=(Proof const& right) const { return !(*this == right); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("A12.p", ("ct", com_t), ("bp", bp_proof),
                          ("cp", cp_proof), ("cc", cc_proof));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("A12.p", ("ct", com_t), ("bp", bp_proof),
                          ("cp", cp_proof), ("cc", cc_proof));
    }
  };

  // Derive random challenges r (length n) and s via Fiat-Shamir
  static void DeriveChallenges(h256_t& seed,
                               std::vector<G1> const& com_z,
                               std::vector<Fr>& r_challenge,
                               Fr& s_challenge) {
    for (auto const& cz : com_z) {
      UpdateSeed(seed, cz);
    }

    int64_t n_val = (int64_t)com_z.size();
    r_challenge.resize(n_val);
    for (int64_t j = 0; j < n_val; ++j) {
      r_challenge[j] = H256ToFr(seed);
      CryptoPP::Keccak_256 h2;
      HashUpdate(h2, seed);
      h2.Final(seed.data());
    }
    s_challenge = H256ToFr(seed);
    CryptoPP::Keccak_256 h3;
    HashUpdate(h3, seed);
    h3.Final(seed.data());
  }

  // ============================================================
  // Structures and functions for decomposed proving
  // ============================================================

  // Structure to hold all R_{cp}^A instances for batched proving
  // Combines instances from R_{bp} (2), R_{cp} (1), and R_{cc}^A (1 if n>1)
  struct IfCpAInstance {
    // A5 (R_{cp}^A) prove input data (owned copies)
    std::vector<std::vector<Fr>> cp_a;   // inner product vectors a_i
    std::vector<std::vector<Fr>> cp_b;   // inner product vectors b_i
    std::vector<Fr> cp_c;                // inner product results c_i
    // A5 commitment data
    A5::CommitmentSec cp_com_sec;
    // Number of instances from each source
    int64_t num_bp_instances;    // always 2
    int64_t num_cp_instance;     // always 1
    int64_t num_cc_instance;     // 1 if n>1, else 0
  };

  // Structure to hold the R_{cp} instance returned from R_{cc}^A proving
  struct CcACpInstance {
    // A3 (R_{cp}) prove input data (owned copies)
    std::vector<Fr> cp_a;    // vector a (hat_u)
    std::vector<Fr> cp_b;    // vector b (hat_v)
    Fr cp_c;                 // scalar c = <a, b> (hat_w)
    // A3 commitment data
    A3::CommitmentSec cp_com_sec;
  };

  // Prove R_{cc}^A and return the R_{cp} instance instead of proving it internally.
  // This function performs the amortization and SumCheck steps of A10, but extracts
  // the final R_{cp} (A3) instance for external batching.
  // The cc_proof will contain sc_com_t0, sc_com_t2, but sub_proof will be
  // left uninitialized (to be filled by the caller).
  static void ProveCcAReturnCp(A10::Proof& cc_proof, h256_t& seed,
                                std::vector<std::vector<Fr>> const& a_vec,
                                std::vector<std::vector<Fr>> const& b_vec,
                                std::vector<A10::CommitmentSec> const& com_secs,
                                std::vector<CopyRange> const& copy_ranges,
                                GetRefG1 const& get_g,
                                CcACpInstance& cp_instance) {
    Tick tick(__FN__, "ProveCcAReturnCp");
    int64_t m = (int64_t)a_vec.size();
    int64_t n = (int64_t)a_vec[0].size();
    assert(m > 0);

    // Step 1: Derive amortization challenge e from seed directly
    // (No need to update seed with commitments on prover side)
    Fr e_amort = H256ToFr(seed);

    // Step 2: Precompute e powers vector
    std::vector<Fr> e_powers(m);
    e_powers[0] = FrOne();
    for (int64_t i = 1; i < m; ++i) {
      e_powers[i] = e_powers[i - 1] * e_amort;
    }

    // Step 3: Compute aggregated vectors and blinding factors in parallel
    std::vector<Fr> hat_a(n, FrZero());
    std::vector<Fr> hat_b(n, FrZero());
    Fr hat_alpha = FrZero();
    Fr hat_beta = FrZero();

    {
      std::array<parallel::VoidTask, 2> tasks;
      // Aggregate vectors: hat_a = A^T * e_powers, hat_b = B^T * e_powers
      // where A's rows are a_vec[i], B's rows are b_vec[i]
      tasks[0] = [&]() {
        // Build FlatMatrix from a_vec and b_vec
        FlatMatrix mat_a(m, n), mat_b(m, n);
        auto build_mats = [&](int64_t i) {
          std::copy(a_vec[i].begin(), a_vec[i].end(), mat_a.row_ptr(i));
          std::copy(b_vec[i].begin(), b_vec[i].end(), mat_b.row_ptr(i));
        };
        parallel::For(m, build_mats);
        // Compute hat_a = mat_a^T * e_powers, hat_b = mat_b^T * e_powers
        MatrixVectorMul(e_powers, mat_a, hat_a);
        MatrixVectorMul(e_powers, mat_b, hat_b);
      };
      // Aggregate blinding factors
      tasks[1] = [&]() {
        std::vector<Fr> r_com_a_vec(m), r_com_b_vec(m);
        for (int64_t i = 0; i < m; ++i) {
          r_com_a_vec[i] = com_secs[i].r_com_a;
          r_com_b_vec[i] = com_secs[i].r_com_b;
        }
        hat_alpha = InnerProduct(r_com_a_vec, e_powers);
        hat_beta = InnerProduct(r_com_b_vec, e_powers);
      };
      parallel::Invoke(tasks);
    }

    // Derive r challenge vector (multi-range)
    std::vector<Fr> r_challenge;
    A10::DeriveRChallenge(seed, copy_ranges, r_challenge);

    // Build selection vectors c, d (multi-range)
    std::vector<Fr> c_vec, d_vec;
    A10::BuildSelectionVectors(c_vec, d_vec, r_challenge, n, copy_ranges);

    // Define u = (hat_a, hat_b), v = (c, d)
    // Build u_vec = [hat_a, hat_b], v_vec = [c_vec, d_vec]
    std::vector<Fr> u_vec(2 * n);
    std::vector<Fr> v_vec(2 * n);
    std::copy(hat_a.begin(), hat_a.end(), u_vec.begin());
    std::copy(hat_b.begin(), hat_b.end(), u_vec.begin() + n);
    std::copy(c_vec.begin(), c_vec.end(), v_vec.begin());
    std::copy(d_vec.begin(), d_vec.end(), v_vec.begin() + n);

    Fr w = FrZero();
    Fr r_com_w = FrZero();
    G1 gc = pc::PcG(0);
    G1 com_w = pc::ComputeCom(gc, w, r_com_w);

    // Run ZKSC_1 (one round of sumcheck)
    auto u_copy = u_vec;
    auto v_copy = v_vec;
    Fr hat_w = w;
    Fr hat_r_com_w = r_com_w;

    std::vector<Fr> e_vec;
    int64_t round = 1;
    SumCheck::Prove(round, 2 * n, cc_proof.sc_com_t0, cc_proof.sc_com_t2,
                    e_vec, seed, u_copy, v_copy, hat_w, hat_r_com_w, gc);

    Fr e_sc = e_vec[0];

    // hat_u = hat_a + e * hat_b, hat_v = e * c + d
    auto& hat_u_vec = u_copy;
    auto& hat_v_vec = v_copy;

    // hat_mu = hat_alpha + e * hat_beta
    Fr hat_mu = hat_alpha + e_sc * hat_beta;

    // Store the R_{cp} instance instead of calling A3::Prove
    // Note: In A5, a is committed vector (secret), b is public vector
    // hat_u is aggregated assignment vector (secret, committed in hat_U)
    // hat_v is selection vector (public, verifier can compute)
    cp_instance.cp_a = hat_u_vec;   // committed vector (secret)
    cp_instance.cp_b = hat_v_vec;   // public vector
    cp_instance.cp_c = hat_w;
    cp_instance.cp_com_sec = A3::CommitmentSec(hat_mu, hat_r_com_w);
  }

  // ============================================================
  // Sparse matrix optimized versions
  // ============================================================

  struct SparseProveInput {
    SparseProveInput(SparseMatrix const& mat_a,
                     SparseMatrix const& mat_b,
                     SparseMatrix const& mat_c,
                     FlatMatrix const& row_z,
                     std::vector<CopyRange> const& copy_ranges,
                     GetRefG1 const& get_g)
        : mat_a(mat_a), mat_b(mat_b), mat_c(mat_c), row_z(row_z),
          copy_ranges(copy_ranges), get_g(get_g) {}
    SparseProveInput(SparseMatrix const& mat_a,
                     SparseMatrix const& mat_b,
                     SparseMatrix const& mat_c,
                     FlatMatrix const& row_z,
                     int64_t input_len,
                     int64_t public_input_start,
                     int64_t output_start,
                     GetRefG1 const& get_g)
        : mat_a(mat_a), mat_b(mat_b), mat_c(mat_c), row_z(row_z),
          copy_ranges({CopyRange(output_start, public_input_start, input_len)}),
          get_g(get_g) {}
    int64_t m() const { return mat_a.rows(); }
    int64_t n_vars() const { return mat_a.cols(); }
    int64_t n() const { return row_z.empty() ? 0 : row_z.cols(); }
    int64_t input_len() const { return copy_ranges.empty() ? 0 : copy_ranges[0].l; }
    int64_t output_start() const { return copy_ranges.empty() ? 0 : copy_ranges[0].l_a; }
    int64_t public_input_start() const { return copy_ranges.empty() ? 0 : copy_ranges[0].l_b; }
    std::string to_string() const {
      return std::to_string(m()) + "x" + std::to_string(n()) + "(sparse)";
    }

    SparseMatrix const& mat_a;
    SparseMatrix const& mat_b;
    SparseMatrix const& mat_c;
    FlatMatrix const& row_z;
    std::vector<CopyRange> copy_ranges;
    GetRefG1 const& get_g;
  };

  struct SparseVerifyInput {
    SparseVerifyInput(SparseMatrix const& mat_a,
                      SparseMatrix const& mat_b,
                      SparseMatrix const& mat_c,
                      CommitmentPub const& com_pub,
                      int64_t n_cols,
                      std::vector<CopyRange> const& copy_ranges,
                      GetRefG1 const& get_g)
        : mat_a(mat_a), mat_b(mat_b), mat_c(mat_c),
          com_pub(com_pub), n_cols_(n_cols),
          copy_ranges(copy_ranges), get_g(get_g) {}
    SparseVerifyInput(SparseMatrix const& mat_a,
                      SparseMatrix const& mat_b,
                      SparseMatrix const& mat_c,
                      CommitmentPub const& com_pub,
                      int64_t n_cols,
                      int64_t input_len,
                      int64_t public_input_start,
                      int64_t output_start,
                      GetRefG1 const& get_g)
        : mat_a(mat_a), mat_b(mat_b), mat_c(mat_c),
          com_pub(com_pub), n_cols_(n_cols),
          copy_ranges({CopyRange(output_start, public_input_start, input_len)}),
          get_g(get_g) {}
    SparseMatrix const& mat_a;
    SparseMatrix const& mat_b;
    SparseMatrix const& mat_c;
    CommitmentPub const& com_pub;
    int64_t n_cols_;
    std::vector<CopyRange> copy_ranges;
    GetRefG1 const& get_g;
    int64_t m() const { return mat_a.rows(); }
    int64_t n() const { return n_cols_; }
    int64_t n_vars() const { return mat_a.cols(); }
    int64_t input_len() const { return copy_ranges.empty() ? 0 : copy_ranges[0].l; }
    int64_t output_start() const { return copy_ranges.empty() ? 0 : copy_ranges[0].l_a; }
    int64_t public_input_start() const { return copy_ranges.empty() ? 0 : copy_ranges[0].l_b; }
    std::string to_string() const {
      return std::to_string(m()) + "x" + std::to_string(n()) + "(sparse)";
    }
  };

  // ============================================================
  // Sparse Z matrix optimized versions (Z is sparse, A/B/C are sparse)
  // ============================================================

  // Input structure for sparse Z matrix proving
  // Uses SparseZMatrix for Z to exploit sparsity
  struct SparseZProveInput {
    SparseZProveInput(SparseMatrix const& mat_a,
                      SparseMatrix const& mat_b,
                      SparseMatrix const& mat_c,
                      SparseZMatrix const& sparse_z,
                      std::vector<CopyRange> const& copy_ranges,
                      GetRefG1 const& get_g)
        : mat_a(mat_a), mat_b(mat_b), mat_c(mat_c), sparse_z(sparse_z),
          copy_ranges(copy_ranges), get_g(get_g) {}
    int64_t m() const { return mat_a.rows(); }
    int64_t n_vars() const { return mat_a.cols(); }
    int64_t n() const { return sparse_z.cols(); }
    int64_t input_len() const { return copy_ranges.empty() ? 0 : copy_ranges[0].l; }
    int64_t output_start() const { return copy_ranges.empty() ? 0 : copy_ranges[0].l_a; }
    int64_t public_input_start() const { return copy_ranges.empty() ? 0 : copy_ranges[0].l_b; }
    std::string to_string() const {
      return std::to_string(m()) + "x" + std::to_string(n()) + 
             "(sparse_z, nnz=" + std::to_string(sparse_z.nnz()) + 
             ", sparsity=" + std::to_string(sparse_z.sparsity() * 100) + "%)";
    }

    SparseMatrix const& mat_a;
    SparseMatrix const& mat_b;
    SparseMatrix const& mat_c;
    SparseZMatrix const& sparse_z;
    std::vector<CopyRange> copy_ranges;
    GetRefG1 const& get_g;
  };

  // Input structure for sparse Z matrix verification
  struct SparseZVerifyInput {
    SparseZVerifyInput(SparseMatrix const& mat_a,
                       SparseMatrix const& mat_b,
                       SparseMatrix const& mat_c,
                       CommitmentPub const& com_pub,
                       int64_t n_cols,
                       std::vector<CopyRange> const& copy_ranges,
                       GetRefG1 const& get_g)
        : mat_a(mat_a), mat_b(mat_b), mat_c(mat_c),
          com_pub(com_pub), n_cols_(n_cols),
          copy_ranges(copy_ranges), get_g(get_g) {}
    SparseMatrix const& mat_a;
    SparseMatrix const& mat_b;
    SparseMatrix const& mat_c;
    CommitmentPub const& com_pub;
    int64_t n_cols_;
    std::vector<CopyRange> copy_ranges;
    GetRefG1 const& get_g;
    int64_t m() const { return mat_a.rows(); }
    int64_t n() const { return n_cols_; }
    int64_t n_vars() const { return mat_a.cols(); }
    int64_t input_len() const { return copy_ranges.empty() ? 0 : copy_ranges[0].l; }
    int64_t output_start() const { return copy_ranges.empty() ? 0 : copy_ranges[0].l_a; }
    int64_t public_input_start() const { return copy_ranges.empty() ? 0 : copy_ranges[0].l_b; }
    std::string to_string() const {
      return std::to_string(m()) + "x" + std::to_string(n()) + "(sparse_z)";
    }
  };

  // Optimized ComputeCom for sparse Z matrix
  // Sparse commitment computation using CSC format + parallel Bdlo12 multiexp.
  // Key optimization: instead of 287 columns fully parallel (each with serial
  // multiexp of 136K points), we limit outer parallelism and directly call
  // ParallelMultiExpBdlo12Inner to bypass the 2M threshold, letting each
  // multiexp use multiple cores internally.
  //
  // With 12 cores, 287 columns, ~136K points per column:
  //   Old: 12 columns parallel × serial multiexp(136K) = 287/12 × 833ms ≈ 20s
  //   New: 3 columns parallel × 4-core parallel multiexp ≈ ~10s target
  static void ComputeComSparseZ(CommitmentPub& com_pub, CommitmentSec& com_sec,
                                 SparseZProveInput const& input) {
    Tick tick(__FN__, input.to_string());
    int64_t n_val = input.n();

    com_pub.com_z.resize(n_val);
    com_sec.r_com_z.resize(n_val);

    // One-time CSR→CSC conversion: O(nnz), amortized over all n columns
    SparseZMatrixCSC csc = SparseZToCSC(input.sparse_z);

    // Determine optimal outer/inner parallelism split.
    // ParallelMultiExpBdlo12Inner uses up to 4 threads internally.
    // So we run total_threads/4 columns concurrently.
    // With 12 cores: 3 columns × 4 threads each = 12 threads fully utilized.
    int64_t total_threads = parallel::tbb_thread_num;
    if (total_threads < 1) total_threads = 1;
    int64_t outer_parallelism = std::max((int64_t)1, total_threads / 4);

    // Process columns in batches to control outer parallelism
    for (int64_t batch_start = 0; batch_start < n_val;
         batch_start += outer_parallelism) {
      int64_t batch_end = std::min(batch_start + outer_parallelism, n_val);
      int64_t batch_size = batch_end - batch_start;

      auto commit_f = [&](int64_t idx) {
        int64_t j = batch_start + idx;
        com_sec.r_com_z[j] = FrRand();
        int64_t col_begin = csc.col_ptr_[j];
        int64_t col_end = csc.col_ptr_[j + 1];
        int64_t col_nnz = col_end - col_begin;

        if (col_nnz == 0) {
          com_pub.com_z[j] = pc::PcH() * com_sec.r_com_z[j];
        } else {
          // Build get_g/get_f that include h and r for Pedersen commitment:
          // com = MultiExp(h, g[0], g[1], ...; r, x[0], x[1], ...) 
          G1 const& h = pc::PcH();
          Fr const& r = com_sec.r_com_z[j];
          auto get_g = [&input, &csc, col_begin, &h](int64_t i) -> G1 const& {
            return i ? input.get_g(csc.row_idx_[col_begin + i - 1]) : h;
          };
          auto get_f = [&csc, col_begin, &r](int64_t i) -> Fr const& {
            return i ? csc.values_[col_begin + i - 1] : r;
          };
          // Directly call ParallelMultiExpBdlo12Inner to bypass the 2M
          // threshold in MultiExpBdlo12, enabling internal parallelism
          // for 136K+ points per column
          com_pub.com_z[j] = ParallelMultiExpBdlo12Inner<G1>(
              get_g, get_f, (size_t)(col_nnz + 1), false);
        }
      };
      parallel::For(batch_size, commit_f);
    }
  }

  // Optimized ProveIf for sparse Z matrix
  // Key optimizations:
  // 1. Use SparseZMatrixVectorMul for Z * r (exploits Z sparsity)
  // 2. Use SparseMatrixMulSparseZ for A * Z (exploits both A and Z sparsity)
  // 3. Use SparseZMatrixCol for column extraction (only non-zero elements)
  static void ProveIfSparseZ(Proof& proof, h256_t seed,
                              SparseZProveInput const& input,
                              CommitmentPub const& com_pub,
                              CommitmentSec const& com_sec) {
    Tick tick(__FN__, "ProveIfSparseZ " + input.to_string());

    int64_t m_val = input.m();
    int64_t n_val = input.n();
    int64_t n_vars_val = input.n_vars();
    int64_t l_val = input.input_len();

    // Step 1: Derive challenges
    std::vector<Fr> r_challenge;
    Fr s_challenge;
    DeriveChallenges(seed, com_pub.com_z, r_challenge, s_challenge);

    std::vector<Fr> s_powers(m_val);
    s_powers[0] = FrOne();
    for (int64_t i = 1; i < m_val; ++i) {
      s_powers[i] = s_powers[i - 1] * s_challenge;
    }

    // Step 2: Compute s_times_c and z_times_r using sparse operations
    std::vector<Fr> s_times_c, z_times_r;
    {
      std::array<parallel::VoidTask, 2> tasks;
      tasks[0] = [&]() { MatrixVectorMul(s_powers, input.mat_c, s_times_c); };
      // OPTIMIZATION: Use sparse Z * vector multiplication
      tasks[1] = [&]() { SparseZMatrixVectorMulLeft(r_challenge, input.sparse_z, z_times_r); };
      parallel::Invoke(tasks);
    }
    Fr t_val = InnerProduct(s_times_c, z_times_r);

    // Step 3: Commit to t
    Fr r_com_t = FrRand();
    G1 gc = pc::PcG(0);
    proof.com_t = pc::ComputeCom(gc, t_val, r_com_t);

    UpdateSeed(seed, proof.com_t);

    // Step 4: Build hat_S_sparse and compute r_com_hat_z
    // NOTE: hat_z_rows is NOT allocated (saves ~37 GB).
    // r_challenge is passed to SparseProveBpReturnCpA instead.
    SparseMatrix hat_S_sparse;
    std::vector<Fr> r_com_hat_z(n_val);
    {
      std::array<parallel::VoidTask, 2> tasks;
      tasks[0] = [&]() { hat_S_sparse = ScaleSparseRows(input.mat_a, s_powers); };
      tasks[1] = [&]() {
        auto compute_r = [&](int64_t j) {
          r_com_hat_z[j] = com_sec.r_com_z[j] * r_challenge[j];
        };
        parallel::For(n_val, compute_r);
      };
      parallel::Invoke(tasks);
    }

    Fr r_com_hat_R = FrZero();
    for (int64_t j = 0; j < n_val; ++j) {
      r_com_hat_R += r_com_hat_z[j];
    }

    std::vector<Fr> const& hat_c_vec = s_times_c;
    std::vector<Fr> const& hat_r_vec = z_times_r;

    // Step 5: Prepare R_{bp} commitments
    A11::CommitmentPub bp_com_pub;
    bp_com_pub.com_t = proof.com_t;
    bp_com_pub.com_c.resize(n_val);
    bp_com_pub.com_d.resize(n_val);
    auto compute_bp_com = [&](int64_t j) {
      bp_com_pub.com_c[j] = com_pub.com_z[j];
      bp_com_pub.com_d[j] = com_pub.com_z[j] * r_challenge[j];
    };
    parallel::For(n_val, compute_bp_com);

    A11::CommitmentSec bp_com_sec;
    bp_com_sec.r_com_t = r_com_t;
    bp_com_sec.r_com_c = com_sec.r_com_z;
    bp_com_sec.r_com_d = r_com_hat_z;

    // Step 6: Build dense row_z from sparse Z for SparseProveBpReturnCpA
    FlatMatrix row_z(n_vars_val, n_val);
    for (int64_t i = 0; i < n_vars_val; ++i) {
      for (int64_t k = input.sparse_z.row_ptr_[i]; k < input.sparse_z.row_ptr_[i + 1]; ++k) {
        int64_t j = input.sparse_z.col_idx_[k];
        row_z(i, j) = input.sparse_z.values_[k];
      }
    }

    IfCpAInstance if_cpa_instance;
    SparseProveBpReturnCpA(proof.bp_proof, seed,
                            hat_S_sparse, input.mat_b, row_z, r_challenge,
                            t_val, input.get_g, bp_com_sec, if_cpa_instance);

    // Step 7: Add R_{cp} instance for <hat_r, hat_c> = t
    if_cpa_instance.cp_a.push_back(hat_r_vec);
    if_cpa_instance.cp_b.push_back(hat_c_vec);
    if_cpa_instance.cp_c.push_back(t_val);
    if_cpa_instance.cp_com_sec.r_com_a.push_back(r_com_hat_R);
    if_cpa_instance.cp_com_sec.r_com_c.push_back(r_com_t);
    if_cpa_instance.num_cp_instance = 1;

    // Step 8: Handle R_{cc}^A for copy constraints (multi-range)
    if (n_val > 1) {
      std::vector<std::vector<Fr>> cc_a_vec(n_val - 1);
      std::vector<std::vector<Fr>> cc_b_vec(n_val - 1);
      std::vector<A10::CommitmentSec> cc_com_secs(n_val - 1);

      // OPTIMIZATION: Extract columns using sparse structure
      auto compute_cc = [&](int64_t j) {
        cc_a_vec[j] = SparseZMatrixCol(input.sparse_z, j);
        cc_b_vec[j] = SparseZMatrixCol(input.sparse_z, j + 1);
        cc_com_secs[j] = A10::CommitmentSec(com_sec.r_com_z[j],
                                             com_sec.r_com_z[j + 1]);
      };
      parallel::For(n_val - 1, compute_cc);

      CcACpInstance cc_cp_instance;
      ProveCcAReturnCp(proof.cc_proof, seed,
                        cc_a_vec, cc_b_vec,
                        cc_com_secs,
                        input.copy_ranges, input.get_g,
                        cc_cp_instance);

      if_cpa_instance.cp_a.push_back(cc_cp_instance.cp_a);
      if_cpa_instance.cp_b.push_back(cc_cp_instance.cp_b);
      if_cpa_instance.cp_c.push_back(cc_cp_instance.cp_c);
      if_cpa_instance.cp_com_sec.r_com_a.push_back(cc_cp_instance.cp_com_sec.r_com_a);
      if_cpa_instance.cp_com_sec.r_com_c.push_back(cc_cp_instance.cp_com_sec.r_com_c);
      if_cpa_instance.num_cc_instance = 1;
    }

    // Step 9: Prove the batched R_{cp}^A
    A5::ProveInput cpa_input(if_cpa_instance.cp_a, if_cpa_instance.cp_b,
                              if_cpa_instance.cp_c, input.get_g, gc);
    A5::Prove(proof.bp_proof.cp_proof, seed, cpa_input,
              if_cpa_instance.cp_com_sec);
  }

  // Optimized VerifyIf for sparse Z matrix
  // Verification is the same as regular sparse version since verifier only sees commitments
  static bool VerifyIfSparseZ(Proof const& proof, h256_t seed,
                               SparseZVerifyInput const& input) {
    // Verification is identical to regular sparse version
    // because the verifier only sees commitments, not the actual Z matrix
    SparseVerifyInput sparse_verify(input.mat_a, input.mat_b, input.mat_c,
                                     input.com_pub, input.n_cols_,
                                     input.copy_ranges, input.get_g);
    return VerifyIf(proof, seed, sparse_verify);
  }

  static void ComputeCom(CommitmentPub& com_pub, CommitmentSec& com_sec,
                         SparseProveInput const& input) {
    Tick tick(__FN__, input.to_string());
    int64_t n_val = input.n();

    com_pub.com_z.resize(n_val);
    com_sec.r_com_z.resize(n_val);

    auto commit_f = [&](int64_t j) {
      std::vector<Fr> col_j = input.row_z.col(j);
      com_sec.r_com_z[j] = FrRand();
      com_pub.com_z[j] = pc::ComputeCom(input.get_g, col_j, com_sec.r_com_z[j], true);
    };
    parallel::For(n_val, commit_f);
  }

  static void Prove(Proof& proof, h256_t seed,
                    SparseProveInput const& input,
                    CommitmentPub const& com_pub,
                    CommitmentSec const& com_sec) {
    Tick tick(__FN__, input.to_string());

    int64_t m_val = input.m();
    int64_t n_val = input.n();
    int64_t n_vars_val = input.n_vars();
    int64_t l_val = input.input_len();

    std::vector<Fr> r_challenge;
    Fr s_challenge;
    DeriveChallenges(seed, com_pub.com_z, r_challenge, s_challenge);

    std::vector<Fr> s_powers(m_val);
    s_powers[0] = FrOne();
    for (int64_t i = 1; i < m_val; ++i) {
      s_powers[i] = s_powers[i - 1] * s_challenge;
    }

    std::vector<Fr> s_times_c, z_times_r;
    {
      std::array<parallel::VoidTask, 2> tasks;
      tasks[0] = [&]() { MatrixVectorMul(s_powers, input.mat_c, s_times_c); };
      tasks[1] = [&]() { MatrixVectorMul(input.row_z, r_challenge, z_times_r); };
      parallel::Invoke(tasks);
    }
    Fr t_val = InnerProduct(s_times_c, z_times_r);

    Fr r_com_t = FrRand();
    G1 gc = pc::PcG(0);
    proof.com_t = pc::ComputeCom(gc, t_val, r_com_t);

    UpdateSeed(seed, proof.com_t);

    // Build hat_S as dense matrix from sparse mat_a
    FlatMatrix hat_S(m_val, n_vars_val, FrZero());
    for (int64_t i = 0; i < m_val; ++i) {
      for (int64_t k = input.mat_a.row_ptr_[i]; k < input.mat_a.row_ptr_[i + 1]; ++k) {
        hat_S(i, input.mat_a.col_idx_[k]) = s_powers[i] * input.mat_a.values_[k];
      }
    }

    // Build dense mat_b from sparse
    FlatMatrix dense_b(m_val, n_vars_val, FrZero());
    for (int64_t i = 0; i < m_val; ++i) {
      for (int64_t k = input.mat_b.row_ptr_[i]; k < input.mat_b.row_ptr_[i + 1]; ++k) {
        dense_b(i, input.mat_b.col_idx_[k]) = input.mat_b.values_[k];
      }
    }

    // Build dense row_z and hat_z_rows from FlatMatrix
    FlatMatrix dense_row_z(n_vars_val, n_val);
    FlatMatrix hat_z_rows(n_vars_val, n_val);
    std::vector<Fr> r_com_hat_z(n_val);
    {
      std::array<parallel::VoidTask, 2> tasks;
      tasks[0] = [&]() {
        auto compute_f = [&](int64_t idx) {
          int64_t i = idx / n_val;
          int64_t j = idx % n_val;
          dense_row_z(i, j) = input.row_z(i, j);
          hat_z_rows(i, j) = input.row_z(i, j) * r_challenge[j];
        };
        parallel::For(n_vars_val * n_val, compute_f);
      };
      tasks[1] = [&]() {
        auto compute_r = [&](int64_t j) {
          r_com_hat_z[j] = com_sec.r_com_z[j] * r_challenge[j];
        };
        parallel::For(n_val, compute_r);
      };
      parallel::Invoke(tasks);
    }

    Fr r_com_hat_R = FrZero();
    for (int64_t j = 0; j < n_val; ++j) {
      r_com_hat_R += r_com_hat_z[j];
    }

    std::vector<Fr> const& hat_c_vec = s_times_c;
    std::vector<Fr> const& hat_r_vec = z_times_r;

    A11::CommitmentPub bp_com_pub;
    bp_com_pub.com_t = proof.com_t;
    bp_com_pub.com_c.resize(n_val);
    bp_com_pub.com_d.resize(n_val);
    auto compute_bp_com = [&](int64_t j) {
      bp_com_pub.com_c[j] = com_pub.com_z[j];
      bp_com_pub.com_d[j] = com_pub.com_z[j] * r_challenge[j];
    };
    parallel::For(n_val, compute_bp_com);

    A11::CommitmentSec bp_com_sec;
    bp_com_sec.r_com_t = r_com_t;
    bp_com_sec.r_com_c = com_sec.r_com_z;
    bp_com_sec.r_com_d = r_com_hat_z;

    A11::ProveInput bp_input(hat_S, dense_b, dense_row_z, hat_z_rows,
                              t_val, input.get_g);
    A11::Prove(proof.bp_proof, seed, bp_input, bp_com_pub, bp_com_sec);

    G1 hat_R = MultiExpBdlo12(com_pub.com_z, r_challenge);

    A3::CommitmentPub cp_com_pub(hat_R, proof.com_t);
    A3::CommitmentSec cp_com_sec(r_com_hat_R, r_com_t);
    A3::ProveInput cp_input(hat_r_vec, hat_c_vec, t_val, input.get_g, gc);
    A3::Prove(proof.cp_proof, seed, cp_input, cp_com_sec);

    if (n_val > 1) {
      std::vector<std::vector<Fr>> cc_a_vec(n_val - 1);
      std::vector<std::vector<Fr>> cc_b_vec(n_val - 1);
      std::vector<A10::CommitmentPub> cc_com_pubs(n_val - 1);
      std::vector<A10::CommitmentSec> cc_com_secs(n_val - 1);

      auto compute_cc = [&](int64_t j) {
        cc_a_vec[j] = input.row_z.col(j);
        cc_b_vec[j] = input.row_z.col(j + 1);
        cc_com_pubs[j] = A10::CommitmentPub(com_pub.com_z[j], com_pub.com_z[j + 1]);
        cc_com_secs[j] = A10::CommitmentSec(com_sec.r_com_z[j], com_sec.r_com_z[j + 1]);
      };
      parallel::For(n_val - 1, compute_cc);

      A10::ProveAmortized(proof.cc_proof, seed, cc_a_vec, cc_b_vec,
                           cc_com_pubs, cc_com_secs, input.copy_ranges, input.get_g);
    }
  }

  static bool Verify(Proof const& proof, h256_t seed,
                     SparseVerifyInput const& input) {
    Tick tick(__FN__, input.to_string());

    int64_t m_val = input.m();
    int64_t n_vars_val = input.n_vars();
    int64_t n_val = input.n();
    int64_t l_val = input.input_len();

    std::vector<Fr> r_challenge;
    Fr s_challenge;
    DeriveChallenges(seed, input.com_pub.com_z, r_challenge, s_challenge);

    std::vector<Fr> s_powers(m_val);
    s_powers[0] = FrOne();
    for (int64_t i = 1; i < m_val; ++i) {
      s_powers[i] = s_powers[i - 1] * s_challenge;
    }

    UpdateSeed(seed, proof.com_t);

    // Build hat_S as dense matrix from sparse mat_a
    FlatMatrix hat_S(m_val, n_vars_val, FrZero());
    for (int64_t i = 0; i < m_val; ++i) {
      for (int64_t k = input.mat_a.row_ptr_[i]; k < input.mat_a.row_ptr_[i + 1]; ++k) {
        hat_S(i, input.mat_a.col_idx_[k]) = s_powers[i] * input.mat_a.values_[k];
      }
    }

    // Build dense mat_b from sparse
    FlatMatrix dense_b(m_val, n_vars_val, FrZero());
    for (int64_t i = 0; i < m_val; ++i) {
      for (int64_t k = input.mat_b.row_ptr_[i]; k < input.mat_b.row_ptr_[i + 1]; ++k) {
        dense_b(i, input.mat_b.col_idx_[k]) = input.mat_b.values_[k];
      }
    }

    A11::CommitmentPub bp_com_pub;
    bp_com_pub.com_t = proof.com_t;
    bp_com_pub.com_c.resize(n_val);
    bp_com_pub.com_d.resize(n_val);
    auto compute_bp_com = [&](int64_t j) {
      bp_com_pub.com_c[j] = input.com_pub.com_z[j];
      bp_com_pub.com_d[j] = input.com_pub.com_z[j] * r_challenge[j];
    };
    parallel::For(n_val, compute_bp_com);

    A11::VerifyInput bp_verify(hat_S, dense_b, bp_com_pub, n_val, input.get_g);
    bool ret = A11::Verify(proof.bp_proof, seed, bp_verify);

    std::vector<Fr> hat_c_vec;
    MatrixVectorMul(s_powers, input.mat_c, hat_c_vec);

    auto get_com_z = [&input](int64_t j) -> G1 const& { return input.com_pub.com_z[j]; };
    auto get_r = [&r_challenge](int64_t j) -> Fr const& { return r_challenge[j]; };
    G1 hat_R = MultiExpBdlo12Inner<G1>(get_com_z, get_r, n_val);

    G1 gc = pc::PcG(0);
    A3::CommitmentPub cp_com_pub(hat_R, proof.com_t);
    A3::VerifyInput cp_verify(hat_c_vec, cp_com_pub, input.get_g, gc);
    ret = ret && A3::Verify(proof.cp_proof, seed, cp_verify);

    if (n_val > 1) {
      std::vector<A10::CommitmentPub> cc_com_pubs(n_val - 1);
      auto compute_cc_com = [&](int64_t j) {
        cc_com_pubs[j] = A10::CommitmentPub(input.com_pub.com_z[j],
                                             input.com_pub.com_z[j + 1]);
      };
      parallel::For(n_val - 1, compute_cc_com);

      ret = ret && A10::VerifyAmortized(proof.cc_proof, seed,
                                         cc_com_pubs,
                                         input.copy_ranges, n_vars_val,
                                         input.get_g);
    }

    return ret;
  }

  // Sparse version of ProveBpReturnCpA: uses sparse matrix multiplication
  // instead of dense MatrixMul for computing AC and BD.
  //
  // Memory optimizations:
  //   1. No intermediate FlatMatrix temporaries: sparse mat-mul writes directly
  //      into padded contiguous layout, avoiding ~64 GB peak overhead.
  //   2. r_challenge instead of hat_z_rows: BD = (mat_b * row_z) * diag(r)
  //      computed on-the-fly, saving ~37 GB.
  //   3. Phase1 SumCheck progressively shrinks mat_ac/mat_bd after each fold,
  //      releasing upper-half memory as soon as it becomes unreachable.
  //   4. hat_S_sparse released after Step 5 (no longer needed).
  static void SparseProveBpReturnCpA(
      A11::Proof& bp_proof, h256_t& seed,
      SparseMatrix const& hat_S_sparse,
      SparseMatrix const& mat_b,
      FlatMatrix const& row_z,
      std::vector<Fr> const& r_challenge,
      Fr const& t_val,
      GetRefG1 const& get_g,
      A11::CommitmentSec const& com_sec,
      IfCpAInstance& cpa_instance) {
    int64_t m_val = hat_S_sparse.rows();
    int64_t n_val = row_z.cols();
    int64_t n_vars_val = hat_S_sparse.cols();
    int64_t l_m = (int64_t)misc::Log2UB(m_val);
    int64_t l_n = (int64_t)misc::Log2UB(n_val);
    int64_t l_total = l_m + l_n;

    Tick tick(__FN__, "SparseProveBpReturnCpA " +
             std::to_string(m_val) + "x" + std::to_string(n_val));

    int64_t padded_m = 1LL << l_m;
    int64_t padded_n = 1LL << l_n;
    G1 gc = pc::PcG(0);
    Fr hat_t = t_val;
    Fr hat_r_com_t = com_sec.r_com_t;

    // Compute AC = hat_S * row_z and BD = mat_b * row_z directly into padded layout.
    // No intermediate FlatMatrix is allocated — each row is computed and written
    // directly into the padded vector, saving ~64 GB peak memory.
    std::vector<Fr> mat_ac(m_val * padded_n, FrZero());
    std::vector<Fr> mat_bd(m_val * padded_n, FrZero());
    {
      std::array<parallel::VoidTask, 2> mul_tasks;
      // AC: hat_S_sparse * row_z → mat_ac (padded)
      mul_tasks[0] = [&]() {
        auto compute_row = [&](int64_t i) {
          Fr* out_row = mat_ac.data() + i * padded_n;
          for (int64_t k = hat_S_sparse.row_ptr_[i]; k < hat_S_sparse.row_ptr_[i + 1]; ++k) {
            int64_t col = hat_S_sparse.col_idx_[k];
            Fr const& val = hat_S_sparse.values_[k];
            Fr const* z_row = row_z.row_ptr(col);
            for (int64_t j = 0; j < n_val; ++j) {
              out_row[j] += val * z_row[j];
            }
          }
        };
        parallel::For(m_val, compute_row);
      };
      // BD: mat_b * row_z → mat_bd (padded), with column scaling by r_challenge
      mul_tasks[1] = [&]() {
        auto compute_row = [&](int64_t i) {
          Fr* out_row = mat_bd.data() + i * padded_n;
          for (int64_t k = mat_b.row_ptr_[i]; k < mat_b.row_ptr_[i + 1]; ++k) {
            int64_t col = mat_b.col_idx_[k];
            Fr const& val = mat_b.values_[k];
            Fr const* z_row = row_z.row_ptr(col);
            for (int64_t j = 0; j < n_val; ++j) {
              out_row[j] += val * z_row[j];
            }
          }
          // Scale columns by r_challenge: BD[i][j] *= r_challenge[j]
          for (int64_t j = 0; j < n_val; ++j) {
            out_row[j] *= r_challenge[j];
          }
        };
        parallel::For(m_val, compute_row);
      };
      parallel::Invoke(mul_tasks);
    }

    // Two-phase SumCheck
    std::vector<Fr> e_challenges;
    e_challenges.reserve(l_total);
    bp_proof.sc_com_t0.reserve(l_total);
    bp_proof.sc_com_t2.reserve(l_total);

    // Phase 1: Row-dimension SumCheck (l_m rounds)
    // After each fold, shrink mat_ac/mat_bd to release upper-half memory.
    {
      int64_t effective_m = m_val;
      int64_t current_padded_m = padded_m;
      for (int64_t loop = 0; loop < l_m; ++loop) {
        int64_t half_rows = current_padded_m / 2;
        int64_t eff_t0_rows = std::min(half_rows, std::max((int64_t)0, effective_m - half_rows));

        Fr t0, r_com_t0, t2, r_com_t2;
        std::array<parallel::VoidTask, 2> tasks;

        tasks[0] = [&, half_rows, eff_t0_rows]() {
          r_com_t0 = FrRand();
          Fr sum = FrZero();
          if (eff_t0_rows > 0) {
            std::vector<Fr> row_sums(eff_t0_rows);
            auto compute_row = [&](int64_t i) {
              Fr const* a_row = mat_ac.data() + i * padded_n;
              Fr const* b_row = mat_bd.data() + (i + half_rows) * padded_n;
              row_sums[i] = InnerProduct(a_row, b_row, padded_n);
            };
            parallel::For(eff_t0_rows, compute_row);
            sum = parallel::Accumulate(row_sums.begin(), row_sums.end(), FrZero());
          }
          t0 = sum;
          bp_proof.sc_com_t0.push_back(pc::ComputeCom(gc, t0, r_com_t0));
        };

        tasks[1] = [&, half_rows, eff_t0_rows]() {
          r_com_t2 = FrRand();
          Fr sum = FrZero();
          if (eff_t0_rows > 0) {
            std::vector<Fr> row_sums(eff_t0_rows);
            auto compute_row = [&](int64_t i) {
              Fr const* a_row = mat_ac.data() + (i + half_rows) * padded_n;
              Fr const* b_row = mat_bd.data() + i * padded_n;
              row_sums[i] = InnerProduct(a_row, b_row, padded_n);
            };
            parallel::For(eff_t0_rows, compute_row);
            sum = parallel::Accumulate(row_sums.begin(), row_sums.end(), FrZero());
          }
          t2 = sum;
          bp_proof.sc_com_t2.push_back(pc::ComputeCom(gc, t2, r_com_t2));
        };
        parallel::Invoke(tasks);

        UpdateSeed(seed, bp_proof.sc_com_t0.back(), bp_proof.sc_com_t2.back());
        Fr e_val = H256ToFr(seed);
        e_challenges.push_back(e_val);

        // Fold rows: mat_ac[i] += e * mat_ac[i + half], mat_bd[i] = e * mat_bd[i] + mat_bd[i + half]
        if (eff_t0_rows > 0) {
          auto fold_rows = [&](int64_t i) {
            Fr* a_row = mat_ac.data() + i * padded_n;
            Fr* a_row_upper = mat_ac.data() + (i + half_rows) * padded_n;
            Fr* b_row = mat_bd.data() + i * padded_n;
            Fr* b_row_upper = mat_bd.data() + (i + half_rows) * padded_n;
            for (int64_t j = 0; j < padded_n; ++j) {
              a_row[j] = a_row[j] + e_val * a_row_upper[j];
              b_row[j] = e_val * b_row[j] + b_row_upper[j];
            }
          };
          parallel::For(eff_t0_rows, fold_rows);
        }
        if (eff_t0_rows < effective_m && eff_t0_rows < half_rows) {
          auto scale_rows = [&](int64_t i) {
            Fr* b_row = mat_bd.data() + i * padded_n;
            for (int64_t j = 0; j < padded_n; ++j) {
              b_row[j] = e_val * b_row[j];
            }
          };
          parallel::For(eff_t0_rows, std::min(effective_m, half_rows), scale_rows);
        }

        Fr ee = e_val * e_val;
        hat_t = t0 + hat_t * e_val + t2 * ee;
        hat_r_com_t = r_com_t0 + hat_r_com_t * e_val + r_com_t2 * ee;

        current_padded_m = half_rows;
        effective_m = std::min(effective_m, half_rows);

        // Shrink mat_ac/mat_bd to release upper-half rows that are no longer needed.
        // After folding, only rows [0, effective_m) are live.
        int64_t new_size = effective_m * padded_n;
        mat_ac.resize(new_size);
        mat_bd.resize(new_size);
      }
    }

    // Phase 2: Column-dimension SumCheck (l_n rounds)
    std::vector<Fr> u_vec(mat_ac.begin(), mat_ac.begin() + padded_n);
    std::vector<Fr> v_vec(mat_bd.begin(), mat_bd.begin() + padded_n);
    mat_ac.clear();
    mat_ac.shrink_to_fit();
    mat_bd.clear();
    mat_bd.shrink_to_fit();

    SumCheck::Prove(l_n, padded_n, bp_proof.sc_com_t0, bp_proof.sc_com_t2,
                    e_challenges, seed, u_vec, v_vec, hat_t, hat_r_com_t, gc);

    assert(u_vec.size() == 1 && v_vec.size() == 1);
    Fr hat_u = u_vec[0];
    Fr hat_v = v_vec[0];

    // Step 4: Commit to hat_u, hat_v and compute tensor products (all parallel)
    Fr hat_mu, hat_nu;
    std::vector<Fr> acute_e_L, acute_e_R, grave_e_L, grave_e_R;
    std::vector<Fr> acute_e_L_trimmed, acute_e_R_trimmed;
    std::vector<Fr> grave_e_L_trimmed, grave_e_R_trimmed;
    {
      std::array<parallel::VoidTask, 4> tasks;
      tasks[0] = [&]() {
        hat_mu = FrRand();
        bp_proof.hat_U = pc::ComputeCom(gc, hat_u, hat_mu);
      };
      tasks[1] = [&]() {
        hat_nu = FrRand();
        bp_proof.hat_V = pc::ComputeCom(gc, hat_v, hat_nu);
      };
      tasks[2] = [&]() {
        misc::ComputeAcuteTensor(acute_e_L, e_challenges, 0, l_m);
        grave_e_L.assign(acute_e_L.rbegin(), acute_e_L.rend());
        acute_e_L_trimmed.assign(acute_e_L.begin(), acute_e_L.begin() + m_val);
        grave_e_L_trimmed.assign(grave_e_L.begin(), grave_e_L.begin() + m_val);
      };
      tasks[3] = [&]() {
        misc::ComputeAcuteTensor(acute_e_R, e_challenges, l_m, l_n);
        grave_e_R.assign(acute_e_R.rbegin(), acute_e_R.rend());
        acute_e_R_trimmed.assign(acute_e_R.begin(), acute_e_R.begin() + n_val);
        grave_e_R_trimmed.assign(grave_e_R.begin(), grave_e_R.begin() + n_val);
      };
      parallel::Invoke(tasks);
    }
    UpdateSeed(seed, bp_proof.hat_U, bp_proof.hat_V);

    // Step 5: Compute hat_a, hat_b, c_acute_eR, d_grave_eR, blinding factors (all parallel)
    std::vector<Fr> hat_a_vec, hat_b_vec, c_acute_eR, d_grave_eR;
    Fr r_c_acute, r_d_grave;
    {
      std::array<parallel::VoidTask, 6> tasks;
      tasks[0] = [&]() { MatrixVectorMul(acute_e_L_trimmed, hat_S_sparse, hat_a_vec); };
      tasks[1] = [&]() { MatrixVectorMul(grave_e_L_trimmed, mat_b, hat_b_vec); };
      tasks[2] = [&]() { MatrixVectorMul(row_z, acute_e_R_trimmed, c_acute_eR); };
      // d_grave_eR = row_z * diag(r_challenge) * grave_e_R = row_z * (r_challenge ⊙ grave_e_R)
      tasks[3] = [&]() {
        std::vector<Fr> scaled_grave_eR(grave_e_R_trimmed.size());
        for (int64_t j = 0; j < (int64_t)grave_e_R_trimmed.size(); ++j) {
          scaled_grave_eR[j] = grave_e_R_trimmed[j] * r_challenge[j];
        }
        MatrixVectorMul(row_z, scaled_grave_eR, d_grave_eR);
      };
      tasks[4] = [&]() { r_c_acute = InnerProduct(com_sec.r_com_c, acute_e_R); };
      tasks[5] = [&]() { r_d_grave = InnerProduct(com_sec.r_com_d, grave_e_R); };
      parallel::Invoke(tasks);
    }

    // Release hat_S_sparse memory (no longer needed after Step 5)
    const_cast<SparseMatrix&>(hat_S_sparse).values_.clear();
    const_cast<SparseMatrix&>(hat_S_sparse).values_.shrink_to_fit();
    const_cast<SparseMatrix&>(hat_S_sparse).col_idx_.clear();
    const_cast<SparseMatrix&>(hat_S_sparse).col_idx_.shrink_to_fit();
    const_cast<SparseMatrix&>(hat_S_sparse).row_ptr_.clear();
    const_cast<SparseMatrix&>(hat_S_sparse).row_ptr_.shrink_to_fit();

    // Step 6: Run R_{sm} and store R_{cp}^A instances
    A1::Prove(bp_proof.sm_proof, seed,
              A1::ProveInput(hat_u, hat_v, hat_t),
              A1::CommitmentSec(hat_mu, hat_nu, hat_r_com_t));

    assert(hat_u == InnerProduct(hat_a_vec, c_acute_eR));
    assert(hat_v == InnerProduct(hat_b_vec, d_grave_eR));

    cpa_instance.cp_b = {hat_a_vec, hat_b_vec};
    cpa_instance.cp_a = {c_acute_eR, d_grave_eR};
    cpa_instance.cp_c = {hat_u, hat_v};
    cpa_instance.cp_com_sec = A5::CommitmentSec({r_c_acute, r_d_grave},
                                                 {hat_mu, hat_nu});
    cpa_instance.num_bp_instances = 2;
    cpa_instance.num_cp_instance = 0;
    cpa_instance.num_cc_instance = 0;
  }

  // Sparse ProveIf: uses sparse matrix multiplication + merged R_{cp}^A
  //
  // Memory optimizations:
  //   1. hat_z_rows is NOT pre-allocated; r_challenge is passed to
  //      SparseProveBpReturnCpA which computes BD on-the-fly (saves ~37 GB).
  //   2. Copy constraint columns are extracted AFTER SparseProveBpReturnCpA
  //      (which releases mat_ac/mat_bd internally), so cc data and the large
  //      SumCheck matrices never coexist in memory.
  //   3. row_z is released immediately after cc column extraction.
  //   4. s_powers is released after hat_S_sparse is built.
  static void ProveIf(Proof& proof, h256_t seed,
                      SparseProveInput const& input,
                      CommitmentPub const& com_pub,
                      CommitmentSec const& com_sec) {
    Tick tick(__FN__, "ProveIf " + input.to_string());

    int64_t m_val = input.m();
    int64_t n_val = input.n();
    int64_t n_vars_val = input.n_vars();
    int64_t l_val = input.input_len();

    // Step 1: Derive challenges
    std::vector<Fr> r_challenge;
    Fr s_challenge;
    DeriveChallenges(seed, com_pub.com_z, r_challenge, s_challenge);

    std::vector<Fr> s_powers(m_val);
    s_powers[0] = FrOne();
    for (int64_t i = 1; i < m_val; ++i) {
      s_powers[i] = s_powers[i - 1] * s_challenge;
    }

    // Compute s_times_c and z_times_r in parallel
    std::vector<Fr> s_times_c, z_times_r;
    {
      std::array<parallel::VoidTask, 2> tasks;
      tasks[0] = [&]() { MatrixVectorMul(s_powers, input.mat_c, s_times_c); };
      tasks[1] = [&]() { MatrixVectorMul(input.row_z, r_challenge, z_times_r); };
      parallel::Invoke(tasks);
    }
    Fr t_val = InnerProduct(s_times_c, z_times_r);

    // Step 2: Commit to t
    Fr r_com_t = FrRand();
    G1 gc = pc::PcG(0);
    proof.com_t = pc::ComputeCom(gc, t_val, r_com_t);

    UpdateSeed(seed, proof.com_t);

    // Step 3: Build hat_S_sparse and compute r_com_hat_z in parallel
    SparseMatrix hat_S_sparse;
    std::vector<Fr> r_com_hat_z(n_val);
    {
      std::array<parallel::VoidTask, 2> tasks;
      tasks[0] = [&]() { hat_S_sparse = ScaleSparseRows(input.mat_a, s_powers); };
      tasks[1] = [&]() {
        auto compute_r = [&](int64_t j) {
          r_com_hat_z[j] = com_sec.r_com_z[j] * r_challenge[j];
        };
        parallel::For(n_val, compute_r);
      };
      parallel::Invoke(tasks);
    }

    // Release s_powers (~0.3 GB) — no longer needed after hat_S_sparse is built
    s_powers.clear();
    s_powers.shrink_to_fit();

    Fr r_com_hat_R = FrZero();
    for (int64_t j = 0; j < n_val; ++j) {
      r_com_hat_R += r_com_hat_z[j];
    }

    std::vector<Fr> const& hat_c_vec = s_times_c;
    std::vector<Fr> const& hat_r_vec = z_times_r;

    // Step 4: Call SparseProveBpReturnCpA
    // row_z is still alive here; SparseProveBpReturnCpA uses it for mat-mul
    // and Step 5 (c_acute_eR, d_grave_eR). After return, mat_ac/mat_bd are
    // already released inside the function.
    A11::CommitmentSec bp_com_sec;
    bp_com_sec.r_com_t = r_com_t;
    bp_com_sec.r_com_c = com_sec.r_com_z;
    bp_com_sec.r_com_d = r_com_hat_z;

    IfCpAInstance if_cpa_instance;
    SparseProveBpReturnCpA(proof.bp_proof, seed,
                            hat_S_sparse, input.mat_b, input.row_z, r_challenge,
                            t_val, input.get_g, bp_com_sec, if_cpa_instance);

    // Step 5: Add R_{cp} instance for <hat_r, hat_c> = t
    if_cpa_instance.cp_a.push_back(hat_r_vec);
    if_cpa_instance.cp_b.push_back(hat_c_vec);
    if_cpa_instance.cp_c.push_back(t_val);
    if_cpa_instance.cp_com_sec.r_com_a.push_back(r_com_hat_R);
    if_cpa_instance.cp_com_sec.r_com_c.push_back(r_com_t);
    if_cpa_instance.num_cp_instance = 1;

    // Step 6: Handle R_{cc}^A for copy constraints (multi-range)
    // Extract cc columns NOW (after SparseProveBpReturnCpA released mat_ac/mat_bd),
    // so cc data (~37 GB) never coexists with the large SumCheck matrices (~82 GB).
    if (n_val > 1) {
      std::vector<std::vector<Fr>> cc_a_vec(n_val - 1);
      std::vector<std::vector<Fr>> cc_b_vec(n_val - 1);
      std::vector<A10::CommitmentSec> cc_com_secs(n_val - 1);

      auto compute_cc = [&](int64_t j) {
        cc_a_vec[j] = input.row_z.col(j);
        cc_b_vec[j] = input.row_z.col(j + 1);
        cc_com_secs[j] = A10::CommitmentSec(com_sec.r_com_z[j],
                                             com_sec.r_com_z[j + 1]);
      };
      parallel::For(n_val - 1, compute_cc);

      // Release row_z memory (~37 GB) — no longer needed
      const_cast<FlatMatrix&>(input.row_z).data_.clear();
      const_cast<FlatMatrix&>(input.row_z).data_.shrink_to_fit();

      CcACpInstance cc_cp_instance;
      ProveCcAReturnCp(proof.cc_proof, seed,
                        cc_a_vec, cc_b_vec,
                        cc_com_secs,
                        input.copy_ranges, input.get_g,
                        cc_cp_instance);

      if_cpa_instance.cp_a.push_back(cc_cp_instance.cp_a);
      if_cpa_instance.cp_b.push_back(cc_cp_instance.cp_b);
      if_cpa_instance.cp_c.push_back(cc_cp_instance.cp_c);
      if_cpa_instance.cp_com_sec.r_com_a.push_back(cc_cp_instance.cp_com_sec.r_com_a);
      if_cpa_instance.cp_com_sec.r_com_c.push_back(cc_cp_instance.cp_com_sec.r_com_c);
      if_cpa_instance.num_cc_instance = 1;
    } else {
      // Release row_z even when no copy constraints
      const_cast<FlatMatrix&>(input.row_z).data_.clear();
      const_cast<FlatMatrix&>(input.row_z).data_.shrink_to_fit();
    }

    // Step 7: Prove the batched R_{cp}^A
    A5::ProveInput cpa_input(if_cpa_instance.cp_a, if_cpa_instance.cp_b,
                              if_cpa_instance.cp_c, input.get_g, gc);
    A5::Prove(proof.bp_proof.cp_proof, seed, cpa_input,
              if_cpa_instance.cp_com_sec);
  }

  // Sparse VerifyIf: verifies the batched R_{cp}^A proof with sparse matrices
  static bool VerifyIf(Proof const& proof, h256_t seed,
                       SparseVerifyInput const& input) {
    Tick tick(__FN__, "VerifyIf " + input.to_string());

    int64_t m_val = input.m();
    int64_t n_vars_val = input.n_vars();
    int64_t n_val = input.n();
    int64_t l_val = input.input_len();

    // Step 1: Derive challenges
    std::vector<Fr> r_challenge;
    Fr s_challenge;
    DeriveChallenges(seed, input.com_pub.com_z, r_challenge, s_challenge);

    std::vector<Fr> s_powers(m_val);
    s_powers[0] = FrOne();
    for (int64_t i = 1; i < m_val; ++i) {
      s_powers[i] = s_powers[i - 1] * s_challenge;
    }

    UpdateSeed(seed, proof.com_t);

    // Step 2: Build hat_S_sparse = ScaleSparseRows(mat_a, s_powers)
    SparseMatrix hat_S_sparse = ScaleSparseRows(input.mat_a, s_powers);

    // Step 3: Verify R_{bp} (SumCheck and R_{sm})
    A11::CommitmentPub bp_com_pub;
    bp_com_pub.com_t = proof.com_t;
    bp_com_pub.com_c.resize(n_val);
    bp_com_pub.com_d.resize(n_val);
    auto compute_bp_com = [&](int64_t j) {
      bp_com_pub.com_c[j] = input.com_pub.com_z[j];
      bp_com_pub.com_d[j] = input.com_pub.com_z[j] * r_challenge[j];
    };
    parallel::For(n_val, compute_bp_com);

    // Verify SumCheck
    G1 gc = pc::PcG(0);
    G1 com_t = proof.com_t;
    std::vector<Fr> e_challenges;
    SumCheck::Verify(proof.bp_proof.sc_com_t0, proof.bp_proof.sc_com_t2, seed,
                     com_t, e_challenges);

    int64_t l_m = (int64_t)misc::Log2UB(m_val);
    int64_t l_n = (int64_t)misc::Log2UB(n_val);
    assert((int64_t)e_challenges.size() == l_m + l_n);

    UpdateSeed(seed, proof.bp_proof.hat_U, proof.bp_proof.hat_V);

    // Compute tensor products
    std::vector<Fr> acute_e_L, acute_e_R, grave_e_L, grave_e_R;
    misc::ComputeAcuteTensor(acute_e_L, e_challenges, 0, l_m);
    misc::ComputeAcuteTensor(acute_e_R, e_challenges, l_m, l_n);
    grave_e_L.assign(acute_e_L.rbegin(), acute_e_L.rend());
    grave_e_R.assign(acute_e_R.rbegin(), acute_e_R.rend());

    std::vector<Fr> acute_e_L_trimmed(acute_e_L.begin(), acute_e_L.begin() + m_val);
    std::vector<Fr> grave_e_L_trimmed(grave_e_L.begin(), grave_e_L.begin() + m_val);

    // Compute hat_a, hat_b using sparse MatrixVectorMul
    std::vector<Fr> hat_a_vec, hat_b_vec;
    {
      std::array<parallel::VoidTask, 2> tasks;
      tasks[0] = [&]() { MatrixVectorMul(acute_e_L_trimmed, hat_S_sparse, hat_a_vec); };
      tasks[1] = [&]() { MatrixVectorMul(grave_e_L_trimmed, input.mat_b, hat_b_vec); };
      parallel::Invoke(tasks);
    }

    // Compute hat_C, hat_D
    auto get_acute_eR = [&acute_e_R](int64_t j) -> Fr const& { return acute_e_R[j]; };
    auto get_grave_eR = [&grave_e_R](int64_t j) -> Fr const& { return grave_e_R[j]; };
    auto get_com_c = [&bp_com_pub](int64_t j) -> G1 const& { return bp_com_pub.com_c[j]; };
    auto get_com_d = [&bp_com_pub](int64_t j) -> G1 const& { return bp_com_pub.com_d[j]; };
    G1 hat_C = MultiExpBdlo12Inner<G1>(get_com_c, get_acute_eR, n_val);
    G1 hat_D = MultiExpBdlo12Inner<G1>(get_com_d, get_grave_eR, n_val);

    // Verify R_{sm}
    A1::CommitmentPub sm_com_pub(proof.bp_proof.hat_U, proof.bp_proof.hat_V, com_t);
    A1::VerifyInput sm_verify(sm_com_pub);
    bool sm_ret = A1::Verify(proof.bp_proof.sm_proof, seed, sm_verify);
    std::cout << "VerifyIf: A1::Verify (R_{sm}) result: " << sm_ret << "\n";

    // Step 4: Build the batched R_{cp}^A verification input
    std::vector<std::vector<Fr>> cp_b = {hat_a_vec, hat_b_vec};

    // Compute hat_c = s^T * C (sparse)
    std::vector<Fr> hat_c_vec;
    MatrixVectorMul(s_powers, input.mat_c, hat_c_vec);
    cp_b.push_back(hat_c_vec);

    // hat_R = prod Z_j^{r_j} = sum com_d[j] (since com_d[j] = com_z[j] * r[j])
    G1 hat_R = G1Zero();
    for (int64_t j = 0; j < n_val; ++j) {
      hat_R += bp_com_pub.com_d[j];
    }

    // Step 5: Handle R_{cc}^A verification (multi-range)
    G1 cc_hat_U;
    G1 cc_com_w;
    if (n_val > 1) {
      // Derive amortization challenge directly from seed (no UpdateSeed with commitments)
      Fr e_amort = H256ToFr(seed);

      std::vector<Fr> e_powers(n_val - 1);
      e_powers[0] = FrOne();
      for (int64_t i = 1; i < n_val - 1; ++i) {
        e_powers[i] = e_powers[i - 1] * e_amort;
      }

      // Compute aggregated commitments hat_A, hat_B from com_z
      std::vector<G1> cc_com_a_vec(n_val - 1), cc_com_b_vec(n_val - 1);
      auto build_cc_com = [&](int64_t j) {
        cc_com_a_vec[j] = input.com_pub.com_z[j];
        cc_com_b_vec[j] = input.com_pub.com_z[j + 1];
      };
      parallel::For(n_val - 1, build_cc_com);

      auto get_cc_com_a = [&cc_com_a_vec](int64_t i) -> G1 const& { return cc_com_a_vec[i]; };
      auto get_cc_com_b = [&cc_com_b_vec](int64_t i) -> G1 const& { return cc_com_b_vec[i]; };
      auto get_e_power = [&e_powers](int64_t i) -> Fr const& { return e_powers[i]; };
      G1 hat_A = MultiExpBdlo12Inner<G1>(get_cc_com_a, get_e_power, n_val - 1);
      G1 hat_B = MultiExpBdlo12Inner<G1>(get_cc_com_b, get_e_power, n_val - 1);

      std::vector<Fr> r_cc_challenge;
      A10::DeriveRChallenge(seed, input.copy_ranges, r_cc_challenge);

      std::vector<Fr> c_vec, d_vec;
      A10::BuildSelectionVectors(c_vec, d_vec, r_cc_challenge, n_vars_val, input.copy_ranges);

      cc_com_w = pc::ComputeCom(gc, FrZero(), FrZero());
      std::vector<Fr> e_sc_vec;
      SumCheck::Verify(proof.cc_proof.sc_com_t0, proof.cc_proof.sc_com_t2, seed,
                       cc_com_w, e_sc_vec);
      assert(e_sc_vec.size() == 1);
      Fr e_sc = e_sc_vec[0];

      std::vector<Fr> hat_v_cc(n_vars_val);
      auto fold_f = [&hat_v_cc, &c_vec, &d_vec, &e_sc](int64_t i) {
        hat_v_cc[i] = e_sc * c_vec[i] + d_vec[i];
      };
      parallel::For(n_vars_val, fold_f);

      cc_hat_U = hat_A + hat_B * e_sc;
      cp_b.push_back(hat_v_cc);
    }

    // Step 6: Verify the batched R_{cp}^A
    std::vector<G1> cp_com_a = {hat_C, hat_D, hat_R};
    if (n_val > 1) {
      cp_com_a.push_back(cc_hat_U);
    }
    std::vector<G1> cp_com_c = {proof.bp_proof.hat_U, proof.bp_proof.hat_V, proof.com_t};
    if (n_val > 1) {
      cp_com_c.push_back(cc_com_w);
    }

    A5::CommitmentPub cp_com_pub(cp_com_a, cp_com_c);
    A5::VerifyInput cp_verify(cp_b, cp_com_pub, input.get_g, gc);
    bool cp_ret = A5::Verify(proof.bp_proof.cp_proof, seed, cp_verify);
    std::cout << "VerifyIf: A5::Verify (R_{cp}^A) result: " << cp_ret << "\n";

    bool ret = sm_ret && cp_ret;
    std::cout << "VerifyIf: Final result: " << ret << "\n";

    return ret;
  }
  // Test function for multi-range copy constraints with A12 protocol.
  // Constructs a simple R1CS system where each constraint is z_0 * z_i = z_i
  // (i.e., the "one" variable times each variable equals itself).
  // The witness matrix Z has n_cols columns, with adjacent columns satisfying
  // the given copy_ranges.
  static bool TestMultiRange(int64_t m_val, int64_t n_cols,
                             std::vector<CopyRange> const& ranges) {
    std::cout << "\n=== A12::TestMultiRange m=" << m_val
              << " n_cols=" << n_cols << " ranges=" << ranges.size() << " ===\n";

    // n_vars = m_val + 1 (index 0 is the "one" variable in libsnark convention)
    int64_t n_vars = m_val + 1;

    // Build trivial R1CS: for each constraint i, A[i,0]=1, B[i,i+1]=1, C[i,i+1]=1
    // This encodes: 1 * z_{i+1} = z_{i+1}
    SparseMatrix sparse_a, sparse_b, sparse_c;
    sparse_a.rows_ = m_val;
    sparse_a.cols_ = n_vars;
    sparse_b.rows_ = m_val;
    sparse_b.cols_ = n_vars;
    sparse_c.rows_ = m_val;
    sparse_c.cols_ = n_vars;

    sparse_a.row_ptr_.resize(m_val + 1);
    sparse_b.row_ptr_.resize(m_val + 1);
    sparse_c.row_ptr_.resize(m_val + 1);

    for (int64_t i = 0; i < m_val; ++i) {
      sparse_a.row_ptr_[i] = i;
      sparse_a.col_idx_.push_back(0);       // A[i,0] = 1
      sparse_a.values_.push_back(FrOne());

      sparse_b.row_ptr_[i] = i;
      sparse_b.col_idx_.push_back(i + 1);   // B[i,i+1] = 1
      sparse_b.values_.push_back(FrOne());

      sparse_c.row_ptr_[i] = i;
      sparse_c.col_idx_.push_back(i + 1);   // C[i,i+1] = 1
      sparse_c.values_.push_back(FrOne());
    }
    sparse_a.row_ptr_[m_val] = m_val;
    sparse_b.row_ptr_[m_val] = m_val;
    sparse_c.row_ptr_[m_val] = m_val;

    // Build witness matrix Z (n_vars x n_cols)
    // Z[0][j] = 1 (the "one" variable) for all j
    // Z[i][j] = random for i >= 1
    // Then enforce copy constraints between adjacent columns
    FlatMatrix row_z(n_vars, n_cols);
    for (int64_t j = 0; j < n_cols; ++j) {
      row_z(0, j) = FrOne();  // "one" variable
      for (int64_t i = 1; i < n_vars; ++i) {
        row_z(i, j) = FrRand();
      }
    }

    // Enforce copy constraints: for each pair (j, j+1), copy ranges
    for (int64_t j = 0; j < n_cols - 1; ++j) {
      for (auto const& range : ranges) {
        for (int64_t k = 0; k < range.l; ++k) {
          row_z(range.l_b + k, j + 1) = row_z(range.l_a + k, j);
        }
      }
    }

    // Verify R1CS: A*z .* B*z = C*z for each column
    for (int64_t j = 0; j < n_cols; ++j) {
      std::vector<Fr> z_col = row_z.col(j);
      for (int64_t i = 0; i < m_val; ++i) {
        // A[i] * z = z[0] = 1
        Fr az = FrZero();
        for (int64_t k = sparse_a.row_ptr_[i]; k < sparse_a.row_ptr_[i + 1]; ++k) {
          az += sparse_a.values_[k] * z_col[sparse_a.col_idx_[k]];
        }
        Fr bz = FrZero();
        for (int64_t k = sparse_b.row_ptr_[i]; k < sparse_b.row_ptr_[i + 1]; ++k) {
          bz += sparse_b.values_[k] * z_col[sparse_b.col_idx_[k]];
        }
        Fr cz = FrZero();
        for (int64_t k = sparse_c.row_ptr_[i]; k < sparse_c.row_ptr_[i + 1]; ++k) {
          cz += sparse_c.values_[k] * z_col[sparse_c.col_idx_[k]];
        }
        if (az * bz != cz) {
          std::cout << "R1CS violation at col " << j << " constraint " << i << "\n";
          return false;
        }
      }
    }
    std::cout << "R1CS check passed for all " << n_cols << " columns\n";

    // Verify copy constraints
    for (int64_t j = 0; j < n_cols - 1; ++j) {
      for (auto const& range : ranges) {
        for (int64_t k = 0; k < range.l; ++k) {
          if (row_z(range.l_a + k, j) != row_z(range.l_b + k, j + 1)) {
            std::cout << "Copy constraint violation at col " << j
                      << " range l_a=" << range.l_a << " l_b=" << range.l_b
                      << " offset=" << k << "\n";
            return false;
          }
        }
      }
    }
    std::cout << "Copy constraint check passed\n";

    // A12 Prove
    h256_t seed = misc::RandH256();
    SparseProveInput prove_input(sparse_a, sparse_b, sparse_c, row_z,
                                 ranges, pc::kGetRefG1);

    CommitmentPub com_pub;
    CommitmentSec com_sec;
    ComputeCom(com_pub, com_sec, prove_input);

    Proof proof;
    ProveIf(proof, seed, prove_input, com_pub, com_sec);

    std::cout << "Proof FrSize: " << proof.FrSize()
              << ", G1Size: " << proof.G1Size() << "\n";

    // A12 Verify
    SparseVerifyInput verify_input(sparse_a, sparse_b, sparse_c, com_pub,
                                   n_cols, ranges, pc::kGetRefG1);
    bool result = VerifyIf(proof, seed, verify_input);
    std::cout << "A12::TestMultiRange result: " << result << "\n";
    return result;
  }
};
}  // namespace argument
