// #pragma once

#include "argument/a12.h"
#include "circuit/func.h"
#include "circuit/pong/dqn_env_gadget.h"
#include "circuit/pong/render/render_gadget.h"
#include "yas/tests/base/externals/nlohmann_json.hpp"

namespace clink::pong{

/**
 * Performance statistics for IteratedFunctionProof
 */
struct IteratedFunctionProofStats {
    size_t max_steps;
    size_t num_instances;
    size_t num_constraints;
    size_t num_vars;
    double trajectory_gen_ms;
    double matrix_transpose_ms;
    double compute_com_ms;
    double prove_ms;
    double verify_ms;
    double total_ms;
    size_t proof_fr_size;
    size_t proof_g1_size;
    bool verify_success;
    double peak_memory_mb;
    // New fields
    size_t com_g1_count;
    size_t com_serialized_size;
    size_t proof_serialized_size;
    size_t total_proof_size;  // com_serialized_size + proof_serialized_size
    double prove_total_ms;
    double verify_total_ms;
    
    std::string to_csv_header() const {
        return "max_steps,num_instances,num_constraints,num_vars,"
               "trajectory_gen_ms,matrix_transpose_ms,compute_com_ms,"
               "prove_ms,verify_ms,total_ms,proof_fr_size,proof_g1_size,"
               "verify_success,peak_memory_mb,"
               "com_g1_count,com_serialized_size,proof_serialized_size,total_proof_size,"
               "prove_total_ms,verify_total_ms";
    }
    
    std::string to_csv() const {
        std::stringstream ss;
        ss << max_steps << ","
           << num_instances << ","
           << num_constraints << ","
           << num_vars << ","
           << std::fixed << std::setprecision(2)
           << trajectory_gen_ms << ","
           << matrix_transpose_ms << ","
           << compute_com_ms << ","
           << prove_ms << ","
           << verify_ms << ","
           << total_ms << ","
           << proof_fr_size << ","
           << proof_g1_size << ","
           << verify_success << ","
           << peak_memory_mb << ","
           << com_g1_count << ","
           << com_serialized_size << ","
           << proof_serialized_size << ","
           << total_proof_size << ","
           << prove_total_ms << ","
           << verify_total_ms;
        return ss.str();
    }
    
    void print() const {
        std::cout << "\n========== Performance Statistics ==========\n";
        std::cout << "max_steps:         " << max_steps << "\n";
        std::cout << "num_instances:     " << num_instances << "\n";
        std::cout << "num_constraints:   " << num_constraints << "\n";
        std::cout << "num_vars:          " << num_vars << "\n";
        std::cout << "--------------------------------------------\n";
        std::cout << std::fixed << std::setprecision(2);
        std::cout << "trajectory_gen:    " << trajectory_gen_ms << " ms\n";
        std::cout << "matrix_transpose:  " << matrix_transpose_ms << " ms\n";
        std::cout << "compute_com:       " << compute_com_ms << " ms\n";
        std::cout << "prove:             " << prove_ms << " ms\n";
        std::cout << "verify:            " << verify_ms << " ms\n";
        std::cout << "total:             " << total_ms << " ms\n";
        std::cout << "--------------------------------------------\n";
        std::cout << "prove_total:       " << prove_total_ms << " ms (trajectory_gen + compute_com + prove)\n";
        std::cout << "verify_total:      " << verify_total_ms << " ms\n";
        std::cout << "--------------------------------------------\n";
        std::cout << "com_g1_count:      " << com_g1_count << "\n";
        std::cout << "com_size:          " << com_serialized_size << " bytes\n";
        std::cout << "proof_fr_size:     " << proof_fr_size << "\n";
        std::cout << "proof_g1_size:     " << proof_g1_size << "\n";
        std::cout << "proof_size:        " << proof_serialized_size << " bytes\n";
        std::cout << "total_proof_size:  " << total_proof_size << " bytes (com + proof)\n";
        std::cout << "verify_success:    " << (verify_success ? "true" : "false") << "\n";
        std::cout << "peak_memory:       " << peak_memory_mb << " MB\n";
        std::cout << "============================================\n\n";
    }
};

/**
 * Load DQN weights from CSV file
 */
inline std::vector<int64_t> LoadWeights(const std::string& filepath) {
    std::vector<int64_t> weights;
    std::ifstream file(filepath);
    CHECK(file.is_open(), "Cannot open weights file: " << filepath);
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        std::stringstream ss(line);
        std::string value;
        while (std::getline(ss, value, ',')) {
            if (!value.empty()) {
                weights.push_back(std::stoll(value));
            }
        }
    }
    return weights;
}

/**
 * Compute AI action (weakened version)
 * 10% probability of no action, ±4 pixel reaction dead zone
 */
inline int ComputeAiAction(int paddle2_x, int ball_x, int paddle_width, std::mt19937& rng) {
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    
    if (dist(rng) < 0.10) {
        return 0;  // 10% probability of no action
    }
    
    int paddle_center = paddle2_x + paddle_width / 2;
    
    if (ball_x < paddle_center - 4) {
        return 1;  // Move left
    } else if (ball_x > paddle_center + 4) {
        return 2;  // Move right
    }
    return 0;  // No action
}

/**
 * Helper: Transpose assignment matrix from row-major to FlatMatrix.
 * Uses blocked transpose for better cache locality.
 * @param row_z Row-major assignment vectors (num_instances x num_vars)
 * @param num_variables Number of variables (excluding constant 1)
 * @return FlatMatrix with dimensions (num_vars+1) x num_instances
 */
inline FlatMatrix TransposeAssignmentMatrix(
    std::vector<std::vector<Fr>>& row_z,
    int64_t num_variables) {
    int64_t n_inst = static_cast<int64_t>(row_z.size());
    int64_t total_rows = num_variables + 1;
    FlatMatrix flat_row_z(total_rows, n_inst);
    
    // Optimization: Use blocked transpose for better cache locality.
    // Process blocks of rows at a time to keep both source and destination in cache.
    constexpr int64_t BLOCK_SIZE = 64;
    int64_t num_blocks = (total_rows + BLOCK_SIZE - 1) / BLOCK_SIZE;
    
    auto transpose_block = [&](int64_t block) {
        int64_t row_start = block * BLOCK_SIZE;
        int64_t row_end = std::min(row_start + BLOCK_SIZE, total_rows);
        for (int64_t j = 0; j < n_inst; ++j) {
            for (int64_t i = row_start; i < row_end; ++i) {
                flat_row_z(i, j) = row_z[j][i];
            }
        }
    };
    parallel::For(num_blocks, transpose_block);
    
    // Free original row_z memory
    { std::vector<std::vector<Fr>>().swap(row_z); }
    
    return flat_row_z;
}

/**
 * Statistics for witness matrix sparsity analysis.
 */
struct WitnessSparsityStats {
    int64_t total_elements;        // 总元素数: rows * cols
    int64_t zero_count;            // 零元素数量
    int64_t nonzero_count;         // 非零元素数量
    double zero_ratio;             // 零元素比例
    double nonzero_ratio;          // 非零元素比例
    
    // 按行统计
    std::vector<int64_t> row_nonzero_counts;  // 每行非零元素数量
    int64_t min_row_nonzero;
    int64_t max_row_nonzero;
    double avg_row_nonzero;
    
    // 按列统计
    std::vector<int64_t> col_nonzero_counts;  // 每列非零元素数量
    int64_t min_col_nonzero;
    int64_t max_col_nonzero;
    double avg_col_nonzero;
    
    // 特殊值统计
    int64_t one_count;             // 值为 1 的元素数量
    int64_t minus_one_count;       // 值为 -1 的元素数量
    int64_t small_value_count;     // 绝对值 < 10 的元素数量 (不含 0, ±1)
    
    void print() const {
        std::cout << "\n========== Witness Matrix Sparsity Analysis ==========\n";
        std::cout << "Matrix dimensions: " << row_nonzero_counts.size() << " rows x " 
                  << col_nonzero_counts.size() << " cols\n";
        std::cout << "Total elements:    " << total_elements << "\n";
        std::cout << "Zero elements:     " << zero_count << " (" 
                  << std::fixed << std::setprecision(2) << (zero_ratio * 100) << "%)\n";
        std::cout << "Non-zero elements: " << nonzero_count << " (" 
                  << (nonzero_ratio * 100) << "%)\n";
        std::cout << "----------------------------------------------------\n";
        std::cout << "Per-row non-zero stats:\n";
        std::cout << "  Min: " << min_row_nonzero << "\n";
        std::cout << "  Max: " << max_row_nonzero << "\n";
        std::cout << "  Avg: " << std::fixed << std::setprecision(2) << avg_row_nonzero << "\n";
        std::cout << "Per-col non-zero stats:\n";
        std::cout << "  Min: " << min_col_nonzero << "\n";
        std::cout << "  Max: " << max_col_nonzero << "\n";
        std::cout << "  Avg: " << avg_col_nonzero << "\n";
        std::cout << "----------------------------------------------------\n";
        std::cout << "Special value counts:\n";
        std::cout << "  Value = 1:      " << one_count << "\n";
        std::cout << "  Value = -1:     " << minus_one_count << "\n";
        std::cout << "  |value| < 10:   " << small_value_count << " (excluding 0, ±1)\n";
        std::cout << "====================================================\n\n";
    }
};

/**
 * Helper: Analyze sparsity of witness matrix (FlatMatrix).
 * @param mat FlatMatrix to analyze (rows = variables, cols = instances)
 * @param verbose If true, print detailed per-row/col statistics
 * @return Sparsity statistics
 */
inline WitnessSparsityStats AnalyzeWitnessSparsity(
    FlatMatrix const& mat,
    bool verbose = false) {
    
    WitnessSparsityStats stats;
    int64_t rows = mat.rows();
    int64_t cols = mat.cols();
    
    stats.total_elements = rows * cols;
    stats.zero_count = 0;
    stats.nonzero_count = 0;
    stats.one_count = 0;
    stats.minus_one_count = 0;
    stats.small_value_count = 0;
    
    stats.row_nonzero_counts.assign(rows, 0);
    stats.col_nonzero_counts.assign(cols, 0);
    
    // 预计算小值的 Fr 表示 (0 到 9 和 -1 到 -9)
    std::vector<Fr> small_positive, small_negative;
    for (int i = 2; i < 10; ++i) {
        small_positive.push_back(Fr(i));
    }
    for (int i = -9; i <= -2; ++i) {
        small_negative.push_back(Fr(i));
    }
    
    for (int64_t i = 0; i < rows; ++i) {
        for (int64_t j = 0; j < cols; ++j) {
            Fr const& val = mat(i, j);
            bool is_zero = val == FrZero();
            
            if (is_zero) {
                stats.zero_count++;
            } else {
                stats.nonzero_count++;
                stats.row_nonzero_counts[i]++;
                stats.col_nonzero_counts[j]++;
                
                // 特殊值统计
                if (val == FrOne()) {
                    stats.one_count++;
                } else if (val == -FrOne()) {
                    stats.minus_one_count++;
                } else {
                    // 检查是否为小值 (绝对值 2-9)
                    // 使用 Fr 比较而非 getInt64()，避免大值转换异常
                    for (auto const& sv : small_positive) {
                        if (val == sv) {
                            stats.small_value_count++;
                            break;
                        }
                    }
                    if (stats.small_value_count == 0) {
                        for (auto const& sv : small_negative) {
                            if (val == sv) {
                                stats.small_value_count++;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    
    stats.zero_ratio = static_cast<double>(stats.zero_count) / stats.total_elements;
    stats.nonzero_ratio = static_cast<double>(stats.nonzero_count) / stats.total_elements;
    
    // 行统计
    stats.min_row_nonzero = *std::min_element(stats.row_nonzero_counts.begin(), 
                                               stats.row_nonzero_counts.end());
    stats.max_row_nonzero = *std::max_element(stats.row_nonzero_counts.begin(), 
                                               stats.row_nonzero_counts.end());
    stats.avg_row_nonzero = static_cast<double>(stats.nonzero_count) / rows;
    
    // 列统计
    stats.min_col_nonzero = *std::min_element(stats.col_nonzero_counts.begin(), 
                                               stats.col_nonzero_counts.end());
    stats.max_col_nonzero = *std::max_element(stats.col_nonzero_counts.begin(), 
                                               stats.col_nonzero_counts.end());
    stats.avg_col_nonzero = static_cast<double>(stats.nonzero_count) / cols;
    
    if (verbose) {
        stats.print();
    }
    
    return stats;
}

/**
 * Helper: Print detailed sparsity pattern (for small matrices or debugging).
 * Shows a visual representation where '.' = zero, '#' = non-zero.
 * @param mat FlatMatrix to visualize
 * @param max_rows Maximum rows to display (0 = all)
 * @param max_cols Maximum cols to display (0 = all)
 */
inline void PrintWitnessSparsityPattern(
    FlatMatrix const& mat,
    int64_t max_rows = 50,
    int64_t max_cols = 80) {
    
    int64_t rows = mat.rows();
    int64_t cols = mat.cols();
    
    int64_t display_rows = (max_rows > 0) ? std::min(rows, max_rows) : rows;
    int64_t display_cols = (max_cols > 0) ? std::min(cols, max_cols) : cols;
    
    std::cout << "\nWitness Matrix Sparsity Pattern (" << rows << " x " << cols << "):\n";
    std::cout << "Legend: '.' = zero, '#' = non-zero, '1' = one, '-' = minus one\n\n";
    
    for (int64_t i = 0; i < display_rows; ++i) {
        for (int64_t j = 0; j < display_cols; ++j) {
            Fr const& val = mat(i, j);
            if (val == FrZero()) {
                std::cout << '.';
            } else if (val == FrOne()) {
                std::cout << '1';
            } else if (val == -FrOne()) {
                std::cout << '-';
            } else {
                std::cout << '#';
            }
        }
        if (display_cols < cols) {
            std::cout << "...";
        }
        std::cout << "\n";
    }
    if (display_rows < rows) {
        std::cout << "... (" << (rows - display_rows) << " more rows)\n";
    }
    std::cout << "\n";
}

/**
 * Helper: Extract sparse R1CS matrices from protoboard.
 * @param pb Protoboard with constraints
 * @param sparse_a Output sparse matrix A
 * @param sparse_b Output sparse matrix B
 * @param sparse_c Output sparse matrix C
 */
inline void ExtractSparseR1CS(
    libsnark::protoboard<Fr>& pb,
    SparseMatrix& sparse_a,
    SparseMatrix& sparse_b,
    SparseMatrix& sparse_c) {
    circuit::PreprocessSparse(pb, sparse_a, sparse_b, sparse_c);
}

/**
 * Helper: Collect full assignment vector from protoboard.
 * @param pb Protoboard with assigned variables
 * @param num_variables Number of variables
 * @return Assignment vector with FrOne() at index 0
 */
inline std::vector<Fr> CollectAssignment(
    libsnark::protoboard<Fr>& pb,
    int64_t num_variables) {
    auto const& full_assignment = pb.full_variable_assignment();
    std::vector<Fr> assignment(num_variables + 1);
    assignment[0] = FrOne();
    for (int64_t i = 0; i < num_variables; ++i) {
        assignment[i + 1] = full_assignment[i];
    }
    return assignment;
}

/**
 * Helper: A12 prove and verify pipeline.
 * Handles commitment computation, proof generation, verification, and serialization.
 * 
 * @param stats Output statistics (will be populated)
 * @param sparse_a, sparse_b, sparse_c Sparse R1CS matrices
 * @param flat_row_z Transposed assignment matrix
 * @param copy_ranges Copy constraint ranges
 * @return true if verification succeeds
 */
inline bool A12ProveAndVerify(
    IteratedFunctionProofStats& stats,
    SparseMatrix const& sparse_a,
    SparseMatrix const& sparse_b,
    SparseMatrix const& sparse_c,
    FlatMatrix const& flat_row_z,
    std::vector<argument::CopyRange> const& copy_ranges) {
    
    std::cout << "\n=== Generating A12 Iterative Proof ===\n";
    
    h256_t proof_seed = misc::RandH256();
    argument::A12::SparseProveInput prove_input(
        sparse_a, sparse_b, sparse_c, flat_row_z, copy_ranges, pc::kGetRefG1);
    
    auto prove_total_start = std::chrono::high_resolution_clock::now();
    
    // Compute commitments
    std::cout << "Computing commitments...\n";
    auto com_start = std::chrono::high_resolution_clock::now();
    argument::A12::CommitmentPub com_pub;
    argument::A12::CommitmentSec com_sec;
    argument::A12::ComputeCom(com_pub, com_sec, prove_input);
    auto com_end = std::chrono::high_resolution_clock::now();
    stats.compute_com_ms = std::chrono::duration<double, std::milli>(com_end - com_start).count();
    std::cout << "Commitment time: " << stats.compute_com_ms << "ms\n";
    
    stats.com_g1_count = com_pub.com_z.size();
    
    // Generate proof
    std::cout << "Generating proof...\n";
    auto prove_start = std::chrono::high_resolution_clock::now();
    argument::A12::Proof proof;
    argument::A12::ProveIf(proof, proof_seed, prove_input, com_pub, com_sec);
    auto prove_end = std::chrono::high_resolution_clock::now();
    stats.prove_ms = std::chrono::duration<double, std::milli>(prove_end - prove_start).count();
    std::cout << "Prove time: " << stats.prove_ms << "ms\n";
    
    auto prove_total_end = std::chrono::high_resolution_clock::now();
    stats.prove_total_ms = std::chrono::duration<double, std::milli>(prove_total_end - prove_total_start).count();
    
    stats.proof_fr_size = proof.FrSize();
    stats.proof_g1_size = proof.G1Size();
    
    // Serialize commitment to get size
    yas::mem_ostream com_os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> com_oa(com_os);
    com_oa.serialize(com_pub);
    stats.com_serialized_size = com_os.get_shared_buffer().size;
    
    // Serialize proof to get size
    yas::mem_ostream proof_os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> proof_oa(proof_os);
    proof_oa.serialize(proof);
    stats.proof_serialized_size = proof_os.get_shared_buffer().size;
    
    stats.total_proof_size = stats.com_serialized_size + stats.proof_serialized_size;
    
    // A12 verify
    std::cout << "\nVerifying proof...\n";
    auto verify_total_start = std::chrono::high_resolution_clock::now();
    auto verify_start = std::chrono::high_resolution_clock::now();
    argument::A12::SparseVerifyInput verify_input(
        sparse_a, sparse_b, sparse_c, com_pub, stats.num_instances, copy_ranges, pc::kGetRefG1);
    bool verify_success = argument::A12::VerifyIf(proof, proof_seed, verify_input);
    auto verify_end = std::chrono::high_resolution_clock::now();
    stats.verify_ms = std::chrono::duration<double, std::milli>(verify_end - verify_start).count();
    auto verify_total_end = std::chrono::high_resolution_clock::now();
    stats.verify_total_ms = std::chrono::duration<double, std::milli>(verify_total_end - verify_total_start).count();
    
    std::cout << "Verify time: " << stats.verify_ms << "ms\n";
    std::cout << "Verify result: " << (verify_success ? "SUCCESS" : "FAILED") << "\n";
    
    stats.verify_success = verify_success;
    return verify_success;
}

/**
 * Helper: A12 prove and verify pipeline with sparse Z matrix optimization.
 * Uses SparseZMatrix to exploit sparsity in the witness matrix Z.
 * 
 * Key optimizations:
 * 1. Sparse Z * vector multiplication (Z * r)
 * 2. Sparse matrix * sparse Z multiplication (A * Z)
 * 3. Sparse column extraction
 * 
 * @param stats Output statistics (will be populated)
 * @param sparse_a, sparse_b, sparse_c Sparse R1CS matrices
 * @param sparse_z Sparse witness matrix Z
 * @param copy_ranges Copy constraint ranges
 * @return true if verification succeeds
 */
inline bool A12ProveAndVerifySparseZ(
    IteratedFunctionProofStats& stats,
    SparseMatrix const& sparse_a,
    SparseMatrix const& sparse_b,
    SparseMatrix const& sparse_c,
    SparseZMatrix const& sparse_z,
    std::vector<argument::CopyRange> const& copy_ranges) {
    
    std::cout << "\n=== Generating A12 Iterative Proof (Sparse Z Optimization) ===\n";
    std::cout << "Z matrix: " << sparse_z.rows() << " x " << sparse_z.cols() 
              << ", nnz=" << sparse_z.nnz() 
              << ", sparsity=" << std::fixed << std::setprecision(2) 
              << (sparse_z.sparsity() * 100) << "%\n";
    
    h256_t proof_seed = misc::RandH256();
    argument::A12::SparseZProveInput prove_input(
        sparse_a, sparse_b, sparse_c, sparse_z, copy_ranges, pc::kGetRefG1);
    
    auto prove_total_start = std::chrono::high_resolution_clock::now();
    
    // Compute commitments (optimized for sparse Z)
    std::cout << "Computing commitments (sparse Z)...\n";
    auto com_start = std::chrono::high_resolution_clock::now();
    argument::A12::CommitmentPub com_pub;
    argument::A12::CommitmentSec com_sec;
    argument::A12::ComputeComSparseZ(com_pub, com_sec, prove_input);
    auto com_end = std::chrono::high_resolution_clock::now();
    stats.compute_com_ms = std::chrono::duration<double, std::milli>(com_end - com_start).count();
    std::cout << "Commitment time: " << stats.compute_com_ms << "ms\n";
    
    stats.com_g1_count = com_pub.com_z.size();
    
    // Generate proof (optimized for sparse Z)
    std::cout << "Generating proof (sparse Z)...\n";
    auto prove_start = std::chrono::high_resolution_clock::now();
    argument::A12::Proof proof;
    argument::A12::ProveIfSparseZ(proof, proof_seed, prove_input, com_pub, com_sec);
    auto prove_end = std::chrono::high_resolution_clock::now();
    stats.prove_ms = std::chrono::duration<double, std::milli>(prove_end - prove_start).count();
    std::cout << "Prove time: " << stats.prove_ms << "ms\n";
    
    auto prove_total_end = std::chrono::high_resolution_clock::now();
    stats.prove_total_ms = std::chrono::duration<double, std::milli>(prove_total_end - prove_total_start).count();
    
    stats.proof_fr_size = proof.FrSize();
    stats.proof_g1_size = proof.G1Size();
    
    // Serialize commitment to get size
    yas::mem_ostream com_os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> com_oa(com_os);
    com_oa.serialize(com_pub);
    stats.com_serialized_size = com_os.get_shared_buffer().size;
    
    // Serialize proof to get size
    yas::mem_ostream proof_os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> proof_oa(proof_os);
    proof_oa.serialize(proof);
    stats.proof_serialized_size = proof_os.get_shared_buffer().size;
    
    stats.total_proof_size = stats.com_serialized_size + stats.proof_serialized_size;
    
    // A12 verify
    std::cout << "\nVerifying proof...\n";
    auto verify_total_start = std::chrono::high_resolution_clock::now();
    auto verify_start = std::chrono::high_resolution_clock::now();
    argument::A12::SparseZVerifyInput verify_input(
        sparse_a, sparse_b, sparse_c, com_pub, stats.num_instances, copy_ranges, pc::kGetRefG1);
    bool verify_success = argument::A12::VerifyIfSparseZ(proof, proof_seed, verify_input);
    auto verify_end = std::chrono::high_resolution_clock::now();
    stats.verify_ms = std::chrono::duration<double, std::milli>(verify_end - verify_start).count();
    auto verify_total_end = std::chrono::high_resolution_clock::now();
    stats.verify_total_ms = std::chrono::duration<double, std::milli>(verify_total_end - verify_total_start).count();
    
    std::cout << "Verify time: " << stats.verify_ms << "ms\n";
    std::cout << "Verify result: " << (verify_success ? "SUCCESS" : "FAILED") << "\n";
    
    stats.verify_success = verify_success;
    return verify_success;
}

/**
 * Test the iterated function proof for Pong DQN environment.
 * Generates a trajectory by running DQN policy against AI,
 * then proves the trajectory using A12 protocol.
 * 
 * Parameters are consistent with PongDqnEnvGameTest::PlayOneGameWithProof
 */
inline void IteratedFunctionProof(size_t max_steps) {
    IteratedFunctionProofStats stats;
    auto total_start = std::chrono::high_resolution_clock::now();

    // ========== 1. Load DQN weights ==========
    std::cout << "Loading DQN weights...\n";
    auto conv1_weights = LoadWeights("../data/pong/weights/conv1_weights.csv");
    auto conv2_weights = LoadWeights("../data/pong/weights/conv2_weights.csv");
    auto fc1_weights = LoadWeights("../data/pong/weights/fc1_weights.csv");
    auto fc2_weights = LoadWeights("../data/pong/weights/fc2_weights.csv");
    
    std::cout << "  Conv1 weights: " << conv1_weights.size() << "\n";
    std::cout << "  Conv2 weights: " << conv2_weights.size() << "\n";
    std::cout << "  FC1 weights: " << fc1_weights.size() << "\n";
    std::cout << "  FC2 weights: " << fc2_weights.size() << "\n";

    // ========== 2. Initialize random number generator ==========
    int seed = 42;
    std::mt19937 rng(seed);
    
    // Pre-generate random sequence (for ball reset)
    std::vector<std::pair<int, int>> random_sequence;
    for (int i = 0; i < 10000; ++i) {
        int random_vx = (rng() % 2 == 0) ? 1 : -1;
        int random_dir = (rng() % 2 == 0) ? 1 : -1;
        random_sequence.emplace_back(random_vx, random_dir);
    }
    int random_index = 0;

    // ========== 3. Game constants (consistent with PlayOneGameWithProof) ==========
    constexpr int FRAME_SKIP = 3;
    constexpr int WIN_SCORE = 1;
    constexpr int BALL_SPEED = 2;
    constexpr int PADDLE_WIDTH = 20;
    
    // Initialize game state (consistent with PlayOneGameWithProof)
    std::uniform_int_distribution<int> ball_x_dist(20, 64);
    std::uniform_int_distribution<int> ball_y_dist(30, 54);
    std::uniform_int_distribution<int> paddle_x_dist(0, 64);
    
    std::vector<int64_t> current_state = {
        ball_x_dist(rng), ball_y_dist(rng),
        (rng() % 2 == 0) ? BALL_SPEED : -BALL_SPEED,
        (rng() % 2 == 0) ? BALL_SPEED : -BALL_SPEED,
        paddle_x_dist(rng), paddle_x_dist(rng),
        0, 0, 0
    };
    
    std::cout << "\nInitial state: [" << current_state[0] << ", " << current_state[1] 
              << ", " << current_state[2] << ", " << current_state[3]
              << ", " << current_state[4] << ", " << current_state[5]
              << ", " << current_state[6] << ", " << current_state[7]
              << ", " << current_state[8] << "]\n";

    // ========== 4. Create protoboard and variables ==========
    libsnark::protoboard<Fr> pb;
    
    libsnark::pb_variable_array<Fr> in_state;
    in_state.allocate(pb, 9, "in_state");
    
    libsnark::pb_variable_array<Fr> prev_image;
    prev_image.allocate(pb, 42 * 42, "prev_image");
    
    libsnark::pb_variable<Fr> action;
    action.allocate(pb, "action");
    
    libsnark::pb_variable_array<Fr> random_vxs, random_dirs;
    random_vxs.allocate(pb, FRAME_SKIP, "random_vxs");
    random_dirs.allocate(pb, FRAME_SKIP, "random_dirs");
    
    libsnark::pb_variable_array<Fr> conv1_weight_vars, conv2_weight_vars;
    libsnark::pb_variable_array<Fr> fc1_weight_vars, fc2_weight_vars;
    conv1_weight_vars.allocate(pb, conv1_weights.size(), "conv1_weights");
    conv2_weight_vars.allocate(pb, conv2_weights.size(), "conv2_weights");
    fc1_weight_vars.allocate(pb, fc1_weights.size(), "fc1_weights");
    fc2_weight_vars.allocate(pb, fc2_weights.size(), "fc2_weights");
    
    // Set DQN weights
    for (size_t i = 0; i < conv1_weights.size(); ++i) {
        pb.val(conv1_weight_vars[i]) = Fr(conv1_weights[i]);
    }
    for (size_t i = 0; i < conv2_weights.size(); ++i) {
        pb.val(conv2_weight_vars[i]) = Fr(conv2_weights[i]);
    }
    for (size_t i = 0; i < fc1_weights.size(); ++i) {
        pb.val(fc1_weight_vars[i]) = Fr(fc1_weights[i]);
    }
    for (size_t i = 0; i < fc2_weights.size(); ++i) {
        pb.val(fc2_weight_vars[i]) = Fr(fc2_weights[i]);
    }

    // ========== 5. Create DqnEnvGadget ==========
    std::cout << "\nCreating DqnEnvGadget...\n";
    auto t1 = std::chrono::high_resolution_clock::now();
    circuit::pong::DqnEnvGadget<FRAME_SKIP, 8, 24> dqn_env_gadget(
        pb, in_state, prev_image, action, random_vxs, random_dirs,
        conv1_weight_vars, conv2_weight_vars, fc1_weight_vars, fc2_weight_vars,
        "DqnEnvGadget");
    auto t2 = std::chrono::high_resolution_clock::now();
    
    int64_t num_constraints = pb.num_constraints();
    int64_t num_variables = pb.num_variables();
    
    std::cout << "  Constraints: " << num_constraints << "\n";
    std::cout << "  Variables: " << num_variables << "\n";
    std::cout << "  Build time: " << std::chrono::duration<double, std::milli>(t2 - t1).count() << " ms\n";
    
    stats.num_constraints = num_constraints;
    stats.num_vars = num_variables;

    // ========== 5.1 Separate DQN, Env, and Render constraint counting ==========
    {
      // DQN only protoboard
      libsnark::protoboard<Fr> pb_dqn;
      libsnark::pb_variable_array<Fr> dqn_image;
      dqn_image.allocate(pb_dqn, circuit::pong::PongDqnGadget<8, 24>::img_size(), "dqn_image");
      libsnark::pb_variable_array<Fr> dqn_conv1_w, dqn_conv2_w, dqn_fc1_w, dqn_fc2_w;
      dqn_conv1_w.allocate(pb_dqn, circuit::pong::PongDqnGadget<8, 24>::conv1_weight_size(), "dqn_conv1_w");
      dqn_conv2_w.allocate(pb_dqn, circuit::pong::PongDqnGadget<8, 24>::conv2_weight_size(), "dqn_conv2_w");
      dqn_fc1_w.allocate(pb_dqn, circuit::pong::PongDqnGadget<8, 24>::fc1_weight_size(), "dqn_fc1_w");
      dqn_fc2_w.allocate(pb_dqn, circuit::pong::PongDqnGadget<8, 24>::fc2_weight_size(), "dqn_fc2_w");
      circuit::pong::PongDqnGadget<8, 24> dqn_only(
          pb_dqn, dqn_image, dqn_conv1_w, dqn_conv2_w, dqn_fc1_w, dqn_fc2_w, "DqnOnly");
      size_t dqn_constraints = pb_dqn.num_constraints();
      size_t dqn_variables = pb_dqn.num_variables();

      // Env only protoboard
      libsnark::protoboard<Fr> pb_env;
      libsnark::pb_variable_array<Fr> env_state;
      env_state.allocate(pb_env, 9, "env_state");
      libsnark::pb_variable<Fr> env_action1, env_action2, env_random_vx, env_random_dir;
      env_action1.allocate(pb_env, "env_action1");
      env_action2.allocate(pb_env, "env_action2");
      env_random_vx.allocate(pb_env, "env_random_vx");
      env_random_dir.allocate(pb_env, "env_random_dir");
      libsnark::linear_combination<Fr> env_action1_lc(env_action1);
      circuit::pong::EnvGadget env_only(
          pb_env, env_state, env_action1_lc, env_action2, env_random_vx, env_random_dir, "EnvOnly");
      size_t env_constraints = pb_env.num_constraints();
      size_t env_variables = pb_env.num_variables();

      // Render only protoboard
      libsnark::protoboard<Fr> pb_render;
      libsnark::pb_variable_array<Fr> render_only_state;
      render_only_state.allocate(pb_render, 8, "render_only_state");
      circuit::pong::RenderGadget render_only(pb_render, render_only_state, "RenderOnly");
      size_t render_constraints = pb_render.num_constraints();
      size_t render_variables = pb_render.num_variables();

      // ImagePreprocess only protoboard
      libsnark::protoboard<Fr> pb_preprocess;
      libsnark::pb_variable_array<Fr> preprocess_image;
      preprocess_image.allocate(pb_preprocess, 84 * 84, "preprocess_image");
      circuit::pong::ImagePreprocessGadget preprocess_only(pb_preprocess, preprocess_image, "PreprocessOnly");
      size_t preprocess_constraints = pb_preprocess.num_constraints();
      size_t preprocess_variables = pb_preprocess.num_variables();

      // Print DQN, Env, and Render statistics
      std::cout << "\n========== Circuit Component Statistics ==========\n";
      std::cout << "DQN (Neural Network Inference):\n";
      std::cout << "  Constraints: " << dqn_constraints << "\n";
      std::cout << "  Variables:   " << dqn_variables << "\n";
      std::cout << "Env (State Transition):\n";
      std::cout << "  Constraints: " << env_constraints << "\n";
      std::cout << "  Variables:   " << env_variables << "\n";
      std::cout << "Render (Image Rendering):\n";
      std::cout << "  Constraints: " << render_constraints << "\n";
      std::cout << "  Variables:   " << render_variables << "\n";
      std::cout << "ImagePreprocess (84x84 -> 42x42):\n";
      std::cout << "  Constraints: " << preprocess_constraints << "\n";
      std::cout << "  Variables:   " << preprocess_variables << "\n";
      std::cout << "Total (DQN + Env + Render + Preprocess + packing):\n";
      std::cout << "  Constraints: " << (dqn_constraints + env_constraints + render_constraints + preprocess_constraints) << " (plus packing constraints)\n";
      std::cout << "  Variables:   " << (dqn_variables + env_variables + render_variables + preprocess_variables) << " (plus shared variables)\n";
      std::cout << "==================================================\n\n";
    }

    // ========== 6. Record variable indices (for copy constraints) ==========
    int64_t in_state_start = in_state[0].index;
    int64_t prev_image_start = prev_image[0].index;
    int64_t out_state_start = dqn_env_gadget.out_state()[0].index;
    int64_t cur_image_42_start = dqn_env_gadget.cur_image_42()[0].index;
    
    std::cout << "\nVariable indices:\n";
    std::cout << "  in_state: " << in_state_start << " ~ " << in_state_start + 8 << "\n";
    std::cout << "  prev_image: " << prev_image_start << " ~ " << prev_image_start + 1763 << "\n";
    std::cout << "  out_state: " << out_state_start << " ~ " << out_state_start + 8 << "\n";
    std::cout << "  cur_image_42: " << cur_image_42_start << " ~ " << cur_image_42_start + 1763 << "\n";
    
    // Build copy constraint ranges
    std::vector<argument::CopyRange> copy_ranges = {
        argument::CopyRange(out_state_start, in_state_start, 9),      // State copy
        argument::CopyRange(cur_image_42_start, prev_image_start, 1764) // Image copy
    };

    // ========== 7. Generate initial frame's preprocessed image ==========
    libsnark::protoboard<Fr> render_pb;
    libsnark::pb_variable_array<Fr> render_state;
    render_state.allocate(render_pb, 8, "render_state");
    
    circuit::pong::RenderGadget render_gadget(render_pb, render_state, "render");
    circuit::pong::ImagePreprocessGadget preprocess_gadget(render_pb, render_gadget.image(), "preprocess");
    
    for (int i = 0; i < 8; ++i) {
        render_pb.val(render_state[i]) = Fr(current_state[i]);
    }
    render_gadget.AssignFromExternal();
    preprocess_gadget.generate_r1cs_witness();
    
    auto const& initial_preprocessed = preprocess_gadget.output();
    for (int i = 0; i < 42 * 42; ++i) {
        pb.val(prev_image[i]) = render_pb.val(initial_preprocessed[i]);
    }

    // ========== 8. Generate trajectory ==========
    std::vector<std::vector<Fr>> row_z;
    
    std::cout << "\n=== Starting Game with Proof Generation ===\n";
    std::cout << "Game ends when either player scores " << WIN_SCORE << " point(s).\n\n";
    
#ifdef DEBUG
    // Game record for replay
    using json = nlohmann::json;
    json game_record;
    game_record["seed"] = seed;
    game_record["initial_state"] = json::array();
    for (int i = 0; i < 9; ++i) {
      game_record["initial_state"].push_back(current_state[i]);
    }
    game_record["steps"] = json::array();
#endif

    int step_count = 0;
    auto traj_start = std::chrono::high_resolution_clock::now();
    
    while (step_count < (int)max_steps) {
        // Set current state
        for (int i = 0; i < 9; ++i) {
            pb.val(in_state[i]) = Fr(current_state[i]);
        }
        
        // Compute AI action
        int ai_action = ComputeAiAction(current_state[5], current_state[0], PADDLE_WIDTH, rng);
        pb.val(action) = Fr(ai_action);
        
        // Set random numbers
        for (size_t i = 0; i < FRAME_SKIP; ++i) {
            pb.val(random_vxs[i]) = Fr(random_sequence[random_index + i].first);
            pb.val(random_dirs[i]) = Fr(random_sequence[random_index + i].second);
        }
        
        // Generate witness
        dqn_env_gadget.GenerateWitness();
        
        // Verify R1CS constraints are satisfied (expensive — only in debug)
#ifdef DEBUG_CHECK_R1CS
        assert(pb.is_satisfied());
#endif

        
        // Collect current step's full assignment vector (using helper function)
        row_z.push_back(CollectAssignment(pb, num_variables));
        
        // Get output state
        auto const& out_state = dqn_env_gadget.out_state();
        std::vector<int64_t> next_state(9);
        for (int i = 0; i < 9; ++i) {
            next_state[i] = pb.val(out_state[i]).getInt64();
        }
        
#ifdef DEBUG
        int dqn_action = dqn_env_gadget.get_dqn_action_index();
        
        std::cout << "Step " << step_count
                  << " | DQN: " << dqn_action
                  << " | AI: " << ai_action
                  << " | Score: " << next_state[6] << "-" << next_state[7] << "\n";
        
        // Record step for game replay
        {
          json step_record;
          step_record["step"] = step_count;
          step_record["state"] = json::array();
          for (int i = 0; i < 9; ++i) {
            step_record["state"].push_back(current_state[i]);
          }
          step_record["dqn_action"] = dqn_action;
          step_record["ai_action"] = ai_action;
          step_record["random_vx"] = random_sequence[random_index].first;
          step_record["random_dir"] = random_sequence[random_index].second;
          step_record["next_state"] = json::array();
          for (int i = 0; i < 9; ++i) {
            step_record["next_state"].push_back(next_state[i]);
          }
          game_record["steps"].push_back(step_record);
        }
#endif

        // Update prev_image (next round's prev_image = current round's cur_image_42)
        auto const& cur_image_42 = dqn_env_gadget.cur_image_42();
        for (int i = 0; i < 42 * 42; ++i) {
            pb.val(prev_image[i]) = pb.val(cur_image_42[i]);
        }
        
        // Update state
        current_state = next_state;
        random_index += FRAME_SKIP;
        step_count++;
    }
    
    auto traj_end = std::chrono::high_resolution_clock::now();
    stats.trajectory_gen_ms = std::chrono::duration<double, std::milli>(traj_end - traj_start).count();
    
    stats.num_instances = row_z.size();
    std::cout << "\nTotal steps: " << stats.num_instances << "\n";
    CHECK(stats.num_instances >= 2, "Need at least 2 steps for A12 proof");

#ifdef DEBUG
    // Save game record
    game_record["total_steps"] = stats.num_instances;
    game_record["final_state"] = json::array();
    for (int i = 0; i < 9; ++i) {
      game_record["final_state"].push_back(current_state[i]);
    }

    {
      // Auto-detect output directory
      std::string record_dir = "data/pong/records";
      std::ifstream test_dir(record_dir + "/../weights/conv1_weights.csv");
      if (!test_dir.is_open()) {
        record_dir = "../data/pong/records";
      }
      std::string record_path = record_dir + "/dqn_env_game_record.json";
      std::ofstream record_file(record_path);
      if (record_file.is_open()) {
        record_file << game_record.dump(2);
        record_file.close();
        std::cout << "Game record saved to: " << record_path << "\n";
      } else {
        std::cout << "Warning: Could not save game record to " << record_path << "\n";
      }
    }
#endif

    // ========== 9. Transpose assignment matrix (using helper function) ==========
    std::cout << "\nTransposing assignment matrix...\n";
    auto transpose_start = std::chrono::high_resolution_clock::now();
    FlatMatrix flat_row_z = TransposeAssignmentMatrix(row_z, num_variables);
    auto transpose_end = std::chrono::high_resolution_clock::now();
    stats.matrix_transpose_ms = std::chrono::duration<double, std::milli>(transpose_end - transpose_start).count();
    std::cout << "Transpose time: " << stats.matrix_transpose_ms << "ms\n";

    // ========== 10. Extract sparse R1CS matrices (using helper function) ==========
    std::cout << "\nExtracting sparse R1CS matrices...\n";
    auto extract_start = std::chrono::high_resolution_clock::now();
    SparseMatrix sparse_a, sparse_b, sparse_c;
    ExtractSparseR1CS(pb, sparse_a, sparse_b, sparse_c);
    auto extract_end = std::chrono::high_resolution_clock::now();
    std::cout << "Extract time: " << std::chrono::duration<double, std::milli>(extract_end - extract_start).count() << "ms\n";

    // ========== 11. A12 prove/verify ==========
    bool verify_success = A12ProveAndVerify(stats, sparse_a, sparse_b, sparse_c, flat_row_z, copy_ranges);
    // Add trajectory_gen time to prove_total
    stats.prove_total_ms += stats.trajectory_gen_ms;
    
    auto total_end = std::chrono::high_resolution_clock::now();
    stats.total_ms = std::chrono::duration<double, std::milli>(total_end - total_start).count();
    
    stats.max_steps = max_steps;
    stats.peak_memory_mb = misc::GetPeakMemoryByPid(getpid()) / 1024.0;
    
    CHECK(verify_success, "A12 verify failed");
    
    stats.print();
}

}  // namespace clink::pong
