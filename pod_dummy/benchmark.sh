#!/bin/bash

# Benchmark script for PFMK zero-knowledge proof experiments
# Supports frozenlake, pong, flappybird environments and pod (Pod::TestKey)
# Extracts: trajectory_gen, compute_com, prove, prove_total, verify,
#           peak_memory, total_proof_size, crs_size, crs_gen_time
# For pod: buyer_time, seller_time, proof_size

EXECUTABLE="../linux/bin/zkfrozenlake"

# Check if executable exists
if [ ! -f "$EXECUTABLE" ]; then
    echo "Error: Executable $EXECUTABLE not found"
    echo "Please build the project first"
    exit 1
fi

# Parse arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 <environment> [max_steps...]"
    echo ""
    echo "Environments:"
    echo "  frozenlake   - FrozenLake DQN (supports up to 2000 steps)"
    echo "  pong         - Pong DQN (supports up to 2000 steps)"
    echo "  flappybird   - FlappyBird DQN (supports up to 100 steps)"
    echo "  pod          - Pod::TestKey benchmark (block_len 1-10)"
    echo "  all          - Run all environments with default step configs"
    echo ""
    echo "Examples:"
    echo "  $0 frozenlake 10 20 50 100 200 500 1000 2000"
    echo "  $0 flappybird 10 20 50 100"
    echo "  $0 pod"
    echo "  $0 all"
    exit 1
fi

ENV_NAME=$1
shift

# Default max_steps for each environment
FROZENLAKE_STEPS="10 20 50 100 200 500 1000 2000"
PONG_STEPS="10 20 50 100 200 500 1000 2000"
FLAPPYBIRD_STEPS="10 20 50 100"

# Helper function to strip ANSI color codes
strip_ansi() {
    sed 's/\x1b\[[0-9;]*[mK]//g'
}

# Helper function to extract a metric value from output
extract_metric() {
    local output="$1"
    local pattern="$2"
    echo "$output" | strip_ansi | grep "$pattern" | grep -oE '[0-9]+\.?[0-9]*' | tail -1
}

# Run benchmark for a single environment with given max_steps
run_benchmark() {
    local env=$1
    shift
    local steps_list=("$@")
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_file="benchmark_${env}_${timestamp}.csv"
    
    # Write CSV header
    echo "env,max_steps,trajectory_gen_ms,compute_com_ms,prove_ms,prove_total_ms,verify_ms,peak_memory_mb,total_proof_size_bytes,crs_size_bytes,crs_gen_ms" > "$output_file"
    
    echo ""
    echo "========================================================"
    echo "  Benchmarking: $env"
    echo "  Steps: ${steps_list[*]}"
    echo "  Output: $output_file"
    echo "========================================================"
    
    for max_steps in "${steps_list[@]}"; do
        echo ""
        echo "--- Testing $env with max_steps=$max_steps ---"
        
        # Run the test and capture output
        output=$($EXECUTABLE "$env" "$max_steps" 2>&1)
        
        # Extract metrics (strip ANSI codes first)
        clean_output=$(echo "$output" | strip_ansi)
        
        trajectory_gen=$(echo "$clean_output" | grep "^trajectory_gen:" | grep -oE '[0-9]+\.[0-9]+' | head -1)
        compute_com=$(echo "$clean_output" | grep "^compute_com:" | grep -oE '[0-9]+\.[0-9]+' | head -1)
        prove=$(echo "$clean_output" | grep "^prove:" | grep -oE '[0-9]+\.[0-9]+' | head -1)
        prove_total=$(echo "$clean_output" | grep "^prove_total:" | grep -oE '[0-9]+\.[0-9]+' | head -1)
        verify=$(echo "$clean_output" | grep "^verify:" | grep -oE '[0-9]+\.[0-9]+' | head -1)
        peak_memory=$(echo "$clean_output" | grep "^peak_memory:" | grep -oE '[0-9]+\.[0-9]+' | head -1)
        total_proof_size=$(echo "$clean_output" | grep "^total_proof_size:" | grep -oE '[0-9]+' | head -1)
        crs_size=$(echo "$clean_output" | grep "^crs_size:" | grep -oE '[0-9]+' | head -1)
        crs_gen=$(echo "$clean_output" | grep "void pc::Base::Create tick:" | grep -oE '[0-9]+' | head -1)
        
        # Validate extraction
        if [ -z "$trajectory_gen" ] || [ -z "$prove_total" ] || [ -z "$verify" ]; then
            echo "  WARNING: Failed to extract some metrics for max_steps=$max_steps"
            echo "  Raw output saved to benchmark_${env}_${max_steps}_raw.log"
            echo "$output" > "benchmark_${env}_${max_steps}_raw.log"
            continue
        fi
        
        # Print results
        echo "  trajectory_gen:    ${trajectory_gen} ms"
        echo "  compute_com:       ${compute_com} ms"
        echo "  prove:             ${prove} ms"
        echo "  prove_total:       ${prove_total} ms"
        echo "  verify:            ${verify} ms"
        echo "  peak_memory:       ${peak_memory} MB"
        echo "  total_proof_size:  ${total_proof_size} bytes"
        echo "  crs_size:          ${crs_size} bytes"
        echo "  crs_gen_time:      ${crs_gen} ms"
        
        # Append to CSV
        echo "${env},${max_steps},${trajectory_gen},${compute_com},${prove},${prove_total},${verify},${peak_memory},${total_proof_size},${crs_size},${crs_gen}" >> "$output_file"
    done
    
    echo ""
    echo "========================================================"
    echo "  Benchmark complete for: $env"
    echo "  Results saved to: $output_file"
    echo "========================================================"
    echo ""
    echo "Summary:"
    column -t -s',' "$output_file"
    echo ""
}

# Run benchmark for pod (Pod::TestKey)
run_pod_benchmark() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_file="benchmark_pod_${timestamp}.csv"
    
    # Write CSV header
    echo "block_len,buyer_time_ms,seller_time_ms,proof_size_bytes" > "$output_file"
    
    echo ""
    echo "========================================================"
    echo "  Benchmarking: pod (Pod::TestKey)"
    echo "  Block lengths: 1-10"
    echo "  Output: $output_file"
    echo "========================================================"
    
    # Test block_len from 1 to 10
    for block_len in {1..10}; do
        echo ""
        echo "--- Testing pod with block_len=$block_len ---"
        
        # Run the test and capture output
        output=$($EXECUTABLE pod $block_len 2>&1)
        
        # Extract metrics (remove ANSI color codes first)
        clean_output=$(echo "$output" | strip_ansi)
        
        seller_time=$(echo "$clean_output" | grep "seller_time:" | grep -oE '[0-9]+\.?[0-9]*' | head -1)
        buyer_time=$(echo "$clean_output" | grep "buyer_time:" | grep -oE '[0-9]+\.?[0-9]*' | head -1)
        proof_size=$(echo "$clean_output" | grep "Total proof size (bytes):" | grep -oE '[0-9]+')
        
        # Check if we got all metrics
        if [ -z "$buyer_time" ] || [ -z "$seller_time" ] || [ -z "$proof_size" ]; then
            echo "  WARNING: Failed to extract some metrics for block_len=$block_len"
            echo "  Raw output saved to benchmark_pod_${block_len}_raw.log"
            echo "$output" > "benchmark_pod_${block_len}_raw.log"
            continue
        fi
        
        # Print results
        echo "  seller_time:   ${seller_time} ms"
        echo "  buyer_time:    ${buyer_time} ms"
        echo "  proof_size:    ${proof_size} bytes"
        
        # Append to CSV
        echo "${block_len},${buyer_time},${seller_time},${proof_size}" >> "$output_file"
    done
    
    echo ""
    echo "========================================================"
    echo "  Benchmark complete for: pod"
    echo "  Results saved to: $output_file"
    echo "========================================================"
    echo ""
    echo "Summary:"
    column -t -s',' "$output_file"
    echo ""
}

# Main logic
case "$ENV_NAME" in
    frozenlake)
        if [ $# -gt 0 ]; then
            run_benchmark frozenlake "$@"
        else
            run_benchmark frozenlake $FROZENLAKE_STEPS
        fi
        ;;
    pong)
        if [ $# -gt 0 ]; then
            run_benchmark pong "$@"
        else
            run_benchmark pong $PONG_STEPS
        fi
        ;;
    flappybird)
        if [ $# -gt 0 ]; then
            run_benchmark flappybird "$@"
        else
            run_benchmark flappybird $FLAPPYBIRD_STEPS
        fi
        ;;
    pod)
        run_pod_benchmark
        ;;
    all)
        echo "Running all environments with default configurations..."
        run_benchmark frozenlake $FROZENLAKE_STEPS
        run_benchmark pong $PONG_STEPS
        run_benchmark flappybird $FLAPPYBIRD_STEPS
        run_pod_benchmark
        echo ""
        echo "All benchmarks complete!"
        ;;
    *)
        echo "Unknown environment: $ENV_NAME"
        echo "Valid environments: frozenlake, pong, flappybird, pod, all"
        exit 1
        ;;
esac
