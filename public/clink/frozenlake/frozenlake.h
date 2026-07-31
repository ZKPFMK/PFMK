#pragma once

#include <cassert>
#include <chrono>
#include <iomanip>
#include <sstream>

#include "../details.h"
#include "argument/a12.h"
#include "circuit/func.h"
#include "circuit/frozenlake/dqn_env_gadget.h"

extern std::vector<std::vector<Fr>> max4_a;
extern std::vector<std::vector<Fr>> max4_b;
extern std::vector<std::vector<Fr>> max4_c;

extern std::vector<std::vector<Fr>> relu_a;
extern std::vector<std::vector<Fr>> relu_b;
extern std::vector<std::vector<Fr>> relu_c;

namespace clink::frozenlake{
std::vector<std::vector<Fr>> env_a, env_b, env_c;

struct FrozenLake {
  struct Para {
    std::vector<std::vector<Fr>> dense1;
    std::vector<std::vector<Fr>> dense2;
    std::vector<std::vector<Fr>> dense3;
  };

  static void LoadPara(Para& para);
};

void FrozenLake::LoadPara(Para& para){
    Tick tick(__FN__);

    namespace fp = circuit::fp;

    size_t const D = 8, N = 24;

    std::array<std::array<double, 64>, 12> dense1 = {
        0.017140,0.017511,-0.159752,0.014187,-0.104055,0.085069,-0.227316,0.050029,0.006745,0.012260,0.021981,-0.122304,-0.132470,-0.233799,-0.282149,0.018927,-0.253411,-0.022004,-0.217931,-0.051855,-0.097648,0.018392,0.005613,0.019657,0.154590,-0.108066,0.144714,-0.082161,0.222306,0.238445,0.106311,0.269389,0.010694,-0.282816,0.022732,0.254095,-0.150374,-0.182076,-0.262797,-0.069738,0.209148,-0.130335,0.082254,-0.174938,0.126462,0.473419,0.195797,-0.217023,0.351166,-0.136546,0.070798,0.127399,0.177893,0.123603,-0.230594,-0.089164,-0.216217,-0.188952,0.100549,0.294698,0.282794,-0.291442,0.016619,0.208278,
        0.085920,0.122403,-0.097177,-0.096152,0.021530,0.134997,-0.086886,0.084551,-0.098150,-0.096758,-0.097966,-0.088438,-0.086816,0.182022,0.254663,-0.191197,-0.133743,-0.176912,-0.240516,-0.280273,-0.295601,-0.091839,-0.231000,-0.004423,-0.142093,-0.094603,-0.171901,-0.098947,-0.089441,-0.000343,-0.096928,-0.087646,-0.266464,0.009574,-0.139464,0.140428,-0.271223,-0.301251,-0.091655,0.373287,-0.079392,-0.014006,0.019606,-0.027624,-0.077510,-0.184960,-0.004231,-0.087806,-0.220140,0.221925,-0.089566,-0.086559,-0.205352,0.037139,0.168348,-0.086264,-0.071089,-0.251805,-0.167911,0.280882,0.288600,-0.211805,0.567376,0.273872,
        -0.181585,-0.047186,-0.024370,0.132303,-0.088975,-0.039862,-0.294647,0.057223,0.131843,-0.204918,-0.198342,0.034676,-0.034654,-0.234889,0.103295,-0.202449,0.130224,0.241484,-0.063951,-0.099234,-0.225443,0.014268,-0.217912,-0.241912,-0.275392,0.103737,0.150468,-0.299481,-0.282860,-0.061255,0.180162,-0.071389,-0.135442,0.149186,-0.004190,-0.137401,-0.170731,-0.226290,0.051913,-0.078077,-0.110277,-0.161090,0.173094,-0.131259,0.050920,0.001133,0.280963,-0.197236,-0.153960,0.192199,-0.067535,-0.228034,0.047882,-0.040580,-0.154143,-0.216490,-0.034480,0.191837,-0.111118,0.159671,0.290096,-0.113466,-0.053996,-0.202102,
        -0.247902,-0.235806,-0.138556,-0.090505,-0.126636,0.036662,0.065908,0.074387,-0.168440,-0.129353,-0.174387,-0.057005,-0.241654,0.034047,0.053614,-0.132445,-0.396159,-0.316324,-0.271463,0.128413,0.057726,-0.200635,0.084945,-0.188944,-0.319173,-0.429890,-0.434385,-0.541039,-0.498103,-0.261132,0.388109,-0.118012,-0.110352,-0.062744,-0.356623,0.250319,-0.124251,-0.526735,-0.529881,0.423706,-0.408517,0.023820,-0.056376,-0.067254,-0.395878,-0.345988,0.160294,0.663577,-0.490847,-0.009641,-0.154927,-0.475371,-0.148581,-0.234174,0.085586,0.815583,-0.301484,-0.427327,-0.388253,0.287277,-0.208484,-0.007501,0.027371,-0.091895,
        0.061173,-0.235150,0.151050,0.066226,0.210479,0.401224,0.261962,0.012210,-0.041738,0.065653,0.146179,-0.054230,0.065738,0.150875,0.058277,0.084319,0.048238,0.101293,-0.072944,-0.085562,-0.199227,0.264443,-0.218297,-0.010160,0.064656,0.031074,-0.199196,-0.227619,-0.037485,-0.000266,-0.039753,0.049114,-0.079159,0.151401,-0.293825,0.198634,0.180154,0.113082,-0.059656,-0.068639,-0.213148,-0.252687,-0.102995,0.188534,0.088627,-0.268237,-0.261860,0.255557,0.083443,0.094787,0.125921,-0.178915,0.156780,0.148258,0.002752,0.028336,0.150831,0.008974,-0.233511,-0.233571,0.280594,-0.126521,0.154001,0.148642,
        -0.216069,-0.144051,-0.200397,-0.140492,-0.270102,0.105682,-0.149697,0.061195,-0.161713,-0.146188,0.521751,-0.145375,-0.146582,0.040881,0.027542,-0.270548,-0.191906,-0.219168,-0.237651,-0.075946,-0.150991,0.816229,-0.204615,-0.135880,-0.086072,-0.072533,-0.079699,-0.178056,-0.145114,-0.064769,-0.140877,0.037508,0.221890,0.450342,0.074667,0.029550,0.179246,0.126073,0.575030,0.117095,-0.162458,0.167462,-0.094948,-0.184308,-0.114583,-0.256995,0.258459,-0.255728,-0.203984,0.240717,0.094094,-0.179106,0.168933,0.208944,-0.273296,-0.095496,-0.093628,0.103052,-0.112760,-0.289750,-0.247409,-0.102200,-0.098261,-0.205349,
        0.105691,0.126431,0.181346,-0.142208,-0.153585,-0.182253,0.256375,0.182450,-0.001228,-0.224093,-0.093404,0.003103,-0.031930,0.240136,0.183174,0.191794,-0.040488,0.148159,0.275984,-0.048317,0.120620,-0.217467,-0.258473,0.120813,0.193349,0.069340,0.062514,-0.157276,-0.219831,-0.185096,-0.281066,-0.113069,-0.155324,-0.089082,0.004884,0.016493,0.195672,-0.006548,-0.120521,-0.208642,-0.111233,0.288611,-0.067456,0.009091,-0.174356,0.041491,-0.124739,-0.242541,-0.298098,-0.102084,-0.191523,0.179770,0.100569,-0.167751,0.055571,-0.191823,-0.228566,-0.020139,0.180477,-0.156314,0.211304,-0.021976,-0.254474,0.302695,
        -0.125428,-0.148817,-0.041794,-0.033233,-0.097808,-0.262035,-0.031775,-0.042359,-0.031383,-0.287065,-0.151579,-0.259201,-0.306150,-0.039736,-0.037308,-0.043928,-0.051449,0.104397,0.394906,0.262989,0.083711,-0.034389,-0.029881,-0.041293,0.061749,-0.072608,-0.291593,-0.248754,-0.119248,-0.098846,-0.084687,-0.031699,0.419458,0.506574,-0.041365,-0.274349,-0.186111,-0.249360,-0.036725,-0.060649,-0.304086,-0.091046,-0.192137,0.353363,-0.165713,0.003252,-0.245326,-0.054668,-0.291839,-0.209964,-0.289991,-0.230561,-0.078823,-0.185322,-0.195628,0.025099,0.028412,-0.089595,-0.115591,0.169893,0.233172,-0.179094,0.085474,-0.194788,
        -0.058502,-0.090097,-0.043483,-0.111087,0.121491,-0.206856,-0.277632,0.185775,-0.047686,-0.065059,-0.058043,-0.100311,0.432584,-0.008634,-0.058329,0.532809,-0.058813,-0.105133,-0.056219,0.034615,-0.262019,-0.149613,-0.229601,0.594622,-0.174453,-0.219102,-0.047685,-0.070035,-0.058057,0.201984,-0.010585,0.665826,-0.011595,-0.059649,-0.061248,0.228310,-0.046857,0.050495,0.065156,-0.175511,-0.274456,-0.173982,0.033190,-0.254412,-0.228791,0.002675,-0.089257,-0.099723,-0.189379,-0.056261,-0.141169,-0.058530,0.089151,-0.103848,-0.237888,-0.065710,-0.093476,-0.127742,-0.269114,0.243095,-0.185975,-0.268431,-0.165160,0.296531,
        -0.004201,0.215387,0.106697,0.203569,-0.088157,-0.062820,0.076937,-0.121795,-0.209082,-0.067669,-0.299362,-0.006280,0.163767,0.101909,0.070641,-0.241350,-0.231808,-0.269531,-0.071886,0.034598,-0.280197,0.136727,-0.020070,0.232908,-0.246653,-0.090054,-0.028620,-0.248065,0.131902,0.106958,-0.013869,-0.010576,0.205385,0.053455,-0.293371,-0.231432,-0.302599,0.270913,-0.043115,0.059181,-0.026621,0.121028,-0.137757,-0.090582,0.186735,0.195604,-0.276609,0.207147,0.014451,0.173122,0.129016,0.128159,0.095709,0.036489,0.085518,-0.150520,0.209649,0.089120,-0.276778,-0.285894,0.006689,0.050938,-0.043178,0.060152,
        -0.141507,-0.169737,0.310628,-0.263010,0.163297,0.053227,-0.093578,-0.258832,0.196137,-0.212632,0.080797,-0.086408,-0.273872,-0.175221,-0.305488,-0.148443,-0.121551,-0.068231,-0.171241,-0.283446,-0.067798,0.040388,0.701792,-0.239536,-0.294108,-0.069849,-0.062243,-0.070172,-0.064379,-0.049993,0.019177,0.241166,0.176544,-0.018003,-0.071414,-0.242993,-0.206070,0.518361,-0.120267,-0.227584,-0.020959,0.053385,0.183920,-0.086218,-0.169563,-0.240153,0.225239,-0.267392,-0.014581,-0.016688,-0.207944,-0.191619,0.131459,-0.034511,-0.195770,-0.098174,0.139546,0.481597,-0.294242,-0.210063,-0.297081,0.237691,0.083275,0.139800,
        -0.087112,0.021781,0.141107,-0.034871,0.033413,-0.129107,0.033930,-0.014262,-0.093889,-0.137888,-0.038862,0.006857,0.161123,-0.084426,0.177253,-0.182593,0.125492,0.152364,0.062812,-0.112599,-0.197961,0.181650,-0.017325,0.064477,0.155838,-0.012633,0.152361,0.094069,-0.097970,-0.105681,0.167370,0.021518,0.018271,-0.230045,0.595909,0.270019,-0.028444,-0.058300,0.169962,0.108314,0.186768,-0.052159,-0.259447,0.412663,0.009214,-0.292511,0.241407,0.153826,-0.161776,-0.171720,0.317959,-0.200812,0.054558,0.040472,0.024493,-0.081022,-0.243880,0.078867,-0.211578,-0.226513,-0.058649,0.150106,0.185492,0.091718
    };

    std::array<double, 12> bias1 = {
        -0.027424, 0.063756, -0.242768, 0.500134, -0.283030, 0.133824, -0.286120, 0.014919, -0.075686, -0.271780, 0.038882, -0.212684
    };

    para.dense1.resize(65, std::vector<Fr>(12));
    for (size_t i = 0; i < dense1.size(); ++i) { //12
        for (size_t j = 0; j < dense1[i].size(); ++j) { //64
            para.dense1[j][i] = fp::DoubleToRational<D, N>(dense1[i][j]);
        }
    };
    for(size_t i = 0; i < dense1.size(); ++i){
        para.dense1[64][i] = fp::DoubleToRational<D, N>(bias1[i]);
    }

    std::array<std::array<double, 12>, 8> dense2 = {
        -0.285675,0.433462,-0.003761,1.330173,0.117273,-0.686185,0.105835,-0.569934,0.481020,-0.055417,0.021545,-0.439629,
        0.000667,-0.448320,-0.097030,-0.913334,0.673997,1.040547,-0.579102,-0.627408,0.727940,-0.687094,-0.504649,0.023224,
        0.401065,0.105954,0.085431,0.270877,0.253432,0.443564,-0.019836,-0.682061,0.397623,-0.385083,-0.725048,0.569048,
        0.474760,-0.418317,0.096260,-0.582603,-0.635407,-0.460931,-0.598247,-0.364361,0.349516,0.556068,0.118121,-0.271124,
        -0.066478,0.776264,0.191050,-0.131797,-0.384535,0.328051,-0.326091,-0.425267,0.612558,0.512372,0.329047,-0.291784,
        0.530919,0.634940,-0.307237,0.530672,0.294586,-0.817589,-0.549717,-0.019264,-0.081361,0.221797,-0.240557,-0.067445,
        0.828110,-0.384499,0.181286,0.472891,-0.258040,0.092105,0.316937,-0.937627,-0.154365,0.493902,-0.641322,0.442862,
        -0.415721,0.537251,0.330144,0.155324,0.190996,-0.200467,-0.702986,-0.334586,-0.413626,-0.186859,0.119080,0.127030,
    };

    std::array<double, 8> bias2 = {
        0.233111, 0.024093, -0.229269, -0.214019, -0.029123, -0.218137, -0.217038, -0.147311
    };

    para.dense2.resize(13, std::vector<Fr>(8));
    for (size_t i = 0; i < dense2.size(); ++i) {
        for (size_t j = 0; j < dense2[i].size(); ++j) {
            para.dense2[j][i] = fp::DoubleToRational<D, N>(dense2[i][j]);
        }
    }
    for(size_t i = 0; i < dense2.size(); ++i){
        para.dense2[12][i] = fp::DoubleToRational<D, N>(bias2[i]);
    }

    std::array<std::array<double, 8>, 4> dense3 = {
        0.296671,0.065205,0.901674,0.491545,0.483183,-1.050923,-1.227999,1.659568,
        0.567688,-0.215269,-0.355977,0.824306,0.941340,-0.515747,0.507854,-0.113410,
        0.750707,1.199792,-0.725605,-0.505755,0.211037,-0.017395,-0.871301,-0.403974,
        0.550835,0.737534,0.040525,0.017675,0.141850,-0.328607,-0.235467,-0.044913
    };

    std::array<double, 4> bias3 = {
        0.172036, -0.010228, -0.094649, 0.034056
    };

    para.dense3.resize(9, std::vector<Fr>(4));
    for (size_t i = 0; i < dense3.size(); ++i) {
        for (size_t j = 0; j < dense3[i].size(); ++j) {
            para.dense3[j][i] = fp::DoubleToRational<D, N>(dense3[i][j]);
        }
    }
    for(size_t i = 0; i < dense3.size(); ++i){
        para.dense3[8][i] = fp::DoubleToRational<D, N>(bias3[i]);
    }
}

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
 * Helper: allocate weight pb_variable_array and assign values from Para matrix.
 * Para format: para[i][j] where i=0..in_dim (last row is bias), j=0..out_dim-1
 * DqnGadget flat format: flat[j * (in_dim+1) + i] = para[i][j]
 */
inline void AllocateAndAssignWeights(
    libsnark::protoboard<Fr>& pb,
    libsnark::pb_variable_array<Fr>& weight_vars,
    std::vector<std::vector<Fr>> const& para_weights,
    const std::string& prefix) {
    size_t in_plus_bias = para_weights.size();
    size_t out_dim = para_weights[0].size();
    size_t total = out_dim * in_plus_bias;
    weight_vars.allocate(pb, total, prefix);
    for (size_t j = 0; j < out_dim; ++j) {
        for (size_t i = 0; i < in_plus_bias; ++i) {
            pb.val(weight_vars[j * in_plus_bias + i]) = para_weights[i][j];
        }
    }
}

/**
 * Helper: create DqnEnvGadget with input state pack and weight variables allocated.
 * Returns the gadget; in_state_pack and weight_vars are output parameters.
 */
inline std::unique_ptr<circuit::frozenlake::DqnEnvGadget> CreateDqnEnvGadget(
    libsnark::protoboard<Fr>& pb,
    FrozenLake::Para const& para,
    libsnark::pb_variable<Fr>& in_state_pack,
    libsnark::pb_variable_array<Fr>& dense1_vars,
    libsnark::pb_variable_array<Fr>& dense2_vars,
    libsnark::pb_variable_array<Fr>& dense3_vars,
    const std::string& prefix) {
    in_state_pack.allocate(pb, prefix + " in_state_pack");
    dense1_vars.allocate(pb, ::circuit::frozenlake::DqnGadget::dense1_weight_size(), prefix + " dense1_w");
    dense2_vars.allocate(pb, ::circuit::frozenlake::DqnGadget::dense2_weight_size(), prefix + " dense2_w");
    dense3_vars.allocate(pb, ::circuit::frozenlake::DqnGadget::dense3_weight_size(), prefix + " dense3_w");
    return std::make_unique<::circuit::frozenlake::DqnEnvGadget>(
        pb, in_state_pack, dense1_vars, dense2_vars, dense3_vars, prefix);
}

/**
 * Helper: assign weight values from Para to pre-allocated weight variables.
 */
inline void AssignWeights(
    libsnark::protoboard<Fr>& pb,
    libsnark::pb_variable_array<Fr> const& weight_vars,
    std::vector<std::vector<Fr>> const& para_weights) {
    size_t in_plus_bias = para_weights.size();
    size_t out_dim = para_weights[0].size();
    for (size_t j = 0; j < out_dim; ++j) {
        for (size_t i = 0; i < in_plus_bias; ++i) {
            pb.val(weight_vars[j * in_plus_bias + i]) = para_weights[i][j];
        }
    }
}

/**
 * Test the full iterated function R1CS proof using A12 protocol.
 * Auto-generates a trajectory by running DQN inference from state 0,
 * using each step's output as the next step's input.
 * Extracts R1CS matrices, constructs the Z matrix, and runs A12 prove/verify.
 */
inline void IteratedFunctionProof(size_t max_steps) {
    IteratedFunctionProofStats stats;
    auto total_start = std::chrono::high_resolution_clock::now();

    FrozenLake::Para para;
    FrozenLake::LoadPara(para);

    // ========== 1. Create protoboard and gadget ==========
    libsnark::protoboard<Fr> pb;
    libsnark::pb_variable<Fr> in_state_pack;
    libsnark::pb_variable_array<Fr> dense1_vars, dense2_vars, dense3_vars;
    auto gadget_ptr = CreateDqnEnvGadget(pb, para, in_state_pack, dense1_vars, dense2_vars, dense3_vars, "DqnEnvGadget");
    auto& gadget = *gadget_ptr;

    int64_t num_constraints = pb.num_constraints();
    int64_t num_variables = pb.num_variables();

    stats.num_constraints = num_constraints;
    stats.num_vars = num_variables + 1;  // +1 for constant 1

    size_t in_idx = gadget.in_pack_index();
    size_t out_idx = gadget.out_pack_index();

    std::cout << "R1CS: " << num_constraints << " constraints, " << num_variables << " variables\n";
    std::cout << "in_idx: " << in_idx << ", out_idx: " << out_idx << "\n";

    // ========== 1.5 Separate DQN and Env constraint counting ==========
    {
      // DQN only protoboard
      libsnark::protoboard<Fr> pb_dqn;
      libsnark::pb_variable_array<Fr> dqn_in_state;
      dqn_in_state.allocate(pb_dqn, 64, "dqn_in_state");
      libsnark::pb_variable_array<Fr> dqn_w1, dqn_w2, dqn_w3;
      dqn_w1.allocate(pb_dqn, circuit::frozenlake::DqnGadget::dense1_weight_size(), "dqn_w1");
      dqn_w2.allocate(pb_dqn, circuit::frozenlake::DqnGadget::dense2_weight_size(), "dqn_w2");
      dqn_w3.allocate(pb_dqn, circuit::frozenlake::DqnGadget::dense3_weight_size(), "dqn_w3");
      circuit::frozenlake::DqnGadget dqn_only(pb_dqn, dqn_in_state, dqn_w1, dqn_w2, dqn_w3, "DqnOnly");
      size_t dqn_constraints = pb_dqn.num_constraints();
      size_t dqn_variables = pb_dqn.num_variables();

      // Env only protoboard
      libsnark::protoboard<Fr> pb_env;
      libsnark::pb_variable_array<Fr> env_in_state;
      env_in_state.allocate(pb_env, 64, "env_in_state");
      libsnark::pb_variable_array<Fr> env_action;
      env_action.allocate(pb_env, 4, "env_action");
      libsnark::pb_variable<Fr> env_in_pack;
      env_in_pack.allocate(pb_env, "env_in_pack");
      circuit::frozenlake::EnvGadget env_only(pb_env, env_in_state, env_action, env_in_pack, "EnvOnly");
      size_t env_constraints = pb_env.num_constraints();
      size_t env_variables = pb_env.num_variables();

      std::cout << "\n========== Circuit Component Statistics ==========\n";
      std::cout << "DQN (Neural Network Inference):\n";
      std::cout << "  Constraints: " << dqn_constraints << "\n";
      std::cout << "  Variables:   " << dqn_variables << "\n";
      std::cout << "Env (State Transition):\n";
      std::cout << "  Constraints: " << env_constraints << "\n";
      std::cout << "  Variables:   " << env_variables << "\n";
      std::cout << "Total (DQN + Env + onehot packing):\n";
      std::cout << "  Constraints: " << (dqn_constraints + env_constraints) << " (plus packing constraints)\n";
      std::cout << "  Variables:   " << (dqn_variables + env_variables) << " (plus shared variables)\n";
      std::cout << "==================================================\n\n";
    }

    // ========== 2. Generate trajectory ==========
    auto traj_start = std::chrono::high_resolution_clock::now();
    std::vector<std::vector<Fr>> row_z;
    int state = 0;

    // Reuse the protoboard created in step 1; assign weights once
    AssignWeights(pb, dense1_vars, para.dense1);
    AssignWeights(pb, dense2_vars, para.dense2);
    AssignWeights(pb, dense3_vars, para.dense3);

    for (size_t step = 0; step < max_steps; ++step) {
        gadget.Assign(state);
        assert(pb.is_satisfied());

        // Collect current step's full assignment vector
        auto const& full_assignment = pb.full_variable_assignment();
        std::vector<Fr> assignment(num_variables + 1);
        assignment[0] = FrOne();
        for (int64_t i = 0; i < num_variables; ++i) {
            assignment[i + 1] = full_assignment[i];
        }
        row_z.push_back(assignment);

#ifdef DEBUG
        std::cout << "Step " << step << ": " << pb.val(gadget.in_pack()).getInt64()
                  << " -> " << pb.val(gadget.out_pack()).getInt64() << "\n";
#endif
        state = (int)pb.val(gadget.out_pack()).getInt64();
    }
    auto traj_end = std::chrono::high_resolution_clock::now();
    stats.trajectory_gen_ms = std::chrono::duration<double, std::milli>(traj_end - traj_start).count();

    stats.num_instances = row_z.size();
    std::cout << "Generated " << stats.num_instances << " valid steps.\n";
    CHECK(stats.num_instances >= 2, "Need at least 2 steps for A12 proof");

    // ========== 3. Transpose assignment matrix ==========
    std::cout << "\nTransposing assignment matrix...\n";
    auto transpose_start = std::chrono::high_resolution_clock::now();
    FlatMatrix flat_row_z(num_variables + 1, stats.num_instances);
    // Optimization: Use blocked transpose for better cache locality
    constexpr int64_t BLOCK_SIZE = 64;
    int64_t total_rows = num_variables + 1;
    int64_t n_inst = (int64_t)stats.num_instances;
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
    { std::vector<std::vector<Fr>>().swap(row_z); }
    auto transpose_end = std::chrono::high_resolution_clock::now();
    stats.matrix_transpose_ms = std::chrono::duration<double, std::milli>(transpose_end - transpose_start).count();
    std::cout << "Transpose time: " << stats.matrix_transpose_ms << "ms\n";

    // ========== 4. Extract sparse R1CS matrices ==========
    std::cout << "\nExtracting sparse R1CS matrices...\n";
    auto extract_start = std::chrono::high_resolution_clock::now();
    SparseMatrix sparse_a, sparse_b, sparse_c;
    circuit::PreprocessSparse(pb, sparse_a, sparse_b, sparse_c);
    auto extract_end = std::chrono::high_resolution_clock::now();
    std::cout << "Extract time: " << std::chrono::duration<double, std::milli>(extract_end - extract_start).count() << "ms\n";

    // ========== 5. Build copy constraint ranges ==========
    std::vector<argument::CopyRange> copy_ranges = {
        argument::CopyRange(out_idx, in_idx, 1)  // State copy: out[i] -> in[i+1]
    };

#ifdef DEBUG
    // ========== 5.5 DEBUG: Verify R1CS and copy constraints before proving ==========
    {
      std::cout << "\n=== DEBUG: Checking R1CS satisfaction and copy constraints ===\n";
      int64_t n_vars_val = num_variables + 1;
      int64_t m_val = sparse_a.rows();
      int64_t n_inst_val = (int64_t)stats.num_instances;
      bool all_ok = true;

      // Check R1CS: (A * z_j) o (B * z_j) = C * z_j for each instance j
      for (int64_t j = 0; j < n_inst_val; ++j) {
        std::vector<Fr> col_j = flat_row_z.col(j);

        // Compute A*z_j, B*z_j, C*z_j using sparse matrices
        std::vector<Fr> az(m_val, FrZero());
        std::vector<Fr> bz(m_val, FrZero());
        std::vector<Fr> cz(m_val, FrZero());
        for (int64_t i = 0; i < m_val; ++i) {
          for (int64_t k = sparse_a.row_ptr_[i]; k < sparse_a.row_ptr_[i + 1]; ++k)
            az[i] += sparse_a.values_[k] * col_j[sparse_a.col_idx_[k]];
          for (int64_t k = sparse_b.row_ptr_[i]; k < sparse_b.row_ptr_[i + 1]; ++k)
            bz[i] += sparse_b.values_[k] * col_j[sparse_b.col_idx_[k]];
          for (int64_t k = sparse_c.row_ptr_[i]; k < sparse_c.row_ptr_[i + 1]; ++k)
            cz[i] += sparse_c.values_[k] * col_j[sparse_c.col_idx_[k]];
        }

        for (int64_t i = 0; i < m_val; ++i) {
          if (az[i] * bz[i] != cz[i]) {
            std::cout << "  R1CS FAILED: instance " << j << ", constraint " << i
                      << " (az*bz != cz)\n";
            all_ok = false;
            break;  // report first failure per instance
          }
        }
      }
      if (all_ok) std::cout << "  R1CS check: PASSED for all " << n_inst_val << " instances\n";

      // Check copy constraints: z_j[out_idx] == z_{j+1}[in_idx]
      bool copy_ok = true;
      for (int64_t j = 0; j < n_inst_val - 1; ++j) {
        for (auto const& cr : copy_ranges) {
          for (int64_t k = 0; k < cr.l; ++k) {
            Fr src = flat_row_z(cr.l_a + k, j);
            Fr dst = flat_row_z(cr.l_b + k, j + 1);
            if (src != dst) {
              std::cout << "  COPY CONSTRAINT FAILED: z_" << j << "[" << (cr.l_a + k)
                        << "] != z_" << (j + 1) << "[" << (cr.l_b + k) << "]\n";
              std::cout << "    src = " << src.getStr() << "\n    dst = " << dst.getStr() << "\n";
              copy_ok = false;
            }
          }
        }
      }
      if (copy_ok) std::cout << "  Copy constraint check: PASSED for all " << (n_inst_val - 1) << " pairs\n";

      std::cout << "=== DEBUG check complete ===\n\n";
      CHECK(all_ok && copy_ok, "DEBUG_CHECK: R1CS or copy constraint check failed");
    }
#endif

    // ========== 6. A12 prove/verify ==========
    std::cout << "\n=== Generating A12 Iterative Proof ===\n";
    
    h256_t proof_seed = misc::RandH256();
    argument::A12::SparseProveInput prove_input(
        sparse_a, sparse_b, sparse_c, flat_row_z, copy_ranges, pc::kGetRefG1);
    
    auto prove_total_start = std::chrono::high_resolution_clock::now();
    
    std::cout << "Computing commitments...\n";
    auto com_start = std::chrono::high_resolution_clock::now();
    argument::A12::CommitmentPub com_pub;
    argument::A12::CommitmentSec com_sec;
    argument::A12::ComputeCom(com_pub, com_sec, prove_input);
    auto com_end = std::chrono::high_resolution_clock::now();
    stats.compute_com_ms = std::chrono::duration<double, std::milli>(com_end - com_start).count();
    std::cout << "Commitment time: " << stats.compute_com_ms << "ms\n";
    
    stats.com_g1_count = com_pub.com_z.size();
    
    std::cout << "Generating proof...\n";
    auto prove_start = std::chrono::high_resolution_clock::now();
    argument::A12::Proof proof;
    argument::A12::ProveIf(proof, proof_seed, prove_input, com_pub, com_sec);
    auto prove_end = std::chrono::high_resolution_clock::now();
    stats.prove_ms = std::chrono::duration<double, std::milli>(prove_end - prove_start).count();
    std::cout << "Prove time: " << stats.prove_ms << "ms\n";
    
    auto prove_total_end = std::chrono::high_resolution_clock::now();
    stats.prove_total_ms = stats.trajectory_gen_ms +
        std::chrono::duration<double, std::milli>(prove_total_end - prove_total_start).count();
    
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
    stats.verify_success = argument::A12::VerifyIf(proof, proof_seed, verify_input);
    auto verify_end = std::chrono::high_resolution_clock::now();
    stats.verify_ms = std::chrono::duration<double, std::milli>(verify_end - verify_start).count();
    auto verify_total_end = std::chrono::high_resolution_clock::now();
    stats.verify_total_ms = std::chrono::duration<double, std::milli>(verify_total_end - verify_total_start).count();
    
    std::cout << "Verify time: " << stats.verify_ms << "ms\n";
    std::cout << "Verify result: " << (stats.verify_success ? "SUCCESS" : "FAILED") << "\n";
    
    auto total_end = std::chrono::high_resolution_clock::now();
    stats.total_ms = std::chrono::duration<double, std::milli>(total_end - total_start).count();
    
    stats.max_steps = max_steps;
    stats.peak_memory_mb = misc::GetPeakMemoryByPid(getpid()) / 1024.0;
    
    CHECK(stats.verify_success, "A12 verify failed");
    
    stats.print();
}

/**
 * Test the full iterated function R1CS proof with detailed performance output.
 * Returns the performance statistics for benchmarking.
 */
inline IteratedFunctionProofStats IteratedFunctionProofWithStats(size_t max_steps, bool verbose = true) {
    IteratedFunctionProofStats stats;
    auto total_start = std::chrono::high_resolution_clock::now();

    FrozenLake::Para para;
    FrozenLake::LoadPara(para);

    // ========== 1. Create protoboard and gadget ==========
    libsnark::protoboard<Fr> pb;
    libsnark::pb_variable<Fr> in_state_pack;
    libsnark::pb_variable_array<Fr> dense1_vars, dense2_vars, dense3_vars;
    auto gadget_ptr = CreateDqnEnvGadget(pb, para, in_state_pack, dense1_vars, dense2_vars, dense3_vars, "DqnEnvGadget");
    auto& gadget = *gadget_ptr;

    int64_t num_constraints = pb.num_constraints();
    int64_t num_variables = pb.num_variables();

    stats.num_constraints = num_constraints;
    stats.num_vars = num_variables + 1;  // +1 for constant 1

    size_t in_idx = gadget.in_pack_index();
    size_t out_idx = gadget.out_pack_index();

    if (verbose) {
        std::cout << "R1CS: " << num_constraints << " constraints, " << num_variables << " variables\n";
        std::cout << "in_idx: " << in_idx << ", out_idx: " << out_idx << "\n";
    }

    // ========== 2. Generate trajectory ==========
    auto traj_start = std::chrono::high_resolution_clock::now();
    std::vector<std::vector<Fr>> row_z;
    int state = 0;

    // Reuse the protoboard created in step 1; assign weights once
    AssignWeights(pb, dense1_vars, para.dense1);
    AssignWeights(pb, dense2_vars, para.dense2);
    AssignWeights(pb, dense3_vars, para.dense3);

    for (size_t step = 0; step < max_steps; ++step) {
        gadget.Assign(state);
        if (!pb.is_satisfied()) break;

        // Collect current step's full assignment vector
        auto const& full_assignment = pb.full_variable_assignment();
        std::vector<Fr> assignment(num_variables + 1);
        assignment[0] = FrOne();
        for (int64_t i = 0; i < num_variables; ++i) {
            assignment[i + 1] = full_assignment[i];
        }
        row_z.push_back(assignment);

        if (verbose) {
            std::cout << "Step " << step << ": " << pb.val(gadget.in_pack()).getInt64()
                      << " -> " << pb.val(gadget.out_pack()).getInt64() << "\n";
        }
        state = (int)pb.val(gadget.out_pack()).getInt64();
    }
    auto traj_end = std::chrono::high_resolution_clock::now();
    stats.trajectory_gen_ms = std::chrono::duration<double, std::milli>(traj_end - traj_start).count();

    stats.num_instances = row_z.size();
    if (verbose) {
        std::cout << "Generated " << stats.num_instances << " valid steps.\n";
    }
    
    if (stats.num_instances < 2) {
        std::cerr << "Error: Need at least 2 steps for A12 proof\n";
        return stats;
    }

    // ========== 3. Transpose assignment matrix ==========
    if (verbose) std::cout << "\nTransposing assignment matrix...\n";
    auto transpose_start = std::chrono::high_resolution_clock::now();
    FlatMatrix flat_row_z(num_variables + 1, stats.num_instances);
    // Optimization: Use blocked transpose for better cache locality
    constexpr int64_t BLOCK_SIZE = 64;
    int64_t total_rows = num_variables + 1;
    int64_t n_inst = (int64_t)stats.num_instances;
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
    { std::vector<std::vector<Fr>>().swap(row_z); }
    auto transpose_end = std::chrono::high_resolution_clock::now();
    stats.matrix_transpose_ms = std::chrono::duration<double, std::milli>(transpose_end - transpose_start).count();
    if (verbose) std::cout << "Transpose time: " << stats.matrix_transpose_ms << "ms\n";

    // ========== 4. Extract sparse R1CS matrices ==========
    if (verbose) std::cout << "\nExtracting sparse R1CS matrices...\n";
    auto extract_start = std::chrono::high_resolution_clock::now();
    SparseMatrix sparse_a, sparse_b, sparse_c;
    circuit::PreprocessSparse(pb, sparse_a, sparse_b, sparse_c);
    auto extract_end = std::chrono::high_resolution_clock::now();
    if (verbose) std::cout << "Extract time: " << std::chrono::duration<double, std::milli>(extract_end - extract_start).count() << "ms\n";

    // ========== 5. Build copy constraint ranges ==========
    std::vector<argument::CopyRange> copy_ranges = {
        argument::CopyRange(out_idx, in_idx, 1)  // State copy: out[i] -> in[i+1]
    };

    // ========== 6. A12 prove/verify ==========
    if (verbose) std::cout << "\n=== Generating A12 Iterative Proof ===\n";
    
    h256_t proof_seed = misc::RandH256();
    argument::A12::SparseProveInput prove_input(
        sparse_a, sparse_b, sparse_c, flat_row_z, copy_ranges, pc::kGetRefG1);
    
    auto prove_total_start = std::chrono::high_resolution_clock::now();
    
    if (verbose) std::cout << "Computing commitments...\n";
    auto com_start = std::chrono::high_resolution_clock::now();
    argument::A12::CommitmentPub com_pub;
    argument::A12::CommitmentSec com_sec;
    argument::A12::ComputeCom(com_pub, com_sec, prove_input);
    auto com_end = std::chrono::high_resolution_clock::now();
    stats.compute_com_ms = std::chrono::duration<double, std::milli>(com_end - com_start).count();
    if (verbose) std::cout << "Commitment time: " << stats.compute_com_ms << "ms\n";
    
    stats.com_g1_count = com_pub.com_z.size();
    
    if (verbose) std::cout << "Generating proof...\n";
    auto prove_start = std::chrono::high_resolution_clock::now();
    argument::A12::Proof proof;
    argument::A12::ProveIf(proof, proof_seed, prove_input, com_pub, com_sec);
    auto prove_end = std::chrono::high_resolution_clock::now();
    stats.prove_ms = std::chrono::duration<double, std::milli>(prove_end - prove_start).count();
    if (verbose) std::cout << "Prove time: " << stats.prove_ms << "ms\n";
    
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
    if (verbose) std::cout << "\nVerifying proof...\n";
    auto verify_total_start = std::chrono::high_resolution_clock::now();
    auto verify_start = std::chrono::high_resolution_clock::now();
    argument::A12::SparseVerifyInput verify_input(
        sparse_a, sparse_b, sparse_c, com_pub, stats.num_instances, copy_ranges, pc::kGetRefG1);
    stats.verify_success = argument::A12::VerifyIf(proof, proof_seed, verify_input);
    auto verify_end = std::chrono::high_resolution_clock::now();
    stats.verify_ms = std::chrono::duration<double, std::milli>(verify_end - verify_start).count();
    auto verify_total_end = std::chrono::high_resolution_clock::now();
    stats.verify_total_ms = std::chrono::duration<double, std::milli>(verify_total_end - verify_total_start).count();
    
    if (verbose) {
        std::cout << "Verify time: " << stats.verify_ms << "ms\n";
        std::cout << "Verify result: " << (stats.verify_success ? "SUCCESS" : "FAILED") << "\n";
    }
    
    auto total_end = std::chrono::high_resolution_clock::now();
    stats.total_ms = std::chrono::duration<double, std::milli>(total_end - total_start).count();
    
    stats.max_steps = max_steps;
    stats.peak_memory_mb = misc::GetPeakMemoryByPid(getpid()) / 1024.0;

    return stats;
}

}  // namespace clink::frozenlake
