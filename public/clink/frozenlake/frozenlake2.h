// #pragma once

// #include "../details.h"
// #include "../parallel_r1cs.h"

// #include "circuit/fixed_point/fixed_point.h"

// namespace clink::frozenlake{

// using Policy = groth09::SuccinctPolicy;
// using R1cs = typename clink::ParallelR1cs<Policy>;
// using Sec51 = typename Policy::Sec51;
// using HyraxA = typename Policy::HyraxA;

// struct FrozenLake{
//     struct Para{
//         std::array<std::array<Fr, 64 + 1>, 12> dense1; //each line represent a neuron, weight + bias
//         std::array<std::array<Fr, 12 + 1>, 8> dense2;
//         std::array<std::array<Fr, 8 + 1>, 4> dense3;
//     };

//     struct ParaCommitmentPub { // commitment
//         // G1 all;
//         std::array<G1, 12> dense1;
//         std::array<G1, 8> dense2;
//         std::array<G1, 4> dense3;
//     };

//     struct ParaCommitmentSec { // the random used to compute commitment
//         // Fr all;
//         std::array<Fr, 12> dense1;
//         std::array<Fr, 8> dense2;
//         std::array<Fr, 4> dense3;
//     };

//     /**
//      * ai * b = ci                          =>
//      * \sum y^i * ai  * b = \sum y^i * ci   =>
//      * HyraxA: d = \sum y^i * ci, Sec51: (\sum y^i * ai)  * b = d, 
//      * 
//      */
//     struct DenseProof{
//         G1 com; // 内积的承诺
//         G1 com_z; // 内积乘以y^i

//         Sec51::Proof proof_51;
//         HyraxA::Proof proof_hy;

//         template <typename Ar>
//         void serialize(Ar& ar) const {
//         ar& YAS_OBJECT_NVP("d.p", ("cd", com), ("cz", com_z), ("51", proof_51),
//                             ("hy", proof_hy));
//         }
//         template <typename Ar>
//         void serialize(Ar& ar) {
//         ar& YAS_OBJECT_NVP("d.p", ("cd", com), ("cz", com_z), ("51", proof_51),
//                             ("hy", proof_hy));
//         }
//     };

//     struct ReluProof{
//         typename R1cs::Proof r1cs_proof;
//         std::vector<G1> com_w;

//         template <typename Ar>
//         void serialize(Ar& ar) const {
//         ar& YAS_OBJECT_NVP("dr.p", ("r1cs", r1cs_proof), ("w", com_w));
//         }

//         template <typename Ar>
//         void serialize(Ar& ar) {
//         ar& YAS_OBJECT_NVP("dr.p", ("r1cs", r1cs_proof), ("w", com_w));
//         }
//     };

//     struct Proof{
//         DenseProof dense1;
//         ReluProof dense1_relu;
//         DenseProof dense2;
//         ReluProof dense2_relu;
//         DenseProof dense3;

//         template <typename Ar>
//         void serialize(Ar& ar) const {
//             ar& YAS_OBJECT_NVP("frozenlake.p", ("d1", dense1),
//                             ("dr1", dense1_relu), ("d2", dense2), ("dr2", dense2_relu), ("d3", dense3));
//         }

//         template <typename Ar>
//         void serialize(Ar& ar) {
//             ar& YAS_OBJECT_NVP("frozenlake.p", ("d1", dense1),
//                             ("dr1", dense1_relu), ("d2", dense2), ("dr2", dense2_relu), ("d3", dense3));
//         }
//     };

//     struct ProveOutput{ //the information about inner product
//         Fr com_r;
//         G1 com;
//         std::vector<Fr> data;
//     };

//     template <size_t M, size_t N> //M: the number of weight in a neuron. N: the number of neuron in a layer
//     struct ProveDenseInput{
//         ProveDenseInput(std::array<std::array<Fr, M + 1>, N> const& para_dense,
//                     std::array<G1, N> const& com_para_dense,
//                     std::array<Fr, N> const& com_para_dense_r,
//                     ProveOutput&& last_output)
//                 : para_dense(para_dense),
//                   com_para_dense(com_para_dense),
//                   com_para_dense_r(com_para_dense_r),
//                   com_data_r(last_output.com_r),
//                   com_data(last_output.com),
//                   data(std::move(last_output.data)){
//             namespace fp = circuit::fp;
//             CHECK(data.size() == M, "");
//             this->data.push_back(fp::RationalConst<6, 24>().kFrN); // [data, 1] * [weight, bias]
//             this->com_data += pc::PcG(M) * data.back();
//         }

//         // information about weight
//         std::array<std::array<Fr, M + 1>, N> const& para_dense;
//         std::array<G1, N> const& com_para_dense;
//         std::array<Fr, N> const& com_para_dense_r;

//         // information about input 
//         std::vector<Fr> data;
//         Fr com_data_r;
//         G1 com_data;
//     };

//     template <size_t N>
//     struct ProveReluInput{
//         typedef circuit::fixed_point::ReluGadget<6, 24> ReluGadget;

//         ProveReluInput(ProveOutput&& last_output):
//                 data(std::move(last_output.data)),
//                 com(last_output.com),
//                 com_r(last_output.com_r) {
//             assert(data.size() == N);

//             int64_t const primary_input_size = 0;
//             libsnark::protoboard<Fr> pb;
//             ReluGadget gadget(pb, data_, nullptr, FMT("Frozenlake ReluGadget"));

//             data_.allocate(pb, FMT("Frozenlake ReluGadget", " data"));
//             gadget.generate_r1cs_constraints();
//             pb.set_input_sizes(primary_input_size);
//             r1cs_ret_index = gadget.ret().index - 1;
//             r1cs_info.reset(new R1csInfo(pb));
//             s = r1cs_info->num_variables;
//             w.resize(s);
//             for (auto& i : w) i.resize(N);


//         #ifdef _DEBUG
//             assert(com == pc::ComputeCom(data, com_r));
//         #endif
//             for (int64_t j = 0; j < (int64_t)N; ++j) {
//                 pb.val(data_) = data[j];
//                 gadget.generate_r1cs_witness();
//                 assert(pb.is_satisfied());
//                 auto v = pb.full_variable_assignment();
//                 for (int64_t i = 0; i < s; ++i) {
//                     w[i][j] = v[i];
//                 }
//                 assert(w[0][j] == data[j]);
//             }
//         }
//         std::vector<Fr> data;
//         G1 com;
//         Fr com_r;

//         libsnark::pb_variable<Fr> data_;

//         int64_t r1cs_ret_index;
//         std::unique_ptr<R1csInfo> r1cs_info;
//         std::vector<std::vector<Fr>> mutable w; //ReluGadget中的多列witness
//         int64_t s; //ReluGadget中变量的数量
//     };

//     template <size_t N>
//     struct ProveRelu2Input {
//         typedef circuit::fixed_point::Relu2Gadget<6, 24 * 2, 24> Relu2Gadget;

//         ProveRelu2Input(ProveOutput&& last_output)
//             : data(std::move(last_output.data)),
//               com(last_output.com),
//               com_r(last_output.com_r) {
//             assert(data.size() == N);

//             libsnark::protoboard<Fr> pb;
//             Relu2Gadget gadget(pb, "Frozenlake Relu2Gadget");

//             int64_t const primary_input_size = 0;
//             pb.set_input_sizes(primary_input_size);
//             r1cs_ret_index = gadget.ret().index - 1;
//             r1cs_info.reset(new R1csInfo(pb));
//             s = r1cs_info->num_variables;
//             w.resize(s);
//             for (auto& i : w) i.resize(N);

//         #ifdef _DEBUG
//             assert(com == pc::ComputeCom(data, com_r));
//         #endif
//             for (int64_t j = 0; j < (int64_t)N; ++j) {
//                 gadget.Assign(data[j]);
//                 assert(pb.is_satisfied());
//                 auto v = pb.full_variable_assignment();
//                 for (int64_t i = 0; i < s; ++i) {
//                     w[i][j] = v[i];
//                 }
//                 assert(w[0][j] == data[j]);
//             }
//         }
//         std::vector<Fr> data;
//         G1 com;
//         Fr com_r;

//         std::unique_ptr<R1csInfo> r1cs_info;
//         int64_t s;
//         std::vector<std::vector<Fr>> mutable w;
//         int64_t r1cs_ret_index;
//     };

//     template <size_t M, size_t N>
//     struct VerifyDenseInput {
//         VerifyDenseInput(G1 const& com_data, std::array<G1, N> const& com_para_dense) 
//             : com_data(com_data),
//               com_para_dense(com_para_dense) {
//             namespace fp = circuit::fp;
//             this->com_data += pc::PcG(M) * fp::RationalConst<6, 24>().kFrN;
//         }

//         G1 com_data;
//         std::array<G1, N> const& com_para_dense;
//     };

//     struct VerifyRelu2Input {
//         typedef circuit::fixed_point::Relu2Gadget<6, 24 * 2, 24> Relu2Gadget;

//         VerifyRelu2Input(G1 const& com) : com(com){
//             libsnark::protoboard<Fr> pb;
//             Relu2Gadget gadget(pb, "Frozenlake Relu2Gadget");
//             int64_t const primary_input_size = 0;
//             pb.set_input_sizes(primary_input_size);
//             r1cs_ret_index = gadget.ret().index - 1;
//             r1cs_info.reset(new R1csInfo(pb));
//             m = r1cs_info->num_constraints;
//             s = r1cs_info->num_variables;
//         }

//         inline static int64_t n = 0;
//         G1 const& com;
//         std::unique_ptr<R1csInfo> r1cs_info;
//         size_t r1cs_ret_index;
//         int64_t m;
//         int64_t s;
//         std::vector<std::vector<Fr>> public_w;  // empty
//     };


//     // int64_t VerifyRelu2Input::n = 0;

//     template <size_t M, size_t N>
//     static std::vector<Fr> ComputeDenseFst(h256_t const& seed);

//     static void LoadPara(Para& para);

//     static void LoadState(std::vector<std::vector<Fr>>& data);

//     static void ComputeParaCom(ParaCommitmentPub& com_pub, ParaCommitmentSec& com_sec, Para const& para);

//     template <typename ProofT>
//     static void UpdateSeed(h256_t& seed, ProofT const& proof);

//     template <size_t M, size_t N>
//     static void ProveDense(DenseProof& proof, ProveOutput& output, h256_t seed,
//                          ProveDenseInput<M, N> const& input);

//     template <size_t N>
//     static void ProveRelu(ReluProof& proof, ProveOutput& output, h256_t seed,
//                          ProveReluInput<N> const& input);
    
//     template <size_t N>
//     static void ProveRelu2(ReluProof& proof, ProveOutput& output, h256_t seed,
//                          ProveRelu2Input<N> const& input);

//     static void Prove(h256_t seed, Proof& proof,
//                     std::array<Fr, 8 * 8> const& data, Para const& para,
//                     ParaCommitmentPub const& para_com_pub,
//                     ParaCommitmentSec const& para_com_sec);

//     template <size_t M, size_t N>
//     static bool VerifyDense(DenseProof const& proof, h256_t seed,
//                           VerifyDenseInput<M, N> const& input);

//     static bool VerifyRelu2(ReluProof const& proof, h256_t seed,
//                           VerifyRelu2Input const& input);

//     static bool Verify(h256_t seed, Proof const& proof,
//                     std::array<Fr, 8 * 8> const& data,
//                     ParaCommitmentPub const& para_com_pub);

//     static bool Test();

//     static bool TestSumCheck();

//     static bool testReluGadget();
// };

// template <size_t M, size_t N>
// std::vector<Fr> FrozenLake::ComputeDenseFst(h256_t const& seed) {
//     std::vector<Fr> x(N);
//     std::string str = "dense";
//     str += std::to_string(M);
//     str += "_";
//     str += std::to_string(N);
//     ComputeFst(seed, str, x);
//     return x;
// }

// template <typename ProofT>
// void FrozenLake::UpdateSeed(h256_t& seed, ProofT const& proof) {
//     CryptoPP::Keccak_256 hash;
//     HashUpdate(hash, seed);
//     yas::mem_ostream os;
//     yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
//     oa.serialize(proof);
//     auto buf = os.get_shared_buffer();
//     HashUpdate(hash, buf.data.get(), buf.size);
//     hash.Final(seed.data());
// }

// void FrozenLake::LoadPara(Para& para){
//     std::array<std::array<double, 64 + 1>, 12> dense1 = {
//         0.017140,0.017511,-0.159752,0.014187,-0.104055,0.085069,-0.227316,0.050029,0.006745,0.012260,0.021981,-0.122304,-0.132470,-0.233799,-0.282149,0.018927,-0.253411,-0.022004,-0.217931,-0.051855,-0.097648,0.018392,0.005613,0.019657,0.154590,-0.108066,0.144714,-0.082161,0.222306,0.238445,0.106311,0.269389,0.010694,-0.282816,0.022732,0.254095,-0.150374,-0.182076,-0.262797,-0.069738,0.209148,-0.130335,0.082254,-0.174938,0.126462,0.473419,0.195797,-0.217023,0.351166,-0.136546,0.070798,0.127399,0.177893,0.123603,-0.230594,-0.089164,-0.216217,-0.188952,0.100549,0.294698,0.282794,-0.291442,0.016619,0.208278, -0.027424,
//         0.085920,0.122403,-0.097177,-0.096152,0.021530,0.134997,-0.086886,0.084551,-0.098150,-0.096758,-0.097966,-0.088438,-0.086816,0.182022,0.254663,-0.191197,-0.133743,-0.176912,-0.240516,-0.280273,-0.295601,-0.091839,-0.231000,-0.004423,-0.142093,-0.094603,-0.171901,-0.098947,-0.089441,-0.000343,-0.096928,-0.087646,-0.266464,0.009574,-0.139464,0.140428,-0.271223,-0.301251,-0.091655,0.373287,-0.079392,-0.014006,0.019606,-0.027624,-0.077510,-0.184960,-0.004231,-0.087806,-0.220140,0.221925,-0.089566,-0.086559,-0.205352,0.037139,0.168348,-0.086264,-0.071089,-0.251805,-0.167911,0.280882,0.288600,-0.211805,0.567376,0.273872, 0.063756,
//         -0.181585,-0.047186,-0.024370,0.132303,-0.088975,-0.039862,-0.294647,0.057223,0.131843,-0.204918,-0.198342,0.034676,-0.034654,-0.234889,0.103295,-0.202449,0.130224,0.241484,-0.063951,-0.099234,-0.225443,0.014268,-0.217912,-0.241912,-0.275392,0.103737,0.150468,-0.299481,-0.282860,-0.061255,0.180162,-0.071389,-0.135442,0.149186,-0.004190,-0.137401,-0.170731,-0.226290,0.051913,-0.078077,-0.110277,-0.161090,0.173094,-0.131259,0.050920,0.001133,0.280963,-0.197236,-0.153960,0.192199,-0.067535,-0.228034,0.047882,-0.040580,-0.154143,-0.216490,-0.034480,0.191837,-0.111118,0.159671,0.290096,-0.113466,-0.053996,-0.202102, -0.242768,
//         -0.247902,-0.235806,-0.138556,-0.090505,-0.126636,0.036662,0.065908,0.074387,-0.168440,-0.129353,-0.174387,-0.057005,-0.241654,0.034047,0.053614,-0.132445,-0.396159,-0.316324,-0.271463,0.128413,0.057726,-0.200635,0.084945,-0.188944,-0.319173,-0.429890,-0.434385,-0.541039,-0.498103,-0.261132,0.388109,-0.118012,-0.110352,-0.062744,-0.356623,0.250319,-0.124251,-0.526735,-0.529881,0.423706,-0.408517,0.023820,-0.056376,-0.067254,-0.395878,-0.345988,0.160294,0.663577,-0.490847,-0.009641,-0.154927,-0.475371,-0.148581,-0.234174,0.085586,0.815583,-0.301484,-0.427327,-0.388253,0.287277,-0.208484,-0.007501,0.027371,-0.091895, 0.500134,
//         0.061173,-0.235150,0.151050,0.066226,0.210479,0.401224,0.261962,0.012210,-0.041738,0.065653,0.146179,-0.054230,0.065738,0.150875,0.058277,0.084319,0.048238,0.101293,-0.072944,-0.085562,-0.199227,0.264443,-0.218297,-0.010160,0.064656,0.031074,-0.199196,-0.227619,-0.037485,-0.000266,-0.039753,0.049114,-0.079159,0.151401,-0.293825,0.198634,0.180154,0.113082,-0.059656,-0.068639,-0.213148,-0.252687,-0.102995,0.188534,0.088627,-0.268237,-0.261860,0.255557,0.083443,0.094787,0.125921,-0.178915,0.156780,0.148258,0.002752,0.028336,0.150831,0.008974,-0.233511,-0.233571,0.280594,-0.126521,0.154001,0.148642, -0.283030,
//         -0.216069,-0.144051,-0.200397,-0.140492,-0.270102,0.105682,-0.149697,0.061195,-0.161713,-0.146188,0.521751,-0.145375,-0.146582,0.040881,0.027542,-0.270548,-0.191906,-0.219168,-0.237651,-0.075946,-0.150991,0.816229,-0.204615,-0.135880,-0.086072,-0.072533,-0.079699,-0.178056,-0.145114,-0.064769,-0.140877,0.037508,0.221890,0.450342,0.074667,0.029550,0.179246,0.126073,0.575030,0.117095,-0.162458,0.167462,-0.094948,-0.184308,-0.114583,-0.256995,0.258459,-0.255728,-0.203984,0.240717,0.094094,-0.179106,0.168933,0.208944,-0.273296,-0.095496,-0.093628,0.103052,-0.112760,-0.289750,-0.247409,-0.102200,-0.098261,-0.205349, 0.133824,
//         0.105691,0.126431,0.181346,-0.142208,-0.153585,-0.182253,0.256375,0.182450,-0.001228,-0.224093,-0.093404,0.003103,-0.031930,0.240136,0.183174,0.191794,-0.040488,0.148159,0.275984,-0.048317,0.120620,-0.217467,-0.258473,0.120813,0.193349,0.069340,0.062514,-0.157276,-0.219831,-0.185096,-0.281066,-0.113069,-0.155324,-0.089082,0.004884,0.016493,0.195672,-0.006548,-0.120521,-0.208642,-0.111233,0.288611,-0.067456,0.009091,-0.174356,0.041491,-0.124739,-0.242541,-0.298098,-0.102084,-0.191523,0.179770,0.100569,-0.167751,0.055571,-0.191823,-0.228566,-0.020139,0.180477,-0.156314,0.211304,-0.021976,-0.254474,0.302695, -0.286120,
//         -0.125428,-0.148817,-0.041794,-0.033233,-0.097808,-0.262035,-0.031775,-0.042359,-0.031383,-0.287065,-0.151579,-0.259201,-0.306150,-0.039736,-0.037308,-0.043928,-0.051449,0.104397,0.394906,0.262989,0.083711,-0.034389,-0.029881,-0.041293,0.061749,-0.072608,-0.291593,-0.248754,-0.119248,-0.098846,-0.084687,-0.031699,0.419458,0.506574,-0.041365,-0.274349,-0.186111,-0.249360,-0.036725,-0.060649,-0.304086,-0.091046,-0.192137,0.353363,-0.165713,0.003252,-0.245326,-0.054668,-0.291839,-0.209964,-0.289991,-0.230561,-0.078823,-0.185322,-0.195628,0.025099,0.028412,-0.089595,-0.115591,0.169893,0.233172,-0.179094,0.085474,-0.194788, 0.014919,
//         -0.058502,-0.090097,-0.043483,-0.111087,0.121491,-0.206856,-0.277632,0.185775,-0.047686,-0.065059,-0.058043,-0.100311,0.432584,-0.008634,-0.058329,0.532809,-0.058813,-0.105133,-0.056219,0.034615,-0.262019,-0.149613,-0.229601,0.594622,-0.174453,-0.219102,-0.047685,-0.070035,-0.058057,0.201984,-0.010585,0.665826,-0.011595,-0.059649,-0.061248,0.228310,-0.046857,0.050495,0.065156,-0.175511,-0.274456,-0.173982,0.033190,-0.254412,-0.228791,0.002675,-0.089257,-0.099723,-0.189379,-0.056261,-0.141169,-0.058530,0.089151,-0.103848,-0.237888,-0.065710,-0.093476,-0.127742,-0.269114,0.243095,-0.185975,-0.268431,-0.165160,0.296531, -0.075686,
//         -0.004201,0.215387,0.106697,0.203569,-0.088157,-0.062820,0.076937,-0.121795,-0.209082,-0.067669,-0.299362,-0.006280,0.163767,0.101909,0.070641,-0.241350,-0.231808,-0.269531,-0.071886,0.034598,-0.280197,0.136727,-0.020070,0.232908,-0.246653,-0.090054,-0.028620,-0.248065,0.131902,0.106958,-0.013869,-0.010576,0.205385,0.053455,-0.293371,-0.231432,-0.302599,0.270913,-0.043115,0.059181,-0.026621,0.121028,-0.137757,-0.090582,0.186735,0.195604,-0.276609,0.207147,0.014451,0.173122,0.129016,0.128159,0.095709,0.036489,0.085518,-0.150520,0.209649,0.089120,-0.276778,-0.285894,0.006689,0.050938,-0.043178,0.060152, -0.271780,
//         -0.141507,-0.169737,0.310628,-0.263010,0.163297,0.053227,-0.093578,-0.258832,0.196137,-0.212632,0.080797,-0.086408,-0.273872,-0.175221,-0.305488,-0.148443,-0.121551,-0.068231,-0.171241,-0.283446,-0.067798,0.040388,0.701792,-0.239536,-0.294108,-0.069849,-0.062243,-0.070172,-0.064379,-0.049993,0.019177,0.241166,0.176544,-0.018003,-0.071414,-0.242993,-0.206070,0.518361,-0.120267,-0.227584,-0.020959,0.053385,0.183920,-0.086218,-0.169563,-0.240153,0.225239,-0.267392,-0.014581,-0.016688,-0.207944,-0.191619,0.131459,-0.034511,-0.195770,-0.098174,0.139546,0.481597,-0.294242,-0.210063,-0.297081,0.237691,0.083275,0.139800, 0.038882,
//         -0.087112,0.021781,0.141107,-0.034871,0.033413,-0.129107,0.033930,-0.014262,-0.093889,-0.137888,-0.038862,0.006857,0.161123,-0.084426,0.177253,-0.182593,0.125492,0.152364,0.062812,-0.112599,-0.197961,0.181650,-0.017325,0.064477,0.155838,-0.012633,0.152361,0.094069,-0.097970,-0.105681,0.167370,0.021518,0.018271,-0.230045,0.595909,0.270019,-0.028444,-0.058300,0.169962,0.108314,0.186768,-0.052159,-0.259447,0.412663,0.009214,-0.292511,0.241407,0.153826,-0.161776,-0.171720,0.317959,-0.200812,0.054558,0.040472,0.024493,-0.081022,-0.243880,0.078867,-0.211578,-0.226513,-0.058649,0.150106,0.185492,0.091718, -0.212684
//     };

//     namespace fp = circuit::fp;
//     // std::cout << "layer1 bias:" << "\n";
//     // for (size_t i = 0; i < dense1.size(); ++i) {
//     //     for (size_t j = 0; j < dense1[i].size(); ++j) {
//     //         para.dense1[i][j] = fp::DoubleToRational<6, 24>(dense1[i][j]);
//     //     }
//     //     std::cout << para.dense1[i][dense1[i].size()-1] << "\t";
//     // }
//     // std::cout << "\n";

//     std::array<std::array<double, 12 + 1>, 8> dense2 = {
//         -0.285675,0.433462,-0.003761,1.330173,0.117273,-0.686185,0.105835,-0.569934,0.481020,-0.055417,0.021545,-0.439629, 0.233111,
//         0.000667,-0.448320,-0.097030,-0.913334,0.673997,1.040547,-0.579102,-0.627408,0.727940,-0.687094,-0.504649,0.023224, 0.024093,
//         0.401065,0.105954,0.085431,0.270877,0.253432,0.443564,-0.019836,-0.682061,0.397623,-0.385083,-0.725048,0.569048, -0.229269,
//         0.474760,-0.418317,0.096260,-0.582603,-0.635407,-0.460931,-0.598247,-0.364361,0.349516,0.556068,0.118121,-0.271124, -0.214019,
//         -0.066478,0.776264,0.191050,-0.131797,-0.384535,0.328051,-0.326091,-0.425267,0.612558,0.512372,0.329047,-0.291784, -0.029123,
//         0.530919,0.634940,-0.307237,0.530672,0.294586,-0.817589,-0.549717,-0.019264,-0.081361,0.221797,-0.240557,-0.067445, -0.218137,
//         0.828110,-0.384499,0.181286,0.472891,-0.258040,0.092105,0.316937,-0.937627,-0.154365,0.493902,-0.641322,0.442862, -0.217038,
//         -0.415721,0.537251,0.330144,0.155324,0.190996,-0.200467,-0.702986,-0.334586,-0.413626,-0.186859,0.119080,0.127030, -0.147311
//     };

//     for (size_t i = 0; i < dense2.size(); ++i) {
//         for (size_t j = 0; j < dense2[i].size(); ++j) {
//             para.dense2[i][j] = fp::DoubleToRational<6, 24>(dense2[i][j]);
//         }
//     }

//     std::array<std::array<double, 8 + 1>, 4> dense3 = {
//         0.296671,0.065205,0.901674,0.491545,0.483183,-1.050923,-1.227999,1.659568, 0.172036,
//         0.567688,-0.215269,-0.355977,0.824306,0.941340,-0.515747,0.507854,-0.113410, -0.010228,
//         0.750707,1.199792,-0.725605,-0.505755,0.211037,-0.017395,-0.871301,-0.403974, -0.094649,
//         0.550835,0.737534,0.040525,0.017675,0.141850,-0.328607,-0.235467,-0.044913, 0.034056
//     };

//     for (size_t i = 0; i < dense3.size(); ++i) {
//         for (size_t j = 0; j < dense3[i].size(); ++j) {
//             para.dense3[i][j] = fp::DoubleToRational<6, 24>(dense3[i][j]);
//         }
//     }
// }

// void FrozenLake::LoadState(std::vector<std::vector<Fr>>& data){
//     int state[] = {0, 8, 9, 10, 11, 12, 13, 21, 22, 30, 38, 39, 47, 55}; //14个状态
//     circuit::fp::RationalConst<6, 24> rationalConst;
//     for(int i=0; i<14; i++){
//         data[i].resize(64, 0);
//         data[i][state[i]] = rationalConst.kFrN;
//     }
//     for(int i=0; i<64; i++){
//         std::cout << data[13][i] << "\t";
//     }
// }

// void FrozenLake::ComputeParaCom(ParaCommitmentPub& com_pub,
//                              ParaCommitmentSec& com_sec, Para const& para) {
//     auto parallel_f1 = [&para, &com_sec, &com_pub](int64_t i) {
//         com_sec.dense1[i] = FrRand();
//         com_pub.dense1[i] = pc::ComputeCom(64 + 1, para.dense1[i].data(),
//                                             com_sec.dense1[i]);
//     };
//     auto parallel_f2 = [&para, &com_sec, &com_pub](int64_t i) {
//         com_sec.dense2[i] = FrRand();
//         com_pub.dense2[i] = pc::ComputeCom(12 + 1, para.dense2[i].data(),
//                                             com_sec.dense2[i]);
//     };
//     auto parallel_f3 = [&para, &com_sec, &com_pub](int64_t i) {
//         com_sec.dense3[i] = FrRand();
//         com_pub.dense3[i] = pc::ComputeCom(8 + 1, para.dense3[i].data(),
//                                             com_sec.dense3[i]);
//     };

//     parallel::For(12, parallel_f1);
//     parallel::For(8, parallel_f2);
//     parallel::For(4, parallel_f3);
// }

// template <size_t M, size_t N>
// void FrozenLake::ProveDense(DenseProof& proof, ProveOutput& output, h256_t seed,
//                     ProveDenseInput<M, N> const& input){
//     Tick tick(__FN__);
//     assert(input.para_dense.size() == N);
//     assert(input.data.size() == M + 1);

//     // build output
//     output.data.resize(N);
//     auto parallel_f = [&input, &output](int64_t i) {
//       assert(input.para_dense[i].size() == M + 1);
//       output.data[i] =
//           std::inner_product(input.data.begin(), input.data.end(),
//                              input.para_dense[i].begin(), FrZero());
//     };
//     parallel::For(N, parallel_f);

// #ifdef _DEBUG
//     std::cout << "dense before relu:\n";
//     for (size_t i = 0; i < N; ++i) {
//       std::cout << output.data[i] << "\n";
//     }
// #endif

//     //commitment of output
//     output.com_r = FrRand();
//     output.com = pc::ComputeCom(output.data, output.com_r);

//     // prove
//     std::vector<Fr> x = ComputeDenseFst<M, N>(seed); // y^0, ..., y^{N-1}
//     G1 com_e = G1Zero();
//     Fr com_e_r = FrZero();
//     for (size_t i = 0; i < N; ++i) {
//         com_e += input.com_para_dense[i] * x[i];
//         com_e_r += input.com_para_dense_r[i] * x[i];
//     }
//     std::vector<Fr> e(M + 1);
//     for (size_t i = 0; i < M + 1; ++i) {
//         e[i] = FrZero();
//         for (size_t j = 0; j < N; ++j) {
//             e[i] += input.para_dense[j][i] * x[j];
//         }
//     }

//     Fr z = std::inner_product(x.begin(), x.end(), output.data.begin(), FrZero());
//     Fr com_z_r = FrRand();
//     G1 com_z = pc::ComputeCom(z, com_z_r);
//     proof.com_z = com_z;
//     proof.com = output.com;

//     // prove left
//     HyraxA::ProveInput input_hy("frozenlake", output.data, x, z, pc::kGetRefG1, pc::PcG(0));
//     HyraxA::CommitmentPub com_pub_hy(output.com, com_z); // com(a1, \cdots, a_i), com(c)
//     HyraxA::CommitmentSec com_sec_hy(output.com_r, com_z_r);
//     HyraxA::Prove(proof.proof_hy, seed, input_hy, com_pub_hy, com_sec_hy);

//     // prove right
//     /**
//      * 这里可以改为一个内积证明
//      */
//     std::vector<Fr> t(e.size(), FrOne());
//     Sec51::ProveInput input_51(e, input.data, t, input.data, z, pc::kGetRefG1,
//                                          pc::kGetRefG1, pc::PcG(0));
//     Sec51::CommitmentPub com_pub_51(com_e, input.com_data, com_z);
//     Sec51::CommitmentSec com_sec_51(com_e_r, input.com_data_r, com_z_r);
//     Sec51::Prove(proof.proof_51, seed, input_51, com_pub_51,
//                            com_sec_51);
// }

// template <size_t N>
// void FrozenLake::ProveRelu(ReluProof& proof, ProveOutput& output, h256_t seed,
//                          ProveReluInput<N> const& input) {
//     Tick tick(__FN__);
//     namespace fp = circuit::fp;
//     std::vector<G1> com_w(input.s);
//     std::vector<Fr> com_w_r(input.s);

//     // std::cout << "compute com(witness)\n";
//     auto parallel_f = [&com_w_r, &com_w, &input](int64_t i) {
//       if (i == 0) {
//         com_w_r[i] = input.com_r;
//         com_w[i] = input.com;
//       } else {
//         com_w_r[i] = FrRand();
//         com_w[i] = pc::ComputeCom(input.w[i], com_w_r[i], true);
//       }
//     };
//     parallel::For<int64_t>(input.s, parallel_f);

//     // save output for next step
//     output.com_r = com_w_r[input.r1cs_ret_index];
//     output.com = com_w[input.r1cs_ret_index];
//     output.data = input.w[input.r1cs_ret_index];

// #ifdef _DEBUG
//     std::cout << "dense relu:\n";
//     for (size_t j = 0; j < output.data.size(); ++j) {
//       double dret = fp::RationalToDouble<6, 24>(output.data[j]);
//       std::cout << std::right << std::setw(12) << std::setfill(' ') << dret;
//     }
//     std::cout << "\n";
// #endif

//     // prove
//     typename R1cs::ProveInput r1cs_input(*input.r1cs_info, "frozenlake",
//                                          std::move(input.w), com_w, com_w_r,
//                                          pc::kGetRefG1);
//     R1cs::Prove(proof.r1cs_proof, seed, std::move(r1cs_input));
//     proof.com_w = std::move(com_w);
// }

// template <size_t N>
// void FrozenLake::ProveRelu2(ReluProof& proof, ProveOutput& output, h256_t seed,
//                          ProveRelu2Input<N> const& input){
//     Tick tick(__FN__);
//     std::vector<G1> com_w(input.s);
//     std::vector<Fr> com_w_r(input.s);

//     auto parallel_f = [&com_w_r, &com_w, &input](int64_t i) {
//         if (i == 0) {
//             com_w_r[i] = input.com_r;
//             com_w[i] = input.com;
//         } else {
//             com_w_r[i] = FrRand();
//             com_w[i] = pc::ComputeCom(input.w[i], com_w_r[i], true);
//         }
//     };
//     parallel::For<int64_t>(input.s, parallel_f);

//     // save output for next step
//     output.com_r = com_w_r[input.r1cs_ret_index];
//     output.com = com_w[input.r1cs_ret_index];
//     output.data = input.w[input.r1cs_ret_index];

// #ifdef _DEBUG
//     std::cout << "dense relu:\n";
//     for (size_t j = 0; j < output.data.size(); ++j) {
//         double dret = fp::RationalToDouble<6, 24>(output.data[j]);
//         std::cout << std::right << std::setw(12) << std::setfill(' ') << dret;
//     }
//     std::cout << "\n";
// #endif

//     // prove
//     typename R1cs::ProveInput r1cs_input(*input.r1cs_info, "frozenlake",
//                                          std::move(input.w), com_w, com_w_r,
//                                          pc::kGetRefG1);
//     R1cs::Prove(proof.r1cs_proof, seed, std::move(r1cs_input));
//     proof.com_w = std::move(com_w);
// }

// // 对于一个prove, 要准备对应的proveinput, 包含: 承诺, 打开(承诺数据 + 随机数), 数据
// void FrozenLake::Prove(h256_t seed, Proof& proof,
//                     std::array<Fr, 8 * 8> const& data, Para const& para,
//                     ParaCommitmentPub const& para_com_pub,
//                     ParaCommitmentSec const& para_com_sec){
//     Tick tick(__FN__);

//     ProveOutput origin_output;
//     origin_output.data = std::vector<Fr>(data.begin(), data.end());
//     origin_output.com_r = 0;
//     origin_output.com = pc::ComputeCom(origin_output.data, origin_output.com_r);

//     // std::cout << "state:\n";
//     // for(int i=0; i<origin_output.data.size(); i++){
//     //     std::cout << origin_output.data[i] << "\t";
//     // }
//     // std::cout << "\n";
//     // std::cout << "dense1:\n";
//     // for(int i=0; i<para.dense1.size(); i++){
//     //     for(int j=0; j<para.dense1[i].size(); j++)
//     //     std::cout << para.dense1[i][j] << "\t";
//     // }
//     // std::cout << "\n";

//     // prove dense1
//     ProveDenseInput<64, 12> dense1_input(
//         para.dense1, para_com_pub.dense1, para_com_sec.dense1, std::move(origin_output));
//     ProveOutput dense1_output; // 输出是<D, 2N>
//     ProveDense<64, 12>(proof.dense1, dense1_output, seed, dense1_input);
//     UpdateSeed(seed, proof.dense1);

//     // std::cout << "dense1 output:\n";
//     // for(int i=0; i<dense1_output.data.size(); i++){
//     //     std::cout << dense1_output.data[i] << "\t";
//     // }
//     // std::cout << "\n";
    
//     // prove dense1 relu
//     ProveRelu2Input<12> dense1_relu_input(std::move(dense1_output));
//     ProveOutput dense1_relu_output; // 输出是<D, N>
//     ProveRelu2<12>(proof.dense1_relu, dense1_relu_output, seed, dense1_relu_input);
//     UpdateSeed(seed, proof.dense1_relu);

//     // std::cout << "relu1 output:\n";
//     // for(int i=0; i<dense1_relu_output.data.size(); i++){
//     //     std::cout << dense1_relu_output.data[i] << "\t";
//     // }
//     // std::cout << "\n";
//     // std::cout << "dense2:\n";
//     // for(int i=0; i<para.dense2.size(); i++){
//     //     for(int j=0; j<para.dense2[i].size(); j++)
//     //     std::cout << para.dense2[i][j] << "\t";
//     // }
//     // std::cout << "\n";

//     // prove dense2
//     ProveDenseInput<12, 8> dense2_input(
//         para.dense2, para_com_pub.dense2, para_com_sec.dense2, std::move(dense1_relu_output));
//     ProveOutput dense2_output; // 输出是<D, 2N>
//     ProveDense<12, 8>(proof.dense2, dense2_output, seed, dense2_input);
//     UpdateSeed(seed, proof.dense2);

//     // std::cout << "dense2 output:\n";
//     // for(int i=0; i<dense2_output.data.size(); i++){
//     //     std::cout << dense2_output.data[i] << "\t";
//     // }
//     // std::cout << "\n";

//     // prove dense2 relu
//     ProveRelu2Input<8> dense2_relu_input(std::move(dense2_output));
//     ProveOutput dense2_relu_output; // 输出是<D, N>
//     ProveRelu2<8>(proof.dense2_relu, dense2_relu_output, seed, dense2_relu_input);
//     UpdateSeed(seed, proof.dense2_relu);

//     // std::cout << "relu2 output:\n";
//     // for(int i=0; i<dense2_relu_output.data.size(); i++){
//     //     std::cout << dense2_relu_output.data[i] << "\t";
//     // }
//     // std::cout << "\n";
//     // std::cout << "dense3:\n";
//     // for(int i=0; i<para.dense3.size(); i++){
//     //     for(int j=0; j<para.dense3[i].size(); j++)
//     //     std::cout << para.dense3[i][j] << "\t";
//     // }
//     // std::cout << "\n";

//     // prove dense3
//     ProveDenseInput<8, 4> dense3_input(
//         para.dense3, para_com_pub.dense3, para_com_sec.dense3, std::move(dense2_relu_output));
//     ProveOutput dense3_output; // 输出是<D, 2N>
//     ProveDense<8, 4>(proof.dense3, dense3_output, seed, dense3_input);

//     // std::cout << "dense3 output:\n";
//     // for(int i=0; i<dense3_output.data.size(); i++){
//     //     std::cout << dense3_output.data[i] << "\t";
//     // }
//     // std::cout << "\n";

// }

// template <size_t M, size_t N>
// bool FrozenLake::VerifyDense(DenseProof const& proof, h256_t seed,
//                           VerifyDenseInput<M, N> const& input){
//     Tick tick(__FN__);
//     std::vector<Fr> x = ComputeDenseFst<M, N>(seed);

//     G1 com_e = G1Zero();
//     for (size_t i = 0; i < N; ++i) {
//         com_e += input.com_para_dense[i] * x[i];
//     }

//     HyraxA::CommitmentPub com_pub_hy(proof.com, proof.com_z);
//     HyraxA::VerifyInput input_hy("frozenlake", x, com_pub_hy, pc::kGetRefG1, pc::PcG(0));
//     if (!HyraxA::Verify(proof.proof_hy, seed, input_hy)) {
//         assert(false);
//         std::cout << "HyraxA::Verify fail \n";
//         return false;
//     }

//     Sec51::CommitmentPub com_pub_51(com_e, input.com_data, proof.com_z);
//     std::vector<Fr> t(M + 1, FrOne());
//     Sec51::VerifyInput input_51(t, com_pub_51, pc::kGetRefG1, pc::kGetRefG1, pc::PcG(0));
//     if (!Sec51::Verify(proof.proof_51, seed, input_51)) {
//         assert(false);
//         std::cout << "Sec51::Verify fail \n";
//         return false;
//     }

//     return true;
// }

// bool FrozenLake::VerifyRelu2(ReluProof const& proof, h256_t seed,
//                           VerifyRelu2Input const& input){
//     Tick tick(__FN__);
//     if ((int64_t)proof.com_w.size() != input.s) {
//         assert(false);
//         std::cout << "witness size != input.s\n";
//         return false;
//     }

//     // Check com of secret input
//     if (proof.com_w[0] != input.com) {
//         assert(false);
//         std::cout << "proof.com_w[0] != input.com\n";
//         return false;
//     }

//     typename R1cs::VerifyInput pr_input(input.n, *input.r1cs_info, "mnist",
//                                         proof.com_w, input.public_w,
//                                         pc::kGetRefG1);
//     return R1cs::Verify(proof.r1cs_proof, seed, pr_input);
// }

// bool FrozenLake::Verify(h256_t seed, Proof const& proof,
//                     std::array<Fr, 8 * 8> const& data,
//                     ParaCommitmentPub const& para_com_pub){
//     Tick tick(__FN__);

//     ProveOutput origin_output;
//     origin_output.data = std::vector<Fr>(data.begin(), data.end());
//     origin_output.com_r = 0;
//     origin_output.com = pc::ComputeCom(origin_output.data, origin_output.com_r);

//     // verify dense1
//     VerifyDenseInput<64, 12> dense1_input(origin_output.com, para_com_pub.dense1);
//     if(!VerifyDense<64, 12>(proof.dense1, seed, dense1_input)){
//         assert(false);
//         std::cout << "verify dense1 fail!\n";
//         return false;
//     }
//     UpdateSeed(seed, proof.dense1);

//     // verify dense relu1
//     VerifyRelu2Input::n = 12;
//     VerifyRelu2Input dense1_relu_input(proof.dense1.com);
//     if (!VerifyRelu2(proof.dense1_relu, seed, dense1_relu_input)) {
//         assert(false);
//         std::cout << "verify relu1 fail!\n";
//         return false;
//     }
//     UpdateSeed(seed, proof.dense1_relu);

//     // verify dense2
//     VerifyDenseInput<12, 8> dense2_input(proof.dense1_relu.com_w[dense1_relu_input.r1cs_ret_index], para_com_pub.dense2);
//     if(!VerifyDense<12, 8>(proof.dense2, seed, dense2_input)){
//         assert(false);
//         std::cout << "verify dense2 fail!\n";
//         return false;
//     }
//     UpdateSeed(seed, proof.dense2);

//     //verify relu2
//     VerifyRelu2Input::n = 8;
//     VerifyRelu2Input dense2_relu_input(proof.dense2.com);
//     dense2_relu_input.n = 8;
//     if (!VerifyRelu2(proof.dense2_relu, seed, dense2_relu_input)) {
//         assert(false);
//         std::cout << "verify relu2 fail!\n";
//         return false;
//     }
//     UpdateSeed(seed, proof.dense2_relu);

//     // verify dense3
//     VerifyDenseInput<8, 4> dense3_input(proof.dense2_relu.com_w[dense1_relu_input.r1cs_ret_index], para_com_pub.dense3);
//     if(!VerifyDense<8, 4>(proof.dense3, seed, dense3_input)){
//         assert(false);
//         std::cout << "verify dense3 fail!\n";
//         return false;
//     }

//     return true;
// }


// bool FrozenLake::testReluGadget(){
//     Tick tick(__FN__);
//     auto seed = misc::RandH256();
//     ProveOutput last_output, output;
//     last_output.data.resize(2);
//     last_output.data[0] = 1 << 24;
//     last_output.data[1] = 2 << 24;
//     last_output.com_r = FrRand();
//     last_output.com = pc::ComputeCom(output.data, output.com_r);
//     ProveReluInput<2> relu_input(std::move(last_output));
//     ProveOutput relu_output;
//     ReluProof relu_proof;
//     ProveRelu<2>(relu_proof, output, seed, relu_input);
//     return true;
// }


// bool FrozenLake::Test() {
//     std::unique_ptr<Para> para(new Para);
//     LoadPara(*para);

//     std::vector<std::vector<Fr>> data(14);
//     LoadState(data);

//     //commit to param
//     std::unique_ptr<ParaCommitmentPub> para_com_pub(new ParaCommitmentPub); // commitment
//     std::unique_ptr<ParaCommitmentSec> para_com_sec(new ParaCommitmentSec); // rnd
//     ComputeParaCom(*para_com_pub, *para_com_sec, *para); // para

//     Tick tick(__FN__);

//     auto seed = misc::RandH256();

//     Proof proof;
//     // Prove(seed, proof, data, *para, *para_com_pub, *para_com_sec);

//     // bool success = Verify(seed, proof, data, *para_com_pub);

//     // std::cout << "success:" << success << "\n";
//     // return success;
//     return 0;
// }


// bool FrozenLake::TestSumCheck() {
//     std::vector<Fr> r(3);
//     r = {
//         1, -1, -2
//     };
//     std::vector<Fr> ret(2 << 2);
//     R1cs::InitArray(r, ret);
//     for(int i=0; i<8; i++){
//         std::cout << ret[i] << "\t";
//     }

//     return true;
// }

// //结论: var_index和full_variable_assignment中的index相差1
// bool testVarIdxAndAssignIdx(){
//     libsnark::protoboard<Fr> pb;
    
//     // 创建变量x, y, z
//     libsnark::pb_variable<Fr> x, y, z;

//     // 分配index给变量
//     x.allocate(pb, FMT("data")); // x会有一个唯一的index
//     y.allocate(pb, FMT("data")); // y会有一个唯一的index
//     z.allocate(pb, FMT("data")); // z会有一个唯一的index

//     // 获取R1CS信息
//     std::unique_ptr<R1csInfo> r1cs_info;
//     r1cs_info.reset(new R1csInfo(pb));
    
//     // 输出总变量数量
//     std::cout << "Number of variables in R1CS: " << r1cs_info->num_variables << "\n";
    
//     // 输出各个变量的index
//     std::cout << "Index of x: " << x.index << "\n"; 
//     std::cout << "Index of y: " << y.index << "\n";
//     std::cout << "Index of z: " << z.index << "\n";

//     pb.add_r1cs_constraint(libsnark::r1cs_constraint<Fr>(x, y, z),
//         FMT("z = x * y"));

//     pb.val(x) = 2;
//     pb.val(y) = 3;
//     pb.val(z) = 6;

//     auto v = pb.full_variable_assignment();
//     for (int64_t i = 0; i < v.size(); ++i) {
//         std::cout << "assign index:" << i << " assign value:" << v[i] << "\n";
//     }

//     assert(pb.is_satisfied());

//     return true;
// }

// }
