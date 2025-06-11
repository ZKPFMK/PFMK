#pragma once

#include "../details.h"
#include "libra/libra.h"

#include "circuit/mimc5_gadget.h"
#include "circuit/fixed_point/fixed_point.h"
#include "circuit/frozenlake/env_gadget.h"
#include "clink/equality3.h"

namespace clink::frozenlake{

struct FrozenLake{

    struct Para{
        std::vector<std::vector<Fr>> dense1; //(64 + 1) * 12
        std::vector<std::vector<Fr>> dense2; //(12 + 1) * 8
        std::vector<std::vector<Fr>> dense3; //(8 + 1) * 4
        size_t m1() const { return 65;}
        size_t n1() const { return 12;}
        size_t m2() const { return 13;}
        size_t n2() const { return 8;}
        size_t m3() const { return 9;}
        size_t n3() const { return 4;}
    };

    struct ParaCommitmentPub { // commitment of col
        std::vector<G1> dense1; //12
        std::vector<G1> dense2; //8
        std::vector<G1> dense3; //4
    };

    struct ParaCommitmentSec { // the random used to compute commitment
        std::vector<Fr> r_dense1; //12
        std::vector<Fr> r_dense2; //8
        std::vector<Fr> r_dense3; //4
    };
 
    struct VerifyInput {
        VerifyInput(size_t const& m_, int64_t const& n_,
                    std::vector<G1> const& data_com_pub,
                    std::vector<G1> const& action_com_pub,
                    ParaCommitmentPub const& para_com_pub,
                    GetRefG1 const& get_g)
            :   m_(m_),
                n_(n_),
                data_com_pub(data_com_pub),
                para_com_pub(para_com_pub),
                action_com_pub(action_com_pub),
                get_g(get_g) {
            }
            ParaCommitmentPub const& para_com_pub;
            std::vector<G1> const& data_com_pub;
            std::vector<G1> const& action_com_pub;
            GetRefG1 const& get_g;
            size_t m_, n_;
            size_t m() const { return m_; }
            size_t n() const { return n_; }
            size_t m1() const { return 64;}
            size_t n1() const { return 12;}
            size_t m2() const { return 12;}
            size_t n2() const { return 8;}
            size_t m3() const { return 8;}
            size_t n3() const { return 4;}
            std::string to_string() const {
            return std::to_string(m()) + "*" + std::to_string(n());
        }
    };

    struct KeyProveInput{
        Fr k;
        std::vector<std::vector<Fr>> bits, a;
        std::vector<Fr> sub_keys;
        G1 pk;

        KeyProveInput(Fr const& k, std::vector<std::vector<Fr>> const& bits,
                      std::vector<std::vector<Fr>> const& a,
                      std::vector<Fr> const& sub_keys, G1 const& pk)
            : k(k),
              bits(bits),
              a(a),
              sub_keys(sub_keys),
              pk(pk)
             {
            if(DEBUG_CHECK){
                Fr t = 0;
                std::vector<Fr> t_vec(n(), 0);
                for(int i=0; i<m(); i++){
                    t += InnerProduct(a[i], bits[i]);
                    t_vec += bits[i] * a[i][0];
                    for(int j=0; j<n(); j++){
                        assert(bits[i][j] == 0 || bits[i][j] == 1);
                    }
                }
                assert(t == k);
                assert(t_vec == sub_keys);
            }
        }
        
        size_t m() const { return bits.size(); }
        size_t n() const { return bits[0].size(); }
    };

    struct KeyCommitmentPub{
        G1 com_k;
        std::vector<G1> com_bits; //m
        std::vector<G1> enc_sub_keys1;   //n
        std::vector<G1> enc_sub_keys2;   //n
        KeyCommitmentPub(G1 const& com_k, 
                         std::vector<G1> const& com_bits,
                         std::vector<G1> const& enc_sub_keys1,
                         std::vector<G1> const& enc_sub_keys2)
            : com_k(com_k),
              com_bits(com_bits),
              enc_sub_keys1(enc_sub_keys1),
              enc_sub_keys2(enc_sub_keys2){}
    };

    struct KeyCommitmentSec{
        Fr r_com_k;
        std::vector<Fr> r_enc_sub_keys, r_com_bits;

        KeyCommitmentSec(Fr const& r_com_k,
                         std::vector<Fr> const& r_com_bits,
                         std::vector<Fr> const& r_enc_sub_keys)
            : r_com_k(r_com_k),
              r_com_bits(r_com_bits),
              r_enc_sub_keys(r_enc_sub_keys){}
    };

    struct KeyVerifyInput{
        G1 pk;
        KeyCommitmentPub const& com_pub;
        std::vector<std::vector<Fr>> a;
        KeyVerifyInput(std::vector<std::vector<Fr>> const& a,
                       G1 const& pk, 
                       KeyCommitmentPub const& com_pub)
            : pk(pk),
              a(a),
              com_pub(com_pub){}
        size_t m() const { return a.size(); }
        size_t n() const { return a[0].size(); }
    };

    struct KeyProof{
        G1 com_ad;
        std::vector<G1> com_b, com_c, com_d, enc_sum_d1, enc_sum_d2;

        std::vector<std::vector<Fr>> z; 
        std::vector<Fr> r_com_z, r_com_eta, r_enc_z;
        Fr r_com_zeta;

        bool operator==(KeyProof const& right) const {
            return com_ad == right.com_ad && com_b == right.com_b &&
                   com_c == right.com_c && com_d == right.com_d &&
                   enc_sum_d1 == right.enc_sum_d1 && enc_sum_d2 == right.enc_sum_d2 && z == right.z &&
                   r_com_z == right.r_com_z && r_com_eta == right.r_com_eta &&
                   r_com_zeta == right.r_com_zeta && r_enc_z == right.r_enc_z;
        }
        bool operator!=(KeyProof const& right) const { return !(*this == right); }


        template <typename Ar>
        void serialize(Ar& ar) const {
            // ar& YAS_OBJECT_NVP("k.p", ("ad", com_ad), ("b", com_b), ("c", com_c),
            //                   ("d", com_d), ("w1", enc_w1), ("w2", enc_w2),
            //                   ("fz", z), ('gz', r_com_z), ("eta", r_com_eta), ("zeta", r_com_zeta));

            ar& YAS_OBJECT_NVP("k.p", ("cad", com_ad), ("cb", com_b), ("cc", com_c), ("cd", com_d),
                              ("ed1", enc_sum_d1), ("ed2", enc_sum_d2), ("fz", z), ("frz", r_com_z),
                              ("fre", r_com_eta), ("fra", r_com_zeta), ("fez", r_enc_z));
        }

        template <typename Ar>
        void serialize(Ar& ar) {
             ar& YAS_OBJECT_NVP("k.p", ("cad", com_ad), ("cb", com_b), ("cc", com_c), ("cd", com_d),
                              ("ed1", enc_sum_d1), ("ed2", enc_sum_d2), ("fz", z), ("frz", r_com_z),
                              ("fre", r_com_eta), ("fra", r_com_zeta), ("fez", r_enc_z));
        }
    };

    struct PodProof{
        libra::A1::Proof enc_proof;
        std::vector<G1> com_mimc;

        bool operator==(PodProof const& right) const {
            return enc_proof == right.enc_proof &&
                   com_mimc == right.com_mimc;
        }
        bool operator!=(PodProof const& right) const { return !(*this == right); }


        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("pod.p", ("cp", enc_proof), ("cw", com_mimc));
        }

        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("pod.p", ("cp", enc_proof), ("cw", com_mimc));
        }
    };

    struct EnvProof{
        libra::A1::Proof env_proof;
        clink::Equality3::Proof eq_proof;

        std::vector<G1> com_env;

        bool operator==(EnvProof const& right) const {
            return env_proof == right.env_proof && com_env == right.com_env;
        }
        bool operator!=(EnvProof const& right) const { return !(*this == right); }


        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("frozenlake.p", ("ep", env_proof), ("ce", com_env));
        }

        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("frozenlake.p", ("ep", env_proof), ("ce", com_env));
        }
    };

    struct ModelProof{

        std::vector<std::vector<G1>> relu1_in_com;
        std::vector<std::vector<G1>> relu2_in_com;
        std::vector<G1> final_in_com;

        libra::A2::Proof dense1_proof;
        libra::A2::Proof dense2_proof;
        libra::A2::Proof dense3_proof;
        libra::A3::Proof relu1_proof;
        libra::A3::Proof relu2_proof;
        libra::A1::Proof max_proof;

        bool operator==(ModelProof const& right) const {
            return relu1_in_com == right.relu1_in_com && relu2_in_com == right.relu2_in_com &&
                final_in_com == right.final_in_com && dense1_proof == right.dense1_proof &&
                dense2_proof == right.dense2_proof && dense3_proof == right.dense3_proof &&
                relu1_proof == right.relu1_proof && relu2_proof == right.relu2_proof &&
                max_proof == right.max_proof;
        }
        bool operator!=(ModelProof const& right) const { return !(*this == right); }


        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("frozenlake.p", ("d1", dense1_proof), ("d2", dense2_proof), 
                            ("d3", dense3_proof),("r1", relu1_proof), ("r1", relu2_proof),
                             ("mx", max_proof), ("rcm1", relu1_in_com),
                             ("rcm2", relu2_in_com), ("out", final_in_com));
        }

        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("frozenlake.p", ("d1", dense1_proof), ("d2", dense2_proof), 
                            ("d3", dense3_proof),("r1", relu1_proof), ("r1", relu2_proof),
                             ("mx", max_proof), ("rcm1", relu1_in_com),
                             ("rcm2", relu2_in_com), ("out", final_in_com));
        }
    };

    struct DeliverTuple{
        std::vector<Fr> cipher; //msg
        Fr r_com_cipher;
        KeyProof key_proof;
        ModelProof model_proof;
        EnvProof env_proof;
        PodProof pod_proof;
        std::vector<G1> com_state, com_action;

        bool operator==(DeliverTuple const& right) const {
            return cipher == right.cipher &&
                   r_com_cipher == right.r_com_cipher &&
                   key_proof == right.key_proof &&
                   model_proof == right.model_proof &&
                   env_proof == right.env_proof &&
                   pod_proof == right.pod_proof &&
                   com_state == right.com_state &&
                   com_action == right.com_action;
        }
        bool operator!=(DeliverTuple const& right) const { return !(*this == right); }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("fl.p", ("ca", cipher),
                              ("rca", r_com_cipher), ("cmts", com_state), ("cmta", com_action),
                              ("kp", key_proof), ("mp", model_proof), ("ep", env_proof), ("pp",pod_proof ));
        }

        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("fl.p", ("ca", cipher),
                              ("rca", r_com_cipher), ("cmts", com_state), ("cmta", com_action),
                              ("kp", key_proof), ("mp", model_proof), ("ep", env_proof), ("pp",pod_proof ));
        }
    };

    struct ProveOutput{ //the information about inner product
        std::vector<G1> com;   //n
        std::vector<Fr> r_com; //n
        std::vector<std::vector<Fr>> data; //n * 12
        
        bool is_row;

        ProveOutput(){
            is_row = false;
        }

        ProveOutput(int64_t m, int64_t n, bool is_row=false)
            : is_row(is_row) {
            int64_t t = m;
            if(!is_row){
                t = n;
            }
            com.resize(t);
            r_com.resize(t);
            data.resize(m, std::vector<Fr>(n));
        }

        size_t m() const { return data.size(); }
        size_t n() const { return data[0].size(); }
    };

    struct MultiOutput { //the information about inner product
        std::vector<std::vector<G1>> com;   //k*m
        std::vector<std::vector<Fr>> r_com; //k*m
        std::vector<std::vector<std::vector<Fr>>> data; //k*m*n

        // ReluData
        MultiOutput(){}
        
        MultiOutput(int64_t k, int64_t m, int64_t n) {
            data.resize(k, std::vector<std::vector<Fr>>(m, std::vector<Fr>(n)));
            r_com.resize(k, std::vector<Fr>(m));
            com.resize(k, std::vector<G1>(m));
        }

        size_t k() const { return data.size(); }
        size_t m() const { return data[0].size(); }
        size_t n() const { return data[0][0].size(); }
    };

    template <size_t M, size_t N>
    static std::vector<Fr> ComputeDenseFst(h256_t const& seed);

    static void LoadPara(Para& para);

    static void LoadState(std::vector<std::vector<Fr>> &data);

    static void LoadAction(std::vector<std::vector<Fr>> &action);

    static void AddCol(ProveOutput & out);

    static void AddCol(std::vector<G1> & out, int64_t m);

    static void ComputeOutCom(ProveOutput & out);

    static void ComputeParaCom(ParaCommitmentPub& com_pub, ParaCommitmentSec& com_sec, Para const& para);

    static void ComputeMimcWit(Fr const& key, ProveOutput const& in, ProveOutput & mimc_data);

    static void ComputeEnvWit(ProveOutput const& state, ProveOutput const& action, 
                               std::vector<int> const& trap, ProveOutput & out);

    static void ComputeMaxWit(ProveOutput const& in, ProveOutput const& action, ProveOutput & max_data);

    static void ComputeReluWit(ProveOutput const& in, ProveOutput & out, MultiOutput & relu_data);

    static void UpdateSeed(h256_t& seed, G1 const& a1, std::vector<G1> const& a2, 
                            std::vector<G1> const& a3, std::vector<G1> const& a4,
                            std::vector<G1> const& a5, std::vector<G1> const& a6);

    template <typename ProofT>
    static void UpdateSeed(h256_t& seed, ProofT const& proof);

    static void BuildHpCom(libsnark::protoboard<Fr> const& pb, //prove max
                            ProveOutput const& out,
                            libra::A1::ProveInput & max_input,
                            libra::A1::CommitmentPub & max_com_pub,
                            libra::A1::CommitmentSec & max_com_sec);

    static void BuildHpCom(libsnark::protoboard<Fr> const& pb,
                            MultiOutput const& relu_data, //prove relu
                            libra::A3::ProveInput & relu_input,
                            libra::A3::CommitmentPub & relu_com_pub,
                            libra::A3::CommitmentSec & relu_com_sec);

    static void BuildHpCom(std::vector<std::vector<Fr>> const& w, //prove
                            std::vector<G1> const &com_w,
                            std::vector<Fr> const &com_w_r,
                            libsnark::linear_combination<Fr> const &lc,
                            std::vector<Fr> &data, G1 &com_pub, Fr &com_sec, G1 const &sigma_g);

    static void BuildHpCom(std::vector<G1> const &com_w, //verify 
                            libsnark::linear_combination<Fr> const& lc,
                            G1 &com_pub, G1 const& pds_sigma_g);

    static void BuildHpCom(libsnark::protoboard<Fr> const& pb, //verify max
                            int64_t const& n, 
                            std::vector<G1> const& com_w,
                            libra::A1::CommitmentPub & com_pub);

    static void BuildHpCom(libsnark::protoboard<Fr> const& pb, //verify relu
                            int64_t const& n,  
                            std::vector<std::vector<G1>> const& com_w,
                            libra::A3::CommitmentPub & com_pub);

    static void KeyProve(h256_t seed, KeyProof & proof, KeyProveInput const& input, 
                          KeyCommitmentPub const& com_pub, KeyCommitmentSec const& com_sec);

    static void PodProve(h256_t seed, DeliverTuple &tpl, PodProof& proof, 
                         ProveOutput const& in, Fr const& key);

    static void EnvProve(h256_t seed, EnvProof& proof,
                        ProveOutput const& state, 
                        ProveOutput const& action,
                        std::vector<int> const& trap);

    static void ModelProve(h256_t seed, ModelProof& proof,
                            ProveOutput const& in, 
                            ProveOutput const& action,
                            Para const& para,
                            ParaCommitmentPub const& para_com_pub,
                            ParaCommitmentSec const& para_com_sec);

    static bool KeyVerify(h256_t seed, KeyProof const& proof, KeyVerifyInput const& input);

    static bool PodVerify(h256_t seed, DeliverTuple const& tpl, PodProof const& proof,
                        std::vector<G1> const& com_in, int64_t const& n);

    static bool ModelVerify(h256_t seed, ModelProof const& proof,
                        VerifyInput const& input);

    static bool EnvVerify(h256_t seed, EnvProof const& proof,
                        std::vector<G1> const& com_s, 
                        std::vector<G1> const& com_a,
                        std::vector<int> const& trap);

    static void SellKey(h256_t seed, DeliverTuple & tpl, KeyProof& proof, G1 const& pk, 
                         G1 const& com_key, Fr const& key, Fr const& r_com_key);
    
    static void BuyKey(h256_t seed, DeliverTuple const& tpl, KeyProof const& proof,
                        G1 const& pk, G1 const& com_key, Fr const& sk);

    static bool TestModel();

    static bool TestEnv();

    static bool TestPod();

    static bool TestKey(uint m, uint n);

    static bool Test();
};

void FrozenLake::UpdateSeed(h256_t& seed, G1 const& a1, std::vector<G1> const& a2, 
                            std::vector<G1> const& a3, std::vector<G1> const& a4,
                            std::vector<G1> const& a5, std::vector<G1> const& a6){
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    HashUpdate(hash, a1);
    HashUpdate(hash, a2);
    HashUpdate(hash, a3);
    HashUpdate(hash, a4);
    HashUpdate(hash, a5);
    HashUpdate(hash, a6);
    hash.Final(seed.data());
}

template <typename ProofT>
void FrozenLake::UpdateSeed(h256_t& seed, ProofT const& proof) {
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    yas::mem_ostream os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
    oa.serialize(proof);
    auto buf = os.get_shared_buffer();
    HashUpdate(hash, buf.data.get(), buf.size);
    hash.Final(seed.data());
}

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

void FrozenLake::LoadAction(std::vector<std::vector<Fr>> &action){ //14 * 4
    Tick tick(__FN__);
    action.resize(14, std::vector<Fr>(4, 0));
    action[0][1] = 1;  //1
    action[1][2] = 1;  //2
    action[2][2] = 1;  //2
    action[3][2] = 1;  //2
    action[4][2] = 1;  //2
    action[5][2] = 1;  //2
    action[6][1] = 1;  //1
    action[7][2] = 1;  //2
    action[8][1] = 1;  //1
    action[9][1] = 1;  //1
    action[10][2] = 1; //2
    action[11][1] = 1; //1
    action[12][1] = 1; //1
    action[13][1] = 1; //1
}

void FrozenLake::LoadState(std::vector<std::vector<Fr>> &data){
    Tick tick(__FN__);
    size_t const D = 8, N = 24;
    circuit::fp::RationalConst<D, N> rationalConst;
    data.resize(14, std::vector<Fr>(64, 0));
    data[0][0] = rationalConst.kFrN;  //1
    data[1][8] = rationalConst.kFrN;  //2
    data[2][9] = rationalConst.kFrN;  //2
    data[3][10] = rationalConst.kFrN; //2
    data[4][11] = rationalConst.kFrN; //2
    data[5][12] = rationalConst.kFrN; //2
    data[6][13] = rationalConst.kFrN; //1
    data[7][21] = rationalConst.kFrN; //2
    data[8][22] = rationalConst.kFrN; //1
    data[9][30] = rationalConst.kFrN; //1
    data[10][38] = rationalConst.kFrN;//2
    data[11][39] = rationalConst.kFrN;//1
    data[12][47] = rationalConst.kFrN;//1
    data[13][55] = rationalConst.kFrN;//1
}

void FrozenLake::ComputeOutCom(ProveOutput & out) {
    if(out.is_row){
        out.com.resize(out.m());
        out.r_com.resize(out.m());
        auto parallel_f1 = [&out](int64_t i) {
            out.r_com[i] = FrRand();
            out.com[i] = pc::ComputeCom(pc::kGetRefG1, out.data[i], out.r_com[i]);
        };
        parallel::For(out.m(), parallel_f1);
    }else{
        out.com.resize(out.n());
        out.r_com.resize(out.n());
        auto parallel_f1 = [&out](int64_t i) {
            out.r_com[i] = FrRand();
            auto get_data = [&out, &i](int64_t j) -> Fr const& { return out.data[j][i]; };
            out.com[i] = pc::ComputeCom(out.data.size(), pc::kGetRefG1, get_data, out.r_com[i]);
        };
        parallel::For(out.n(), parallel_f1);
    } 
}

void FrozenLake::ComputeParaCom(ParaCommitmentPub& com_pub,
                             ParaCommitmentSec& com_sec, Para const& para) {
    Tick tick(__FN__);

    com_pub.dense1.resize(12);
    com_pub.dense2.resize(8);
    com_pub.dense3.resize(4);

    com_sec.r_dense1.resize(12);
    com_sec.r_dense2.resize(8);
    com_sec.r_dense3.resize(4);

    auto parallel_f1 = [&para, &com_sec, &com_pub](int64_t i) {
        com_sec.r_dense1[i] = FrRand();
        auto get_dense1 = [&para, &i](int64_t j) -> Fr const& { return para.dense1[j][i]; };
        com_pub.dense1[i] = pc::ComputeCom(para.m1(), pc::kGetRefG1, get_dense1, com_sec.r_dense1[i]);

        if(i < 8){
            com_sec.r_dense2[i] = FrRand();
            auto get_dense2 = [&para, &i](int64_t j) -> Fr const& { return para.dense2[j][i]; };
            com_pub.dense2[i] = pc::ComputeCom(para.m2(), pc::kGetRefG1, get_dense2, com_sec.r_dense2[i]);
        }
        
        if(i < 4){
            com_sec.r_dense3[i] = FrRand();
            auto get_dense3 = [&para, &i](int64_t j) -> Fr const& { return para.dense3[j][i]; };
            com_pub.dense3[i] = pc::ComputeCom(para.m3(), pc::kGetRefG1, get_dense3, com_sec.r_dense3[i]);
        }
    };

    parallel::For(12, parallel_f1);
}

void FrozenLake::ComputeReluWit(ProveOutput const& relu_in, ProveOutput & relu_out, MultiOutput & relu_data) {
    Tick tick(__FN__);

    libsnark::protoboard<Fr> pb;
    circuit::fixed_point::Relu2Gadget<8, 48, 24> gadget(pb, "Frozenlake gadget");

    int64_t k = relu_in.n(), m = pb.num_variables(), n = relu_in.m(), l = gadget.ret().index - 1;
    
    auto & d = relu_in.data;
    auto & com_d = relu_in.com;
    auto & r_com_d = relu_in.r_com;

    auto & w = relu_data.data;
    auto & com_w = relu_data.com;
    auto & r_com_w = relu_data.r_com;

    auto & v = relu_out.data;
    auto & com_v = relu_out.com;
    auto & r_com_v = relu_out.r_com;
   

    w.resize(k, std::vector<std::vector<Fr>>(m, std::vector<Fr>(n)));
    r_com_w.resize(k, std::vector<Fr>(m));
    com_w.resize(k, std::vector<G1>(m));

    auto parallel_f1 = [&d, &w](int64_t i) {
        libsnark::protoboard<Fr> pb;
        circuit::fixed_point::Relu2Gadget<8, 48, 24> gadget(pb, "Frozenlake gadget");
        int64_t row = i / d[0].size(), col = i % d[0].size();
        gadget.Assign(d[row][col]);
        CopyRowToLine(w[col], pb.full_variable_assignment(), row);
    };
    parallel::For(d.size()*d[0].size(), parallel_f1);

    auto parallel_f2 = [&w, &com_w, &r_com_w, &d, &com_d, &r_com_d](int64_t i) {
        int64_t row = i / w[0].size(), col = i % w[0].size();
        if(col == 0){
            r_com_w[row][col] = r_com_d[row];
            com_w[row][col] = com_d[row];
        }else{
            r_com_w[row][col] = FrRand();
            com_w[row][col] = pc::ComputeCom(w[row][col], r_com_w[row][col]);
        }
    }; 
    parallel::For(k * m, parallel_f2);

    auto parallel_f3 = [&w, &com_w, &r_com_w, &v, &com_v, &r_com_v, &l](int64_t i) {
        CopyRowToLine(v, w[i][l], i);
        com_v[i] = com_w[i][l];
        r_com_v[i] = r_com_w[i][l];
    }; 
    parallel::For(k, parallel_f3);
}


void FrozenLake::ComputeMaxWit(ProveOutput const& in, ProveOutput const& action, ProveOutput & max_data) {
    Tick tick(__FN__);

    libsnark::protoboard<Fr> pb;
    circuit::fixed_point::Max2Gadget<8, 48> gadget(pb, in.n(), "Frozenlake Max2Gadget");

    int64_t m = pb.num_variables(), n = in.m(), l = gadget.ret().index - 1;

    auto & d = in.data;
    auto & com_d = in.com;
    auto & r_com_d = in.r_com;

    auto & w = max_data.data;
    auto & com_w = max_data.com;
    auto & r_com_w = max_data.r_com;

    auto & v = action.data;
    auto & com_v = action.com;
    auto & r_com_v = action.r_com;
    
    w.resize(m, std::vector<Fr>(n));
    r_com_w.resize(m);
    com_w.resize(m);

    auto parallel_f1 = [&d, &w](int64_t i) {
        libsnark::protoboard<Fr> pb;
        circuit::fixed_point::Max2Gadget<8, 48> gadget(pb, d[0].size(), "Frozenlake Max2Gadget");
        gadget.Assign(d[i]);
        CopyRowToLine(w, pb.full_variable_assignment(), i);
    };
    parallel::For(n, parallel_f1);

    auto parallel_f2 = [&w, &com_w, &r_com_w, &d, &com_d, &r_com_d, &com_v, &r_com_v, &l](int64_t i) {
        if(i < com_d.size()){
            r_com_w[i] = r_com_d[i];
            com_w[i] = com_d[i];
        }else if(i < l + 5){
            r_com_w[i] = r_com_v[i - l];
            com_w[i] = com_v[i - l];
        }else{
            r_com_w[i] = FrRand();
            com_w[i] = pc::ComputeCom(pc::kGetRefG1, w[i], r_com_w[i]);
        }
    }; 
    parallel::For(m, parallel_f2);
}

void FrozenLake::ComputeEnvWit(ProveOutput const& state, ProveOutput const& action, 
                               std::vector<int> const& trap, ProveOutput & env_data) {
    libsnark::protoboard<Fr> pb;
    circuit::frozenlake::EnvGadget<8, 24> gadget(pb, state.n(), action.n(), trap, "Frozenlake EnvGadget");
    
    circuit::fixed_point::RationalConst<8, 24> rationalConst;

    int64_t m = pb.num_variables(), n = state.m();

    auto & s = state.data;
    auto & com_s = state.com;
    auto & r_com_s = state.r_com;

    auto & a = action.data;
    auto & com_a = action.com;
    auto & r_com_a = action.r_com;

    auto & w = env_data.data;
    auto & com_w = env_data.com;
    auto & r_com_w = env_data.r_com;

    w.resize(m, std::vector<Fr>(n));
    r_com_w.resize(m);
    com_w.resize(m);

    auto parallel_f1 = [&w, &s, &a, &trap](int64_t i) {
        libsnark::protoboard<Fr> pb;
        circuit::frozenlake::EnvGadget<8, 24> gadget(pb, s[0].size(), a[0].size(), trap, "Frozenlake EnvGadget");

        gadget.Assign(s[i], a[i]);
        CopyRowToLine(w, pb.full_variable_assignment(), i);
    };
    parallel::For(n, parallel_f1);

    auto parallel_f2 = [&w, &com_w, &r_com_w, &com_s, &r_com_s, &com_a, &r_com_a](int64_t i) {
        if(i < com_s.size()){
            r_com_w[i] = r_com_s[i];
            com_w[i] = com_s[i];
        }else if(i < com_a.size() + com_s.size()){
            r_com_w[i] = r_com_a[i - com_s.size()];
            com_w[i] = com_a[i - com_s.size()];
        }else{
            r_com_w[i] = FrRand();
            com_w[i] = pc::ComputeCom(w[i], r_com_w[i]);
        }
    }; 
    parallel::For(m, parallel_f2);
}


void FrozenLake::ComputeMimcWit(Fr const& key, ProveOutput const& in, ProveOutput & mimc_data) {
    libsnark::protoboard<Fr> pb;
    circuit::Mimc5Gadget mimc_gadget(pb, "Mimc5Gadget");

    int64_t m = pb.num_variables(), n = in.n();

    auto & d = in.data;
    auto & com_d = in.com;
    auto & r_com_d = in.r_com;

    auto & w = mimc_data.data;
    auto & com_w = mimc_data.com;
    auto & r_com_w = mimc_data.r_com;

    w.resize(m, std::vector<Fr>(n));
    r_com_w.resize(m);
    com_w.resize(m);

    auto parallel_f1 = [&w, &d, &key](int64_t i) {
        libsnark::protoboard<Fr> pb;
        circuit::Mimc5Gadget gadget(pb, "Mimc5Gadget");
        gadget.Assign(i, key); //ctr模式, i是计数器
        CopyRowToLine(w, pb.full_variable_assignment(), i);
    };
    parallel::For(n, parallel_f1);

    FrRand(r_com_w);
    r_com_w[0] = 0;
    
    auto parallel_f = [&w, &com_w, &r_com_w, &com_d, &r_com_d](int64_t i) {
        com_w[i] = pc::ComputeCom(w[i], r_com_w[i]);
    }; 
    parallel::For(m, parallel_f);
}


// for prove max
void FrozenLake::BuildHpCom(libsnark::protoboard<Fr> const& pb,
                            ProveOutput const& out,
                            libra::A1::ProveInput & input,
                            libra::A1::CommitmentPub & com_pub,
                            libra::A1::CommitmentSec & com_sec){
    int64_t m = out.m(), n = out.n(), new_m = pb.num_constraints();

    auto & w = out.data;
    auto & com_w = out.com;
    auto & r_com_w = out.r_com;
    
    auto & com_a = com_pub.a;
    auto & com_b = com_pub.b;
    auto & com_c = com_pub.c;
    com_a.resize(new_m, G1Zero());
    com_b.resize(new_m, G1Zero());
    com_c.resize(new_m, G1Zero());
    
    auto & r_com_a = com_sec.alpha;
    auto & r_com_b = com_sec.beta;
    auto & r_com_c = com_sec.theta;
    r_com_a.resize(new_m, FrZero());
    r_com_b.resize(new_m, FrZero());
    r_com_c.resize(new_m, FrZero());

    auto & a = input.a;
    auto & b = input.b;
    auto & c = input.c;
    a.resize(new_m, std::vector<Fr>(n, FrZero()));
    b.resize(new_m, std::vector<Fr>(n, FrZero()));
    c.resize(new_m, std::vector<Fr>(n, FrZero()));

    auto pds_sigma_g = pc::ComputeSigmaG(pc::kGetRefG1, n);
    auto parallel_f = [&pb, &w, &com_w, &r_com_w, &a, &com_a, &r_com_a, &b, &com_b, &r_com_b, &c, &com_c, &r_com_c, &pds_sigma_g](int64_t i) {
        BuildHpCom(w, com_w, r_com_w, pb.get_constraint_system().constraints[i].a, a[i], com_a[i], r_com_a[i], pds_sigma_g);
        BuildHpCom(w, com_w, r_com_w, pb.get_constraint_system().constraints[i].b, b[i], com_b[i], r_com_b[i], pds_sigma_g);
        BuildHpCom(w, com_w, r_com_w, pb.get_constraint_system().constraints[i].c, c[i], com_c[i], r_com_c[i], pds_sigma_g);
        // assert(HadamardProduct(a[i], b[i]) == c[i]);
        // assert(pc::ComputeCom(a[i], r_com_a[i]) == com_a[i]);
        // assert(pc::ComputeCom(b[i], r_com_b[i]) == com_b[i]);
        // assert(pc::ComputeCom(c[i], r_com_c[i]) == com_c[i]);
    };
    parallel::For(new_m, parallel_f);
}


// for prove relu
void FrozenLake::BuildHpCom(libsnark::protoboard<Fr> const& pb,
                            MultiOutput const& mult_out,
                            libra::A3::ProveInput & mult_input,
                            libra::A3::CommitmentPub & mult_com_pub,
                            libra::A3::CommitmentSec & mult_com_sec){

    int64_t k = mult_out.k(), m = mult_out.m(), n = mult_out.n(), new_m = pb.num_constraints();

    auto pds_sigma_g = pc::ComputeSigmaG(pc::kGetRefG1, n);

    auto & w = mult_out.data;
    auto & com_w = mult_out.com;
    auto & r_com_w = mult_out.r_com;
    
    auto & com_a = mult_com_pub.a;
    auto & com_b = mult_com_pub.b;
    auto & com_c = mult_com_pub.c;
    com_a.resize(k, std::vector<G1>(new_m, G1Zero()));
    com_b.resize(k, std::vector<G1>(new_m, G1Zero()));
    com_c.resize(k, std::vector<G1>(new_m, G1Zero()));

    auto & r_com_a = mult_com_sec.alpha;
    auto & r_com_b = mult_com_sec.beta;
    auto & r_com_c = mult_com_sec.theta;
    r_com_a.resize(k, std::vector<Fr>(new_m, FrZero()));
    r_com_b.resize(k, std::vector<Fr>(new_m, FrZero()));
    r_com_c.resize(k, std::vector<Fr>(new_m, FrZero()));

    auto & a = mult_input.a;
    auto & b = mult_input.b;
    auto & c = mult_input.c;
    a.resize(k, std::vector<std::vector<Fr>>(new_m, std::vector<Fr>(n, FrZero())));
    b.resize(k, std::vector<std::vector<Fr>>(new_m, std::vector<Fr>(n, FrZero())));
    c.resize(k, std::vector<std::vector<Fr>>(new_m, std::vector<Fr>(n, FrZero())));

    auto parallel_f = [&pb, &w, &com_w, &r_com_w, &a, &com_a, &r_com_a, &b, &com_b, &r_com_b, &c, &com_c, &r_com_c, &pds_sigma_g](int64_t i) {
        int64_t row = i / w.size(), col = i % w.size();
        BuildHpCom(w[col], com_w[col], r_com_w[col], pb.get_constraint_system().constraints[row].a, a[col][row], com_a[col][row], r_com_a[col][row], pds_sigma_g);
        BuildHpCom(w[col], com_w[col], r_com_w[col], pb.get_constraint_system().constraints[row].b, b[col][row], com_b[col][row], r_com_b[col][row], pds_sigma_g);
        BuildHpCom(w[col], com_w[col], r_com_w[col], pb.get_constraint_system().constraints[row].c, c[col][row], com_c[col][row], r_com_c[col][row], pds_sigma_g);
    };
    parallel::For(new_m * k, parallel_f);
}

// for prove
void FrozenLake::BuildHpCom(std::vector<std::vector<Fr>> const& w, //s*n
                         std::vector<G1> const &com_w, //s
                         std::vector<Fr> const &com_w_r, //s
                         libsnark::linear_combination<Fr> const &lc,
                         std::vector<Fr> &data, G1 &com_pub, Fr &com_sec, G1 const &sigma_g) { //m*n, m, m
    // Tick tick(__FN__);
    for (auto const &term : lc.terms) {
      if (term.coeff == FrZero()) continue;
      if (term.coeff == FrOne()) {
        if (term.index == 0) {  // constants
          com_pub += sigma_g;
          VectorInc(data, FrOne());
        } else {
          com_pub += com_w[term.index - 1];
          com_sec += com_w_r[term.index - 1];
          VectorInc(data, w[term.index - 1]);
        }
      } else {
        if (term.index == 0) {  // constants
          com_pub += sigma_g * term.coeff;
          VectorInc(data, FrOne() * term.coeff);
        } else {
          com_pub += com_w[term.index - 1] * term.coeff;
          com_sec += com_w_r[term.index - 1] * term.coeff;
          VectorInc(data, w[term.index - 1] * term.coeff);
        }
      }
    }
}

// for verify max
void FrozenLake::BuildHpCom(libsnark::protoboard<Fr> const& pb,
                            int64_t const& n,
                            std::vector<G1> const& com_w,
                            libra::A1::CommitmentPub & com_pub){
    int64_t m = com_w.size(), new_m = pb.num_constraints();

    auto pds_sigma_g = pc::ComputeSigmaG(pc::kGetRefG1, n);
    
    auto & com_a = com_pub.a;
    auto & com_b = com_pub.b;
    auto & com_c = com_pub.c;
    com_a.resize(new_m, G1Zero());
    com_b.resize(new_m, G1Zero());
    com_c.resize(new_m, G1Zero());

    auto parallel_f = [&pb, &com_w, &com_a, &com_b, &com_c, &pds_sigma_g](int64_t i) {
        BuildHpCom(com_w, pb.get_constraint_system().constraints[i].a, com_a[i], pds_sigma_g);
        BuildHpCom(com_w, pb.get_constraint_system().constraints[i].b, com_b[i], pds_sigma_g);
        BuildHpCom(com_w, pb.get_constraint_system().constraints[i].c, com_c[i], pds_sigma_g);
    };
    parallel::For(new_m, parallel_f);
}


// for verify relu
void FrozenLake::BuildHpCom(libsnark::protoboard<Fr> const& pb,
                            int64_t const& n,
                            std::vector<std::vector<G1>> const& com_w,
                            libra::A3::CommitmentPub & com_pub){

    int64_t k = com_w.size(), m = com_w[0].size(), new_m = pb.num_constraints();

    auto pds_sigma_g = pc::ComputeSigmaG(pc::kGetRefG1, n);
    
    auto & com_a = com_pub.a; 
    auto & com_b = com_pub.b;
    auto & com_c = com_pub.c;

    com_a.resize(k, std::vector<G1>(new_m, G1Zero()));
    com_b.resize(k, std::vector<G1>(new_m, G1Zero()));
    com_c.resize(k, std::vector<G1>(new_m, G1Zero()));

    auto parallel_f = [&pb, &com_w, &com_a, &com_b, &com_c, &pds_sigma_g](int64_t i) {
        int64_t row = i / com_w.size(), col = i % com_w.size();
        BuildHpCom(com_w[col], pb.get_constraint_system().constraints[row].a, com_a[col][row], pds_sigma_g);
        BuildHpCom(com_w[col], pb.get_constraint_system().constraints[row].b, com_b[col][row], pds_sigma_g);
        BuildHpCom(com_w[col], pb.get_constraint_system().constraints[row].c, com_c[col][row], pds_sigma_g);
    };
    parallel::For(new_m * k, parallel_f);
}

// for verify
void FrozenLake::BuildHpCom(std::vector<G1> const &com_w, //s
                            libsnark::linear_combination<Fr> const &lc,
                            G1 &com_pub, G1 const &sigma_g) { //m*n, m, m
    // Tick tick(__FN__);
    for (auto const &term : lc.terms) {
      if (term.coeff == FrZero()) continue;
      if (term.coeff == FrOne()) {
        if (term.index == 0) {  // constants
          com_pub += sigma_g;
        } else {
          com_pub += com_w[term.index - 1];
        }
      } else {
        if (term.index == 0) {  // constants
          com_pub += sigma_g * term.coeff;
        } else {
          com_pub += com_w[term.index - 1] * term.coeff;
        }
      }
    }
}

void FrozenLake::AddCol(std::vector<G1> & a, int64_t m){
    circuit::fp::RationalConst<8, 24> rationalConst;
    G1 pds_sigma_g = pc::ComputeSigmaG(pc::kGetRefG1, m) * rationalConst.kFrN;
    a.resize(a.size()+1, pds_sigma_g);
}

void FrozenLake::AddCol(ProveOutput & out){
    circuit::fp::RationalConst<8, 24> rationalConst;

    int64_t n = out.n() + 1;
    auto parallel_f = [&out, &rationalConst, &n](int64_t i) {
        out.data[i].resize(n, rationalConst.kFrN);
    };
    parallel::For(out.m(), parallel_f); 

    G1 pds_sigma_g = pc::ComputeSigmaG(pc::kGetRefG1, out.m()) * rationalConst.kFrN;
    out.com.resize(n, pds_sigma_g);
    out.r_com.resize(n, 0);
}

// void FrozenLake::KeyTrade(h256_t seed)

void FrozenLake::KeyProve(h256_t seed, KeyProof & proof, KeyProveInput const& input, 
                          KeyCommitmentPub const& com_pub, KeyCommitmentSec const& com_sec){
    Tick tick(__FN__);
    int m = input.m(), n = input.n();

    if(DEBUG_CHECK){
        assert(pc::ComputeCom(input.k, com_sec.r_com_k) == com_pub.com_k);
        for(int i=0; i<input.m(); i++){
            assert(pc::ComputeCom(input.bits[i], com_sec.r_com_bits[i]) == com_pub.com_bits[i]);
        }
        for(int i=0; i<input.n(); i++){
            assert(pc::kGetRefG1(0) * com_sec.r_enc_sub_keys[i] == com_pub.enc_sub_keys1[i]);
            assert(input.pk * com_sec.r_enc_sub_keys[i] + pc::kGetRefG1(0) * input.sub_keys[i] == com_pub.enc_sub_keys2[i]);
        }
    }
    
    std::vector<Fr> sum_d(n);
    std::vector<std::vector<Fr>> d(m, std::vector<Fr>(n)), b(m, std::vector<Fr>(n)), c(m, std::vector<Fr>(n));
    Fr ad = 0;
    for(int i=0; i<m; i++) {
        FrRand(d[i]);
        sum_d += d[i] * input.a[i][0];
        ad += InnerProduct(input.a[i], d[i]);
        b[i] = HadamardProduct(d[i], d[i]);
        c[i] = HadamardProduct(d[i], input.bits[i]) * Fr(2) - d[i];
    }

    Fr r_com_ad = FrRand();
    std::vector<Fr> r_com_d(m), r_com_b(m), r_com_c(m), r_enc_sum_d(n);
    FrRand(r_com_d);
    FrRand(r_com_b);
    FrRand(r_com_c);
    FrRand(r_enc_sum_d);

    G1 com_ad = pc::ComputeCom(ad, r_com_ad);
    std::vector<G1> com_b(m), com_c(m), com_d(m), enc_sum_d1(n), enc_sum_d2(n);
    for(int i=0; i<m; i++){
        com_b[i] = pc::ComputeCom(b[i], r_com_b[i]);
        com_c[i] = pc::ComputeCom(c[i], r_com_c[i]);
        com_d[i] = pc::ComputeCom(d[i], r_com_d[i]);
    }

    for(int i=0; i<n; i++){
        enc_sum_d1[i] = pc::kGetRefG1(0) * r_enc_sum_d[i];
        enc_sum_d2[i] = input.pk * r_enc_sum_d[i] + pc::kGetRefG1(0) * sum_d[i];
    }

    UpdateSeed(seed, com_ad, com_b, com_c, com_d, enc_sum_d1, enc_sum_d2);
    Fr e = H256ToFr(seed);

    proof.z.resize(m, std::vector<Fr>(n));
    proof.r_com_z.resize(m);
    proof.r_enc_z.resize(n);
    proof.r_com_eta.resize(m);
    for(int i=0; i<m; i++){
        proof.z[i] = d[i] + input.bits[i] * e;
        proof.r_com_z[i] = r_com_d[i] + com_sec.r_com_bits[i] * e;
        proof.r_com_eta[i] = r_com_b[i] + r_com_c[i] * e;
    }
    for(int i=0; i<n; i++){
        proof.r_enc_z[i] = r_enc_sum_d[i] + com_sec.r_enc_sub_keys[i] * e;
    }
    proof.r_com_zeta = r_com_ad + com_sec.r_com_k * e;

    // Fr t = 0;
    // std::vector<Fr> sum_z(n, 0);
    // for(int i=0; i<m; i++){
    //     t += InnerProduct(input.a[i], proof.z[i]);
    //     sum_z +=  proof.z[i] * input.a[i][0];
    //     assert(com_d[i] + com_pub.com_bits[i] * e == pc::ComputeCom(proof.z[i], proof.r_com_z[i]));
    //     assert(com_b[i] + com_c[i] * e == pc::ComputeCom(HadamardProduct(proof.z[i], proof.z[i]) - proof.z[i] * e, proof.r_com_eta[i]));
    // }
    // assert(com_ad + com_pub.com_k * e == pc::ComputeCom(t, proof.r_com_zeta));

    // for(int i=0; i<n; i++){
    //     assert(enc_sum_d1[i] + com_pub.enc_sub_keys1[i] * e == pc::kGetRefG1(0) * proof.r_enc_z[i]);
    //     assert(enc_sum_d2[i] + com_pub.enc_sub_keys2[i] * e == input.pk * proof.r_enc_z[i] + pc::kGetRefG1(0) * sum_z[i]);
    // }
    
    proof.com_ad = com_ad;
    proof.com_b = std::move(com_b);
    proof.com_c = std::move(com_c);
    proof.com_d = std::move(com_d);
    proof.enc_sum_d1 = std::move(enc_sum_d1);
    proof.enc_sum_d2 = std::move(enc_sum_d2);

    // G1 enc_left1 = enc_a1 + com_pub.enc_k1 * e;
    // G1 enc_right1 = input.enc_base * r_enc_z;
}

bool FrozenLake::KeyVerify(h256_t seed, KeyProof const& proof, KeyVerifyInput const& input){
    int m = input.m(), n = input.n();
    UpdateSeed(seed, proof.com_ad, proof.com_b, proof.com_c, proof.com_d, proof.enc_sum_d1, proof.enc_sum_d2);
    bool ret = true;
    Fr t = 0;
    Fr e = H256ToFr(seed);
    std::vector<Fr> sum_z(n, 0);
    auto &com_pub = input.com_pub;
    for(int i=0; i<m; i++){
        t += InnerProduct(input.a[i], proof.z[i]);
        sum_z +=  proof.z[i] * input.a[i][0];
        ret = ret && (proof.com_d[i] + com_pub.com_bits[i] * e == pc::ComputeCom(proof.z[i], proof.r_com_z[i]));
        ret = ret && (proof.com_b[i] + proof.com_c[i] * e == pc::ComputeCom(HadamardProduct(proof.z[i], proof.z[i]) - proof.z[i] * e, proof.r_com_eta[i]));
    }
    ret = ret && (proof.com_ad + com_pub.com_k * e == pc::ComputeCom(t, proof.r_com_zeta));

    for(int i=0; i<n; i++){
        ret = ret && (proof.enc_sum_d1[i] + com_pub.enc_sub_keys1[i] * e == pc::kGetRefG1(0) * proof.r_enc_z[i]);
        ret = ret && (proof.enc_sum_d2[i] + com_pub.enc_sub_keys2[i] * e == input.pk * proof.r_enc_z[i] + pc::kGetRefG1(0) * sum_z[i]);
    }
    return ret;
}

void FrozenLake::PodProve(h256_t seed, DeliverTuple &tpl, PodProof& proof, ProveOutput const& in, Fr const& key){
    Tick tick(__FN__);
    libsnark::protoboard<Fr> pb;
    circuit::Mimc5Gadget mimc_gadget(pb, "Mimc5Gadget");

    //计算witness
    ProveOutput mimc_data;
    ComputeMimcWit(key, in, mimc_data);

    //R1CS证明
    libra::A1::ProveInput enc_input(pc::kGetRefG1);
    libra::A1::CommitmentPub enc_com_pub;
    libra::A1::CommitmentSec enc_com_sec;
    BuildHpCom(pb, mimc_data, enc_input, enc_com_pub, enc_com_sec);
    libra::A1::Prove(proof.enc_proof, seed, enc_input, enc_com_pub, enc_com_sec);

    auto & msgcipher = tpl.cipher;
    auto & r_com_msgcipher = tpl.r_com_cipher;

    auto & msg = in.data[0];
    auto & r_com_msg = in.r_com[0];
    
    auto & ctr = mimc_data.data[mimc_data.data.size() - 1];
    auto & r_com_ctr = mimc_data.r_com[mimc_data.r_com.size() - 1];

    auto & com_key = mimc_data.com[1];
    auto & r_com_key = mimc_data.r_com[1];

    msgcipher = ctr + msg; //对消息加密
    r_com_msgcipher = r_com_ctr + r_com_msg;

    proof.com_mimc = std::move(mimc_data.com);
}

void FrozenLake::EnvProve(h256_t seed, EnvProof& proof,
                        ProveOutput const& state, 
                        ProveOutput const& action,
                        std::vector<int> const& trap){
    Tick tick(__FN__);
    libsnark::protoboard<Fr> pb;
    circuit::frozenlake::EnvGadget<8, 24> gadget(pb, state.n(), action.n(), trap, "Frozenlake EnvGadget");

    circuit::fixed_point::RationalConst<8, 24> rationalConst;

    int64_t l1 = gadget.InState().index - 1, l2 = gadget.OutState().index - 1;

    ProveOutput env_data;
    ComputeEnvWit(state, action, trap, env_data);

    libra::A1::ProveInput env_input(pc::kGetRefG1);
    libra::A1::CommitmentPub env_com_pub;
    libra::A1::CommitmentSec env_com_sec;
    BuildHpCom(pb, env_data, env_input, env_com_pub, env_com_sec);
    libra::A1::Prove(proof.env_proof, seed, env_input, env_com_pub, env_com_sec);

    G1 com_x = env_data.com[l1], com_y = env_data.com[l2] - (pc::kGetRefG1(state.m()-1) * ((state.n() - 1) * rationalConst.kFrN));
    
    int64_t gx_offset = 1, gy_offset = 0;
    GetRefG1 get_gx = [gx_offset](int64_t i) -> G1 const& {
        return pc::PcG()[gx_offset + i];
    };
    GetRefG1 get_gy = [gy_offset](int64_t i) -> G1 const& {
        return pc::PcG()[gy_offset + i];
    };

    std::vector<Fr> x(env_data.data[l2].begin(), env_data.data[l2].end()-1);

    // std::cout << "eq input:\n";
    // misc::PrintVector(x * rationalConst.kFrN.inverse());

    //状态的相同
    clink::Equality3::ProveInput eq_input(x, get_gx, get_gy);
    clink::Equality3::CommitmentPub eq_com_pub(com_x, com_y);
    clink::Equality3::CommitmentSec eq_com_sec(env_data.r_com[l1], env_data.r_com[l2]);
    clink::Equality3::Prove(proof.eq_proof, seed, eq_input, eq_com_pub, eq_com_sec);

    proof.com_env = std::vector<G1>(env_data.com.begin() + state.n() + action.n(), env_data.com.end());

    // std::cout << "in state:\n";
    // misc::PrintVector(env_data.data[l1] * rationalConst.kFrN.inverse());
    // std::cout << "out state:\n";
    // misc::PrintVector(env_data.data[l2] * rationalConst.kFrN.inverse());
    // std::cout << "action:\n";
    // for(int i=0; i<14; i++){
    //     misc::PrintVector(action.data[i]);
    // }
}

// 对于一个prove, 要准备对应的proveinput, 包含: 承诺, 打开(承诺数据 + 随机数), 数据
void FrozenLake::ModelProve(h256_t seed, ModelProof& proof,
                    ProveOutput const& in,
                    ProveOutput const& action,
                    Para const& para,
                    ParaCommitmentPub const& para_com_pub,
                    ParaCommitmentSec const& para_com_sec) {
    Tick tick(__FN__);

    libsnark::protoboard<Fr> pb_max, pb_relu;
    circuit::fixed_point::Relu2Gadget<8, 48, 24> relu_gadget(pb_relu, "Frozenlake relu_gadget");
    circuit::fixed_point::Max2Gadget<8, 48> max_gadget(pb_max, 4, "Frozenlake max_gadget");

    // prove dense1
    ProveOutput dense1_in = in;
    AddCol(dense1_in);
   
    int64_t m = dense1_in.m(), k = dense1_in.n(), n = para.n1();

    ProveOutput dense1_out(m, n);
    MatrixMul(dense1_in.data, para.dense1, dense1_out.data); // 输出是<D, 2N>
    ComputeOutCom(dense1_out);

    libra::A2::ProveInput dense1_input(dense1_in.data, para.dense1, dense1_out.data, pc::kGetRefG1);
    libra::A2::CommitmentPub dense1_com_pub(dense1_in.com, para_com_pub.dense1, dense1_out.com);
    libra::A2::CommitmentSec dense1_com_sec(dense1_in.r_com, para_com_sec.r_dense1, dense1_out.r_com);
    libra::A2::Prove(proof.dense1_proof, seed, dense1_input, dense1_com_pub, dense1_com_sec);
    UpdateSeed(seed, proof.dense1_proof);

    // prove relu1
    MultiOutput relu1_data;
    ProveOutput relu1_out(m, n), &relu1_in = dense1_out;
    ComputeReluWit(relu1_in, relu1_out, relu1_data);

    libra::A3::ProveInput relu1_input(pc::kGetRefG1);
    libra::A3::CommitmentPub relu1_com_pub;
    libra::A3::CommitmentSec relu1_com_sec; 
    BuildHpCom(pb_relu, relu1_data, relu1_input, relu1_com_pub, relu1_com_sec);
    libra::A3::Prove(proof.relu1_proof, seed, relu1_input, relu1_com_pub, relu1_com_sec);
    UpdateSeed(seed, proof.relu1_proof);
    proof.relu1_in_com = std::move(relu1_data.com);

    // prove dense2
    ProveOutput &dense2_in = relu1_out;
    AddCol(dense2_in);
    m = dense2_in.m();  k = dense2_in.n();  n = para.n2();

    ProveOutput dense2_out(m, n);
    MatrixMul(dense2_in.data, para.dense2, dense2_out.data); 
    ComputeOutCom(dense2_out);

    libra::A2::ProveInput dense2_input(dense2_in.data, para.dense2, dense2_out.data, pc::kGetRefG1);
    libra::A2::CommitmentPub dense2_com_pub(dense2_in.com, para_com_pub.dense2, dense2_out.com);
    libra::A2::CommitmentSec dense2_com_sec(dense2_in.r_com, para_com_sec.r_dense2, dense2_out.r_com);
    libra::A2::Prove(proof.dense2_proof, seed, dense2_input, dense2_com_pub, dense2_com_sec);
    UpdateSeed(seed, proof.dense2_proof);

    //prove relu2
    MultiOutput relu2_data;
    ProveOutput relu2_out(m, n), &relu2_in = dense2_out;
    ComputeReluWit(relu2_in, relu2_out, relu2_data);

    libra::A3::ProveInput relu2_input(pc::kGetRefG1);
    libra::A3::CommitmentPub relu2_com_pub;
    libra::A3::CommitmentSec relu2_com_sec; 
    BuildHpCom(pb_relu, relu2_data, relu2_input, relu2_com_pub, relu2_com_sec);
    libra::A3::Prove(proof.relu2_proof, seed, relu2_input, relu2_com_pub, relu2_com_sec);
    UpdateSeed(seed, proof.relu2_proof);
    proof.relu2_in_com = std::move(relu2_data.com);
 
    // prove dense3
    ProveOutput &dense3_in = relu2_out;
    AddCol(dense3_in);

    m = dense3_in.m();  k = dense3_in.n();  n = para.n3();

    ProveOutput dense3_out(m, n);
    MatrixMul(dense3_in.data, para.dense3, dense3_out.data); 
    ComputeOutCom(dense3_out);

    libra::A2::ProveInput dense3_input(dense3_in.data, para.dense3, dense3_out.data, pc::kGetRefG1);
    libra::A2::CommitmentPub dense3_com_pub(dense3_in.com, para_com_pub.dense3, dense3_out.com);
    libra::A2::CommitmentSec dense3_com_sec(dense3_in.r_com, para_com_sec.r_dense3, dense3_out.r_com);
    libra::A2::Prove(proof.dense3_proof, seed, dense3_input, dense3_com_pub, dense3_com_sec);
    UpdateSeed(seed, proof.dense3_proof);

    // max
    ProveOutput max_data;
    ProveOutput &max_in = dense3_out;
    ComputeMaxWit(max_in, action, max_data);
    libra::A1::ProveInput max_input(pc::kGetRefG1);
    libra::A1::CommitmentPub max_com_pub;
    libra::A1::CommitmentSec max_com_sec;
    BuildHpCom(pb_max, max_data, max_input, max_com_pub, max_com_sec);
    libra::A1::Prove(proof.max_proof, seed, max_input, max_com_pub, max_com_sec);
    UpdateSeed(seed, proof.max_proof);

    // std::cout << "action:\n";
    // misc::PrintVector(max_data.data[4]);

    // std::cout << "action one hot:\n";
    // misc::PrintVector(max_data.data[5]);
    // misc::PrintVector(max_data.data[6]);
    // misc::PrintVector(max_data.data[7]);
    // misc::PrintVector(max_data.data[8]);

    proof.final_in_com = std::vector<G1>(max_data.com.begin() + 9, max_data.com.end());
    proof.final_in_com.insert(proof.final_in_com.begin(), max_data.com.begin(), max_data.com.begin() + 4);
}

bool FrozenLake::ModelVerify(h256_t seed, ModelProof const& proof, VerifyInput const& input){
    Tick tick(__FN__);
    auto const& para_com_pub = input.para_com_pub;
    auto const& action_com_pub = input.action_com_pub;

    bool ret_dense1 = false, ret_dense2 = false, ret_dense3 = false;
    bool ret_relu1 = false, ret_relu2 = false, ret_max = false;

    libsnark::protoboard<Fr> pb_max, pb_relu;
    circuit::fixed_point::Relu2Gadget<8, 48, 24> relu_gadget(pb_relu, "Frozenlake relu_gadget");
    circuit::fixed_point::Max2Gadget<8, 48> max_gadget(pb_max, 4, "Frozenlake max_gadget");
    
    circuit::fp::RationalConst<8, 24> rationalConst;

    //verify dense1
    std::vector<G1> dense1_in = input.data_com_pub;
    AddCol(dense1_in, input.m());

    int64_t m = input.m(), k = input.n() + 1, n = input.n1();

    std::vector<G1> dense1_out(n);
    CopyLineToRow(proof.relu1_in_com, dense1_out, 0);

    libra::A2::CommitmentPub dense1_com_pub(dense1_in, para_com_pub.dense1, dense1_out);
    libra::A2::VerifyInput dense1_verify_input(m, k, n, dense1_com_pub, input.get_g);
    ret_dense1 = libra::A2::Verify(proof.dense1_proof, seed, dense1_verify_input);
    UpdateSeed(seed, proof.dense1_proof);

    //verify relu1
    auto const& relu1_in = proof.relu1_in_com;
    libra::A3::CommitmentPub relu1_com_pub;
    BuildHpCom(pb_relu, m, relu1_in, relu1_com_pub);
    libra::A3::VerifyInput relu1_verify_input(relu1_com_pub.k(), relu1_com_pub.m(), m, relu1_com_pub, pc::kGetRefG1);
    ret_relu1 = libra::A3::Verify(proof.relu1_proof, seed, relu1_verify_input);
    UpdateSeed(seed, proof.relu1_proof);
    
    //verify dense2
    std::vector<G1> dense2_in, dense2_out;
    CopyLineToRow(proof.relu1_in_com, dense2_in, 1);
    CopyLineToRow(proof.relu2_in_com, dense2_out, 0);
    AddCol(dense2_in, m);
                                      
    m = m; k = n+1; n = input.n2();
    libra::A2::CommitmentPub dense2_verify_com(dense2_in, para_com_pub.dense2, dense2_out);
    libra::A2::VerifyInput dense2_verify_input (m, k, n, dense2_verify_com, input.get_g);
    ret_dense2 = libra::A2::Verify(proof.dense2_proof, seed, dense2_verify_input);
    UpdateSeed(seed, proof.dense2_proof);

    //verify relu2
    auto const& relu2_in = proof.relu2_in_com;
    libra::A3::CommitmentPub relu2_com_pub;
    BuildHpCom(pb_relu, m, relu2_in, relu2_com_pub);
    libra::A3::VerifyInput relu2_verify_input(relu2_com_pub.k(), relu2_com_pub.m(), m, relu2_com_pub, pc::kGetRefG1);
    ret_relu2 = libra::A3::Verify(proof.relu2_proof, seed, relu2_verify_input);
    UpdateSeed(seed, proof.relu2_proof);

    //verify dense3
    std::vector<G1> dense3_in, dense3_out(proof.final_in_com.begin(), proof.final_in_com.begin()+4);
    CopyLineToRow(proof.relu2_in_com, dense3_in, 1);
    AddCol(dense3_in, m);
    m = m; k = n+1; n = input.n3();

    libra::A2::CommitmentPub dense3_verify_com(dense3_in, para_com_pub.dense3, dense3_out);
    libra::A2::VerifyInput dense3_verify_input (m, k, n, dense3_verify_com, input.get_g);
    ret_dense3 = libra::A2::Verify(proof.dense3_proof, seed, dense3_verify_input);
    UpdateSeed(seed, proof.dense3_proof);

    //verify max
    auto max_in = proof.final_in_com;
    max_in.insert(max_in.begin()+4, action_com_pub.begin(), action_com_pub.end());

    libra::A1::CommitmentPub max_com_pub;
    BuildHpCom(pb_max, m, max_in, max_com_pub);
    libra::A1::VerifyInput max_verify_input(max_com_pub.m(), m, max_com_pub, pc::kGetRefG1, pc::kGetRefG1(0));
    ret_max = libra::A1::Verify(proof.max_proof, seed, max_verify_input);

    if(!(ret_dense1 && ret_dense2 && ret_dense3 && ret_relu1 && ret_relu2 && ret_max)){
        std::cout << ret_dense1 << "\t" << ret_relu1 << "\t" << ret_dense2 << "\t" << ret_relu2 << "\t" << ret_dense3 <<"\t" << ret_max << "\n";
        return false;
    }
    return true;
}

bool FrozenLake::EnvVerify(h256_t seed, EnvProof const& proof,
                        std::vector<G1> const& com_s, 
                        std::vector<G1> const& com_a,
                        std::vector<int> const& trap){
    Tick tick(__FN__);

    libsnark::protoboard<Fr> pb;
    circuit::frozenlake::EnvGadget<8, 24> gadget(pb, 64, 4, trap, "Frozenlake EnvGadget");

    circuit::fixed_point::RationalConst<8, 24> rationalConst;

    bool ret1 = false, ret2 = false;

    int64_t m = 14, n = com_s.size(), l1 = gadget.InState().index - 1, l2 = gadget.OutState().index - 1;
    std::vector<G1> com_env = proof.com_env;

    com_env.insert(com_env.begin(), com_a.begin(), com_a.end());
    com_env.insert(com_env.begin(), com_s.begin(), com_s.end());
    
    libra::A1::CommitmentPub env_com_pub;
    BuildHpCom(pb, m, com_env, env_com_pub);

    libra::A1::VerifyInput env_verify_input(env_com_pub.m(), m, env_com_pub, pc::kGetRefG1, pc::kGetRefG1(0));
    ret1 = libra::A1::Verify(proof.env_proof, seed, env_verify_input);

    int64_t gx_offset = 1, gy_offset = 0;
    GetRefG1 get_gx = [gx_offset](int64_t i) -> G1 const& {
        return pc::PcG()[gx_offset + i];
    };
    GetRefG1 get_gy = [gy_offset](int64_t i) -> G1 const& {
        return pc::PcG()[gy_offset + i];
    };

    G1 com_x =com_env[l1], com_y = com_env[l2] - pc::kGetRefG1(m-1) * ((n-1) * rationalConst.kFrN);
    
    clink::Equality3::CommitmentPub eq_com_pub(com_x, com_y);
    clink::Equality3::VerifyInput eq_input(m-1, eq_com_pub, get_gx, get_gy);
    ret2 = clink::Equality3::Verify(proof.eq_proof, seed, eq_input);

    if(!(ret1 && ret2)){
        std::cout << "ret:" << ret1 << "\t" << ret2 << "\n";
        return false;
    }

    return true;
}

bool FrozenLake::PodVerify(h256_t seed, DeliverTuple const& tpl, PodProof const& proof,
                            std::vector<G1> const& com_in, int64_t const& n){
    Tick tick(__FN__);
    libsnark::protoboard<Fr> pb;
    circuit::Mimc5Gadget mimc_gadget(pb, "Mimc5Gadget");

    auto const& com_enc = proof.com_mimc;
    libra::A1::CommitmentPub enc_com_pub;
    BuildHpCom(pb, n, com_enc, enc_com_pub); //验证加密的正确性

    bool ret = true;
    
    std::vector<Fr> ctr(n);
    std::iota(ctr.begin(), ctr.end(), 0);
    ret = ret && (pc::ComputeCom(ctr, 0) == com_enc[0]); //验证计数器的正确性

    G1 com_cipher = com_enc[com_enc.size() - 1] + com_in[0];
    ret = ret && (pc::ComputeCom(tpl.cipher, tpl.r_com_cipher) == com_cipher); //验证密文的正确性

    libra::A1::VerifyInput enc_verify_input(enc_com_pub.m(), n, enc_com_pub, pc::kGetRefG1, pc::kGetRefG1(0));
    ret = ret && libra::A1::Verify(proof.enc_proof, seed, enc_verify_input); //验证加密的正确性

    return ret;
}

bool FrozenLake::TestPod() {
    Tick tick(__FN__);

    DeliverTuple tpl;

    ProveOutput action(1, 14, true); //row
    action.data[0] = {
        1, 2, 2, 2, 2, 2, 1, 2, 1, 1, 2, 1, 1, 1
    };
    ComputeOutCom(action); //列承诺

    auto seed = misc::RandH256();
    
    Fr key = FrRand();
    
    PodProof proof;
    PodProve(seed, tpl, proof, action, key);

#ifndef DISABLE_SERIALIZE_CHECK
    // serializeto buffer
    yas::mem_ostream os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
    oa.serialize(proof);
    std::cout << "proof size: " << os.get_shared_buffer().size << "\n";
    // serialize from buffer
    yas::mem_istream is(os.get_intrusive_buffer());
    yas::binary_iarchive<yas::mem_istream, YasBinF()> ia(is);
    PodProof proof2;
    ia.serialize(proof2);
    if (proof != proof2) {
      assert(false);
      std::cout << "oops, serialize check failed\n";
      return false;
    }
#endif
    
    bool success = PodVerify(seed, tpl, proof, action.com, action.n());

    std::cout << "success:" << success << "\n";
    return success;
}


bool FrozenLake::TestEnv() {
    Tick tick(__FN__);

    ProveOutput state(14, 64); //col
    ProveOutput action(14, 4); //row
    std::vector<int> trap =  {
        19, 29, 35, 41, 42, 46, 49, 52, 54, 59
    };
   
    LoadState(state.data);
    LoadAction(action.data);

    ComputeOutCom(state); //列承诺
    ComputeOutCom(action); //列承诺

    auto seed = misc::RandH256();

    EnvProof proof;
    EnvProve(seed, proof, state, action, trap);

#ifndef DISABLE_SERIALIZE_CHECK
    // serializeto buffer
    yas::mem_ostream os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
    oa.serialize(proof);
    std::cout << "proof size: " << os.get_shared_buffer().size << "\n";
    // serialize from buffer
    yas::mem_istream is(os.get_intrusive_buffer());
    yas::binary_iarchive<yas::mem_istream, YasBinF()> ia(is);
    EnvProof proof2;
    ia.serialize(proof2);
    if (proof != proof2) {
      assert(false);
      std::cout << "oops, serialize check failed\n";
      return false;
    }
#endif

    bool success = EnvVerify(seed, proof, state.com, action.com, trap);

    std::cout << "success:" << success << "\n";
    return success;
}

bool FrozenLake::TestKey(uint m, uint n) {
    Tick tick(__FN__);

    assert(m*n == 256);

    Fr k = FrRand(), r_com_k = FrRand(), sk_s = FrRand(), sk_c = FrRand();
    G1 com_k = pc::ComputeCom(k, r_com_k), pk_s = pc::kGetRefG1(0) * sk_s, pk_c = pc::kGetRefG1(0) * sk_c, pk = pk_s + pk_c;

    std::vector<std::vector<Fr>> bits(m, std::vector<Fr>(n, 0)), a(m, std::vector<Fr>(n));
    std::vector<Fr> r_com_bits(m), sub_keys(n, 0), r_enc_sub_keys(n);
    std::vector<G1> com_bits(m), enc_sub_keys1(n), enc_sub_keys2(n);
   
    //将密钥划分为m*n的比特矩阵
    Fr k_copy = k;
    for(int i=0; i<256; i++){
        int y = i / m;
        int x = i % m;
        if(k_copy.isOdd()){
            bits[x][y] = 1;
            k_copy = k_copy-1;
        }
        k_copy = k_copy / 2;
        if(x == 0 && y == 0){
            a[x][y] = 1;
        }else if(x == 0){
            a[x][y] = a[m-1][y-1] * 2;
        }else{
            a[x][y] = a[x-1][y] * 2;
        }
    }

    //对矩阵进行承诺
    FrRand(r_com_bits);
    for(int i=0; i<m; i++){
        com_bits[i] = pc::ComputeCom(bits[i], r_com_bits[i]);
        sub_keys += bits[i] * a[i][0];
    }

    //对子密钥加密
    FrRand(r_enc_sub_keys);
    for(int i=0; i<n; i++){
        enc_sub_keys1[i] = pc::kGetRefG1(0) * r_enc_sub_keys[i];
        enc_sub_keys2[i] = pk * r_enc_sub_keys[i] + pc::kGetRefG1(0) * sub_keys[i];
    }

    //生成证明
    auto seed = misc::RandH256();

    KeyProveInput input(k, bits, a, sub_keys, pk);
    KeyCommitmentPub com_pub(com_k, com_bits, enc_sub_keys1, enc_sub_keys2);
    KeyCommitmentSec com_sec(r_com_k, r_com_bits, r_enc_sub_keys);
    KeyProof proof;
    KeyProve(seed, proof, input, com_pub, com_sec);

#ifndef DISABLE_SERIALIZE_CHECK
    // serializeto buffer
    yas::mem_ostream os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
    oa.serialize(proof);
    std::cout << "proof size: " << os.get_shared_buffer().size << "\n";
    // serialize from buffer
    yas::mem_istream is(os.get_intrusive_buffer());
    yas::binary_iarchive<yas::mem_istream, YasBinF()> ia(is);
    KeyProof proof2;
    ia.serialize(proof2);
    if (proof != proof2) {
      assert(false);
      std::cout << "oops, serialize check failed\n";
      return false;
    }
#endif

    KeyVerifyInput verify_input(a, pk, com_pub);
    bool success = KeyVerify(seed, proof, verify_input);

    std::cout << "success:" << success << "\n";
    return success;
}

/**
 * 测试模型推理的正确性
 */
bool FrozenLake::TestModel() {
    Tick tick(__FN__);

    ProveOutput in(14, 64); //状态, 一共14个状态, 每个状态都是one-hot编码
    ProveOutput out(5, 14, true); //动作, 第0行为动作的值(0-3), 其余行为第一行的one-hot编码

    out.data[0] = {
        1, 2, 2, 2, 2, 2, 1, 2, 1, 1, 2, 1, 1, 1
    };
    for(int i=0; i<14; i++){
        out.data[out.data[0][i].getInt64() + 1][i] = 1;
    }

    std::unique_ptr<Para> para(new Para);
    std::unique_ptr<ParaCommitmentPub> para_com_pub(new ParaCommitmentPub); // commitment
    std::unique_ptr<ParaCommitmentSec> para_com_sec(new ParaCommitmentSec); // rnd

    LoadPara(*para);
    LoadState(in.data);

    ComputeOutCom(in); //列承诺
    ComputeOutCom(out); //行承诺
    ComputeParaCom(*para_com_pub, *para_com_sec, *para); //列承诺

    auto seed = misc::RandH256();

    ModelProof proof;
    ModelProve(seed, proof, in, out, *para, *para_com_pub, *para_com_sec);

#ifndef DISABLE_SERIALIZE_CHECK
    // serializeto buffer
    yas::mem_ostream os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
    oa.serialize(proof);
    std::cout << "proof size: " << os.get_shared_buffer().size << "\n";
    // serialize from buffer
    yas::mem_istream is(os.get_intrusive_buffer());
    yas::binary_iarchive<yas::mem_istream, YasBinF()> ia(is);
    ModelProof proof2;
    ia.serialize(proof2);
    if (proof != proof2) {
      assert(false);
      std::cout << "oops, serialize check failed\n";
      return false;
    }
#endif

    VerifyInput verify_input(14, 64, in.com, out.com, *para_com_pub, pc::kGetRefG1);
    bool success = ModelVerify(seed, proof, verify_input);

    std::cout << "success:" << success << "\n";
    return success;
}

bool FrozenLake::Test(){
    Tick tick(__FN__);

    auto seed = misc::RandH256();

    DeliverTuple tpl;
    ProveOutput state(14, 64);
    ProveOutput action(5, 14, true);
    ProveOutput action_oh(14, 4);
    ProveOutput action_sg(1, 14, true);

    std::vector<int> trap =  {
        19, 29, 35, 41, 42, 46, 49, 52, 54, 59
    };

    Fr key = 1000, seller_sk = FrRand(), buyer_sk = FrRand(), sk = seller_sk + buyer_sk;
    G1 seller_pk = pc::kGetRefG1(0) * seller_sk, buyer_pk = pc::kGetRefG1(0) * buyer_sk, pk = seller_pk + buyer_pk;

    std::unique_ptr<Para> para(new Para);
    std::unique_ptr<ParaCommitmentPub> para_com_pub(new ParaCommitmentPub); // commitment
    std::unique_ptr<ParaCommitmentSec> para_com_sec(new ParaCommitmentSec); // rnd

    bool model_success = false, env_success = false, pod_success = false;

{
    Tick tick(__FN__, "sell time");
    

    action.data.resize(5, std::vector<Fr>(14, 0));
    action_sg.data[0] = action.data[0] = {
        1, 2, 2, 2, 2, 2, 1, 2, 1, 1, 2, 1, 1, 1
    };
    for(int i=0; i<14; i++){
        action.data[action.data[0][i].getInt64() + 1][i] = 1;
    }

    LoadPara(*para); //参数
    LoadState(state.data); //状态
    LoadAction(action_oh.data); //动作

    ComputeOutCom(state); //列承诺
    ComputeOutCom(action); //行承诺
    ComputeParaCom(*para_com_pub, *para_com_sec, *para); //列承诺

    action_oh.com = std::vector<G1>(action.com.begin()+1, action.com.end());
    action_oh.r_com = std::vector<Fr>(action.r_com.begin()+1, action.r_com.end());

    action_sg.com[0] = action.com[0];
    action_sg.r_com[0] = action.r_com[0];

    ModelProve(seed, tpl.model_proof, state, action, *para, *para_com_pub, *para_com_sec);
    EnvProve(seed, tpl.env_proof, state, action_oh, trap);
    PodProve(seed, tpl, tpl.pod_proof, action_sg, key);
    tpl.com_state = state.com;
    tpl.com_action = action.com; 
}
#ifndef DISABLE_SERIALIZE_CHECK
    // serializeto buffer
    yas::mem_ostream os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
    oa.serialize(tpl);
    std::cout << "deliver tuple size: " << os.get_shared_buffer().size << "\n";
    // serialize from buffer
    yas::mem_istream is(os.get_intrusive_buffer());
    yas::binary_iarchive<yas::mem_istream, YasBinF()> ia(is);
    DeliverTuple tpl2;
    ia.serialize(tpl2);
    if (tpl != tpl2) {
      assert(false);
      std::cout << "oops, serialize check failed\n";
      return false;
    }
#endif
{
     Tick tick(__FN__, "buy time");
    VerifyInput verify_input(14, 64, state.com, action.com, *para_com_pub, pc::kGetRefG1);
    model_success = ModelVerify(seed, tpl.model_proof, verify_input);
    env_success = EnvVerify(seed, tpl.env_proof, state.com, action_oh.com, trap);
    pod_success = PodVerify(seed, tpl,tpl.pod_proof, action_sg.com, action_sg.n());
}
    bool success = model_success && env_success & pod_success;
    std::cout << "success:" << success << "\n";
    return success;
}
}
