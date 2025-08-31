#pragma once

#include "../details.h"
#include "argument/a6.h"
#include "circuit/fixed_point/fixed_point.h"
#include "circuit/frozenlake/env_gadget.h"

extern std::vector<std::vector<Fr>> max4_a;
extern std::vector<std::vector<Fr>> max4_b;
extern std::vector<std::vector<Fr>> max4_c;

extern std::vector<std::vector<Fr>> relu_a;
extern std::vector<std::vector<Fr>> relu_b;
extern std::vector<std::vector<Fr>> relu_c;

namespace clink::frozenlake{
std::vector<std::vector<Fr>> env_a, env_b, env_c;

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
        std::vector<G1> dense1; //65
        std::vector<G1> dense2; //13
        std::vector<G1> dense3; //9

        size_t m1() const { return 65;}
        size_t n1() const { return 12;}
        size_t m2() const { return 13;}
        size_t n2() const { return 8;}
        size_t m3() const { return 9;}
        size_t n3() const { return 4;}
    };

    struct ParaCommitmentSec { // the random used to compute commitment
        std::vector<Fr> r_dense1; //65
        std::vector<Fr> r_dense2; //13
        std::vector<Fr> r_dense3; //9
    };

    struct ProveOutput{ //the information about inner product
        bool is_row;
        std::vector<G1> com_data;   //n
        std::vector<Fr> r_com_data; //n
        std::vector<std::vector<Fr>> data; //n * 12

        ProveOutput(bool is_row=true)
            : is_row(is_row){   
        }

        size_t m() const { return data.size(); }
        size_t n() const { return data[0].size(); }
    };

    struct ProveDenseInput {

        ProveDenseInput(std::vector<std::vector<Fr>> const& para_dense,
                        std::vector<Fr> const& r_com_para_dense,
                        ProveOutput const& last_output)
            : para_dense(para_dense),
            r_com_para_dense(r_com_para_dense),
            data(last_output.data),
            r_com_data(last_output.r_com_data),
            is_row(last_output.is_row) {
            namespace fp = circuit::fp;
            CHECK(data[0].size() == para_dense.size() - 1, "");
            for(size_t i=0; i<data.size(); i++){
                this->data[i].push_back(fp::RationalConst<8, 24>().kFrN);
            }
            if(!is_row){
                this->r_com_data.push_back(FrZero());
            }
        }
        std::vector<std::vector<Fr>> const& para_dense;
        std::vector<Fr> const& r_com_para_dense;
        
        std::vector<std::vector<Fr>> data;
        std::vector<Fr> r_com_data; 

        bool is_row = true;
    };

    struct VerifyDenseInput {
        /**
         * _n, 如果为行, 则为列数; 如果为列, 则为行数
         * 
         */
        VerifyDenseInput(size_t m, size_t n,
                         std::vector<G1> const& com_data,
                         std::vector<G1> const& com_para_dense,
                         bool is_row = true)
            : m(m), n(n), is_row(is_row), com_data(com_data), com_para_dense(com_para_dense) {
            namespace fp = circuit::fp;
            size_t k = com_para_dense.size()-1;
            if(is_row){
                assert(com_data.size() == m);
                for(size_t i=0; i<com_data.size(); i++){
                    this->com_data[i] += pc::PcG(k) * fp::RationalConst<8, 24>().kFrN;
                }
            }else{
                assert(com_data.size() == com_para_dense.size() - 1);
                this->com_data.push_back(pc::ComputeSigmaG(0, m) * fp::RationalConst<8, 24>().kFrN);
            }
            
        }
        size_t m, n;
        bool is_row = true;
        std::vector<G1> com_data;
        std::vector<G1> const& com_para_dense;
    };

    struct ProveRelu2Input {
        typedef circuit::fixed_point::Relu2Gadget<8, 24 * 2, 24> Relu2Gadget;
        ProveRelu2Input(std::vector<Fr> const& in_data,
                        Fr const& r_com_in_data,
                        G1 const& com_in_data,
                        std::vector<Fr> const& out_data,
                        Fr const& r_com_out_data,
                        G1 const& com_out_data)
            : in_data(in_data), com_in_data(com_in_data), r_com_in_data(r_com_in_data),
              out_data(out_data), com_out_data(com_out_data), r_com_out_data(r_com_out_data) {
            namespace fp = circuit::fp;
            assert(in_data.size() == out_data.size());

            libsnark::protoboard<Fr> pb;
            Relu2Gadget gadget(pb, "Mnist Relu2Gadget");
            r1cs_ret_index = gadget.ret().index;  // see protoboard<FieldT>::val
            
            n = in_data.size();
            s = pb.num_variables() + 1;
            w.resize(s, std::vector<Fr>(n));

            auto parallel_f = [this](size_t j){
                libsnark::protoboard<Fr> pb;
                Relu2Gadget gadget(pb, "Mnist Relu2Gadget");
                gadget.Assign(this->in_data[j]);
                assert(pb.is_satisfied());
                auto v = pb.full_variable_assignment();
                CopyRowToLine(w, v, j, true);
            };
            parallel::For(n, parallel_f);
            assert(w[r1cs_ret_index] == out_data);
        }

        std::vector<Fr> const& out_data;
        Fr const& r_com_out_data;
        G1 const& com_out_data;

        std::vector<Fr> const& in_data;
        Fr const& r_com_in_data;
        G1 const& com_in_data;
        int64_t s, n;
        std::vector<std::vector<Fr>> mutable w;
        int64_t r1cs_ret_index;
    };

    struct VerifyRelu2Input {
        typedef circuit::fixed_point::Relu2Gadget<8, 24 * 2, 24> Relu2Gadget;
        VerifyRelu2Input(size_t n,
                        G1 const& com_in_data,
                        G1 const& com_out_data)
            : n(n),
              com_in_data(com_in_data),
              com_out_data(com_out_data) {
            namespace fp = circuit::fp;

            libsnark::protoboard<Fr> pb;
            Relu2Gadget gadget(pb, "Mnist Relu2Gadget");
            r1cs_ret_index = gadget.ret().index;  // see protoboard<FieldT>::val
 
            s = pb.num_variables() + 1;
        }

        G1 const& com_out_data;
        G1 const& com_in_data;
        int64_t s, n;
        int64_t r1cs_ret_index;
    };

    struct ProveMax2Input {
        typedef circuit::fixed_point::Max2Gadget<8, 24 * 2> Max2Gadget;
        ProveMax2Input(ProveOutput const& output)
            : data(output.data),
              com_data(output.com_data),
              r_com_data(output.r_com_data) {
            namespace fp = circuit::fp;
            libsnark::protoboard<Fr> pb;
            Max2Gadget gadget(pb, data[0].size(), "Mnist Max2Gadget");
            r1cs_ret_index = gadget.ret().index;  // see protoboard<FieldT>::val
            s = pb.num_variables() + 1;
            n = data.size();
            w.resize(s, std::vector<Fr>(n));

            auto parallel_f = [this](size_t j){
                libsnark::protoboard<Fr> pb;
                Max2Gadget gadget(pb, this->data[j].size(), "Mnist Max2Gadget");
                gadget.Assign(this->data[j]);
                assert(pb.is_satisfied());
                auto v = pb.full_variable_assignment();
                CopyRowToLine(w, v, j, true);
            };
            parallel::For(n, parallel_f);
        }

        std::vector<std::vector<Fr>> const& data;
        std::vector<Fr> const& r_com_data;
        std::vector<G1> const& com_data;
        int64_t s;
        int64_t n;
        std::vector<std::vector<Fr>> mutable w;
        int64_t r1cs_ret_index;
    };

    struct VerifyMax2Input {
        typedef circuit::fixed_point::Max2Gadget<8, 24 * 2> Max2Gadget;
        VerifyMax2Input(size_t n, std::vector<G1> const& com_data)
            : n(n), com_data(com_data) {
            namespace fp = circuit::fp;
            libsnark::protoboard<Fr> pb;
            Max2Gadget gadget(pb, com_data.size(), "Mnist Max2Gadget");
            r1cs_ret_index = gadget.ret().index;  // see protoboard<FieldT>::val
            s = pb.num_variables() + 1;
        }

        std::vector<G1> const& com_data;
        int64_t s;
        int64_t n;
        int64_t r1cs_ret_index;
    };

    struct ProveCombineInput {
        ProveCombineInput(ProveOutput const& output1, ProveOutput const& output2) {
            data = output1.data;
            data.insert(data.end(), output2.data.begin(), output2.data.end());

            com_data = output1.com_data;
            com_data.insert(com_data.end(), output2.com_data.begin(), output2.com_data.end());

            r_com_data = output1.r_com_data;
            r_com_data.insert(r_com_data.end(), output2.r_com_data.begin(), output2.r_com_data.end());

            for(size_t i=0; i<data.size(); i++){
                combine_data.insert(combine_data.end(), data[i].begin(), data[i].end());
            }
            
            r_com_combine_data = FrRand();
            com_combine_data = pc::ComputeCom(combine_data, r_com_combine_data);
        }

        std::vector<std::vector<Fr>> data;
        std::vector<Fr> r_com_data;
        std::vector<G1> com_data;

        std::vector<Fr> combine_data;
        Fr r_com_combine_data;
        G1 com_combine_data;
    };

    struct VerifyCombineInput {
        VerifyCombineInput(size_t n1,
                           size_t n2,
                           std::vector<G1> const& com_data1,
                           std::vector<G1> const& com_data2,
                           G1 const& com_combine_data)
            : n1(n1),
              n2(n2),
              com_combine_data(com_combine_data) {
            m1 = com_data1.size();
            m2 = com_data2.size();
            com_data = com_data1;
            com_data.insert(com_data.end(), com_data2.begin(), com_data2.end());
        }

        std::vector<G1> com_data;
        size_t n1, n2, m1, m2;
        G1 com_combine_data;
    };

    struct ProveEnvInput {
        typedef circuit::frozenlake::EnvGadget EnvGadget;
    
        ProveEnvInput(ProveOutput const& out1, ProveOutput const& out2)
            : state(out1.data),
              com_state(out1.com_data),
              r_com_state(out1.r_com_data),
              action(out2.data),
              com_action(out2.com_data),
              r_com_action(out2.r_com_data) {
            assert(state.size() == action[0].size());
            assert(!out1.is_row && out2.is_row);
            namespace fp = circuit::fp;

            libsnark::protoboard<Fr> pb;
            EnvGadget gadget(pb, "Frozenlake EnvGadget");

            r1cs_ret_index = gadget.ret().index;  // see protoboard<FieldT>::val
            in_index = gadget.in().index;

            s = pb.num_variables() + 1;
            n = state.size();
            w.resize(s, std::vector<Fr>(n));

            auto parallel_f = [this](size_t j){
                libsnark::protoboard<Fr> pb;
                EnvGadget gadget(pb, "Frozenlake EnvGadget");
                std::vector<Fr> act = {this->action[0][j], this->action[1][j], this->action[2][j], this->action[3][j]};
                gadget.Assign(this->state[j], act);
                assert(pb.is_satisfied());
                auto v = pb.full_variable_assignment();
                CopyRowToLine(w, v, j, true);
            };
            parallel::For(n, parallel_f);
        }
        std::vector<G1> const& com_state;
        std::vector<G1> const& com_action;
        std::vector<Fr> const& r_com_state;
        std::vector<Fr> const& r_com_action;
        std::vector<std::vector<Fr>> const& state;
        std::vector<std::vector<Fr>> const& action;
        int64_t s;
        int64_t n;
        std::vector<std::vector<Fr>> mutable w;
        int64_t r1cs_ret_index, in_index;
    };

    struct VerifyEnvInput {
        typedef circuit::frozenlake::EnvGadget EnvGadget;
        VerifyEnvInput(size_t n,
                       std::vector<G1> const& com_state,
                       std::vector<G1> const& com_action)
             : n(n),
               com_state(com_state),
               com_action(com_action) {
            namespace fp = circuit::fp;

            libsnark::protoboard<Fr> pb;
            EnvGadget gadget(pb, "Frozenlake EnvGadget");

            r1cs_ret_index = gadget.ret().index;  // see protoboard<FieldT>::val
            in_index = gadget.in().index;
            s = pb.num_variables() + 1;
        }
        int64_t s;
        int64_t n;
        int64_t r1cs_ret_index, in_index;
        std::vector<G1> const& com_state;
        std::vector<G1> const& com_action;
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

    struct DenseProof{
        std::vector<G1> com;
        argument::A6::Proof sub_proof;

        bool operator==(DenseProof const& b) const {
            return com == b.com && sub_proof == b.sub_proof;
        }

        bool operator!=(DenseProof const& b) const { return !(*this == b); }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("d.p", ("c", com), ("p", sub_proof));
        }
        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("d.p", ("c", com), ("p", sub_proof));
        }
    };

    struct CombineProof{
        G1 com1; //combine in
        G1 com2; //combine out

        argument::A4::Proof sub_proof;

        bool operator==(CombineProof const& b) const {
            return sub_proof == b.sub_proof && com1 == b.com1 && com2 == b.com2;
        }

        bool operator!=(CombineProof const& b) const { return !(*this == b); }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("cb.p", ("p", sub_proof), ("1", com1), ("2", com2));
        }
        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("cb.p", ("p", sub_proof), ("1", com1), ("2", com2));
        }
    };

    struct Relu2Proof{
        std::vector<G1> com1;
        std::vector<G1> com2;
        std::vector<G1> com_w;
        argument::A7::Proof r1cs_proof;

        bool operator==(Relu2Proof const& b) const {
            return r1cs_proof == b.r1cs_proof && com1 == b.com1 && com2 == b.com2 && com_w == b.com_w;
        }

        bool operator!=(Relu2Proof const& b) const { return !(*this == b); }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("rl.p", ("p", r1cs_proof), ("1", com1), ("2", com2), ("w", com_w));
        }
        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("rl.p", ("p", r1cs_proof), ("1", com1), ("2", com2), ("w", com_w));
        }
    };

    struct Max2Proof{
        std::vector<G1> com_w;
        argument::A7::Proof r1cs_proof;

        bool operator==(Max2Proof const& b) const {
            return r1cs_proof == b.r1cs_proof && com_w == b.com_w;
        }

        bool operator!=(Max2Proof const& b) const { return !(*this == b); }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("dr.p", ("r1cs", r1cs_proof), ("w", com_w));
        }
        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("dr.p", ("r1cs", r1cs_proof), ("w", com_w));
        }
    };

    struct ModelProof{
        CombineProof combine_proof;
        DenseProof dense1_proof;
        DenseProof dense2_proof;
        DenseProof dense3_proof;
        Relu2Proof relu_proof;
        Max2Proof max_proof;

        bool operator==(ModelProof const& b) const {
            return combine_proof == b.combine_proof && dense1_proof == b.dense1_proof &&
                   dense2_proof == b.dense2_proof && dense3_proof == b.dense3_proof &&
                   relu_proof == b.relu_proof && max_proof == b.max_proof;
        }

        bool operator!=(ModelProof const& b) const { return !(*this == b); }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("infer.p", ("c", combine_proof), ("d1", dense1_proof),
                              ("d2", dense2_proof), ("d3", dense3_proof),
                              ("rl", relu_proof), ("mx", max_proof));
        }
        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("infer.p", ("c", combine_proof), ("d1", dense1_proof),
                              ("d2", dense2_proof), ("d3", dense3_proof),
                              ("rl", relu_proof), ("mx", max_proof));
        }
    };

    struct EnvProof{
        G1 com1, com2;
        std::vector<Fr> z; 
        Fr r_com_z1, r_com_z2;

        std::vector<G1> com_w;
        argument::A7::Proof r1cs_proof;

        bool operator==(EnvProof const& b) const {
            return r1cs_proof == b.r1cs_proof && com_w == b.com_w &&
                    com1 == b.com1 && com2 == b.com2 && z == b.z &&
                    r_com_z1 == b.r_com_z1 && r_com_z2 == b.r_com_z2;
        }

        bool operator!=(EnvProof const& b) const { return !(*this == b); }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("ev.p", ("r1cs", r1cs_proof), ("w", com_w), ("1", com1),
                                       ("2", com2), ("r1", r_com_z1), ("r2", r_com_z2), ("z", z));
        }
        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("ev.p", ("r1cs", r1cs_proof), ("w", com_w), ("1", com1),
                                       ("2", com2), ("r1", r_com_z1), ("r2", r_com_z2), ("z", z));
        }
    };

    struct Message{
        EnvProof env_proof;
        ModelProof mdl_proof;
        Pod::KeyProof key_proof;
        Pod::MimcProof mimc_proof;
        

        Fr r_enc_action;
        std::vector<Fr> enc_action;

         bool operator==(Message const& b) const {
            return  env_proof == b.env_proof && mdl_proof == b.mdl_proof &&
                    mimc_proof == b.mimc_proof && r_enc_action == b.r_enc_action && 
                    enc_action == b.enc_action && key_proof == b.key_proof;
        }

        bool operator!=(Message const& b) const { return !(*this == b); }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("msg.p", ("p1", env_proof), ("p2", mdl_proof), ("p3", mimc_proof),
                                        ("p4", key_proof), ("r", r_enc_action), ("c", enc_action));
        }
        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("msg.p", ("p1", env_proof), ("p2", mdl_proof), ("p3", mimc_proof),
                                        ("p4", key_proof), ("r", r_enc_action), ("c", enc_action));
        }
    };

    static void ProveDense(DenseProof& proof, ProveOutput& output, h256_t seed,
                            ProveDenseInput const& input) {
        Tick tick(__FN__);
        namespace fp = circuit::fp;
        size_t m = input.data.size(), k = input.data[0].size(), n = input.para_dense[0].size();

        MatrixMul(input.data, input.para_dense, output.data);

        ComputeOutCom(output);
    
        proof.com = output.com_data;
        argument::A6::ProveInput a6_in(input.data, input.para_dense, output.data, pc::kGetRefG1);
        argument::A6::CommitmentSec a6_sec(input.r_com_data, input.r_com_para_dense, output.r_com_data, input.is_row, output.is_row);
        argument::A6::Prove(proof.sub_proof, seed, a6_in, a6_sec);
    }

    static bool VerifyDense(DenseProof const& proof, h256_t seed,
                            VerifyDenseInput const& input, bool in_is_row=true, bool out_is_row=true) {
        Tick tick(__FN__);

        size_t m = input.m, k = input.com_para_dense.size(), n = input.n;
        
        argument::A6::CommitmentPub a6_pub(input.com_data, input.com_para_dense, proof.com, in_is_row, out_is_row);
        argument::A6::VerifyInput a6_in(m, k, n, a6_pub, pc::kGetRefG1);
        return argument::A6::Verify(proof.sub_proof, seed, a6_in);
    }

     static void ProveMax2(Max2Proof& proof, ProveOutput & output, 
                           ProveOutput & action, h256_t seed,
                           ProveMax2Input const& input) {
        Tick tick(__FN__);
        namespace fp = circuit::fp;
        std::vector<G1> com_w(input.s);
        std::vector<Fr> com_w_r(input.s);

        std::cout << "compute com(witness)\n";
        auto parallel_f = [&com_w_r, &com_w, &input](int64_t i) {
            if(i == 0){ 
                com_w_r[i] = FrZero();
                com_w[i] = pc::ComputeSigmaG(0, input.w[0].size());
            }else if (i < 5) {
                com_w_r[i] = input.r_com_data[i-1];
                com_w[i] = input.com_data[i-1];
            } else {
                com_w_r[i] = FrRand();
                com_w[i] = pc::ComputeCom(input.w[i], com_w_r[i], true);
            }
        };
        parallel::For<int64_t>(input.s, parallel_f);

        // save output for next step
        output.r_com_data.push_back(com_w_r[input.r1cs_ret_index]);
        output.com_data.push_back(com_w[input.r1cs_ret_index]);
        output.data.push_back(input.w[input.r1cs_ret_index]);

        for(size_t i=0; i<4; i++){
            action.data.push_back(input.w[6+i]);
            action.com_data.push_back(com_w[6+i]);
            action.r_com_data.push_back(com_w_r[6+i]);
        }
        action.data.push_back(input.w[input.r1cs_ret_index]);
        action.com_data.push_back(com_w[input.r1cs_ret_index]);
        action.r_com_data.push_back(com_w_r[input.r1cs_ret_index]);

        proof.com_w = std::move(com_w);
        UpdateSeed(seed, proof.com_w);

        std::vector<std::vector<Fr>> wa, wb, wc;
        std::vector<Fr> r_com_wa, r_com_wb, r_com_wc;
        ComputeWitness(input.w, max4_a, max4_b, max4_c, wa, wb, wc, com_w_r, r_com_wa, r_com_wb, r_com_wc);
        argument::A7::CommitmentSec a7_sec(r_com_wa, r_com_wb, r_com_wc);
        argument::A7::ProveInput a7_input(wa, wb, wc, pc::kGetRefG1);
        argument::A7::Prove(proof.r1cs_proof, seed, a7_input, a7_sec);
    }

     static bool VerifyMax2(Max2Proof const& proof, h256_t seed,
                           VerifyMax2Input const& input) {
        Tick tick(__FN__);
        if(proof.com_w[0] != pc::ComputeSigmaG(0, input.n)){
            assert(false);
            return false;
        }

        for(size_t i=0; i<input.com_data.size(); i++){
            if(proof.com_w[i+1] != input.com_data[i]){
                assert(false);
                return false;
            }
        }
        UpdateSeed(seed, proof.com_w);
        return argument::A7::Verify(input.n, proof.r1cs_proof, seed, max4_a, max4_b, max4_c, proof.com_w, pc::kGetRefG1);
    }

    static void ProveRelu2(Relu2Proof& proof, h256_t seed, ProveRelu2Input const& input) {
        Tick tick(__FN__);
        namespace fp = circuit::fp;
        std::vector<G1> com_w(input.s);
        std::vector<Fr> com_w_r(input.s);

        std::cout << "compute com(witness)\n";
        auto parallel_f = [&com_w_r, &com_w, &input](int64_t i) {
            if(i == 0){ 
                com_w_r[i] = FrZero();
                com_w[i] = pc::ComputeSigmaG(0, input.w[0].size());
            }else if (i == 1) {
                com_w_r[i] = input.r_com_in_data;
                com_w[i] = input.com_in_data;
            } else if(i == input.r1cs_ret_index){
                com_w_r[i] = input.r_com_out_data;
                com_w[i] = input.com_out_data;
            } else {
                com_w_r[i] = FrRand();
                com_w[i] = pc::ComputeCom(input.w[i], com_w_r[i], true);
            }
        };
        parallel::For<int64_t>(input.s, parallel_f);

        proof.com_w = std::move(com_w);
        UpdateSeed(seed, proof.com_w);

        std::vector<std::vector<Fr>> wa, wb, wc;
        std::vector<Fr> r_com_wa, r_com_wb, r_com_wc;
        ComputeWitness(input.w, relu_a, relu_b, relu_c, wa, wb, wc, com_w_r, r_com_wa, r_com_wb, r_com_wc);
        argument::A7::CommitmentSec a7_sec(r_com_wa, r_com_wb, r_com_wc);
        argument::A7::ProveInput a7_input(wa, wb, wc, pc::kGetRefG1);
        argument::A7::Prove(proof.r1cs_proof, seed, a7_input, a7_sec);
    }

    static bool VerifyRelu2(Relu2Proof const& proof, h256_t seed, VerifyRelu2Input const& input) {
        Tick tick(__FN__);
        if(proof.com_w[0] != pc::ComputeSigmaG(0, input.n)){
            assert(false);
            return false;
        }

        if(proof.com_w[1] != input.com_in_data || proof.com_w[input.r1cs_ret_index] != input.com_out_data){
            assert(false);
            return false;
        }
        
        UpdateSeed(seed, proof.com_w);
        return argument::A7::Verify(input.n, proof.r1cs_proof, seed, relu_a, relu_b, relu_c, proof.com_w, pc::kGetRefG1);
    }

    static void ProveCombine(CombineProof& proof, h256_t seed,
                             ProveCombineInput const& input1,
                             ProveCombineInput const& input2) {
        Tick tick(__FN__);
        std::vector<Fr> vec_e(1);
        ComputeFst(seed, "combine e", vec_e);
        Fr e = vec_e[0];

        std::vector<Fr> combine_data = input1.combine_data * e + input2.combine_data;
        Fr r_com_combine_data = input1.r_com_combine_data * e + input2.r_com_combine_data;
        
        ProveOutput output;
        std::vector<std::vector<Fr>> data = MatrixMul(input1.data, e);
        for(size_t i=0; i<data.size(); i++){
            data[i] = data[i] + input2.data[i];
        }

        std::vector<Fr> r_com_data = input1.r_com_data * e + input2.r_com_data;

        std::vector<std::vector<Fr>> r(data.size());
        std::vector<Fr> combine_r;
        
        for(size_t i=0; i<data.size(); i++){
            r[i].resize(data[i].size());
            ComputeFst(seed, "combine r " + std::to_string(i), r[i]);
            combine_r.insert(combine_r.end(), r[i].begin(), r[i].end());
        }
        assert(InnerProduct(data, r) == InnerProduct(combine_data, combine_r));

        std::vector<std::vector<Fr>> &a = data, &b = r;
        std::vector<Fr> &r_com_a = r_com_data;
        Fr c = 0, r_com_c = 0;

        b.push_back(-combine_r);
        a.push_back(combine_data);
        r_com_a.push_back(r_com_combine_data);

        argument::A4::ProveInput a4_in(a, b, c, pc::kGetRefG1, pc::kGetRefG1(0));
        argument::A4::CommitmentSec a4_sec(r_com_a, r_com_c);
        argument::A4::Prove(proof.sub_proof, seed, a4_in, a4_sec);
        
        proof.com1 = input1.com_combine_data;
        proof.com2 = input2.com_combine_data;
    }

    static bool VerifyCombine(CombineProof const& proof, h256_t seed,
                              VerifyCombineInput const& input1,
                              VerifyCombineInput const& input2) {
        Tick tick(__FN__);
        assert(input1.m1 == input2.m1 && input1.m2 == input2.m2);
        assert(input1.n1 == input2.n1 && input1.n2 == input2.n2);

        std::vector<Fr> vec_e(1);
        ComputeFst(seed, "combine e", vec_e);
        Fr e = vec_e[0];

        std::vector<G1> com_data = input1.com_data * e + input2.com_data;
        G1 com_combine_data = input1.com_combine_data * e + input2.com_combine_data;
        
        std::vector<std::vector<Fr>> r(com_data.size());
        std::vector<Fr> combine_r;
        
        for(size_t i=0; i<com_data.size(); i++){
            if(i < input1.m1){
                r[i].resize(input1.n1);
            }else{
                r[i].resize(input1.n2);
            }
            ComputeFst(seed, "combine r " + std::to_string(i), r[i]);
            combine_r.insert(combine_r.end(), r[i].begin(), r[i].end());
        }

        std::vector<std::vector<Fr>> &b = r;
        b.push_back(-combine_r);

        std::vector<G1> &com_a = com_data;
        com_a.push_back(com_combine_data);

        argument::A4::CommitmentPub a4_pub(com_a, G1Zero());
        argument::A4::VerifyInput a4_in(b, a4_pub, pc::kGetRefG1, pc::kGetRefG1(0));
        return argument::A4::Verify(proof.sub_proof, seed, a4_in);
    }

    static void EnvProve(h256_t seed, EnvProof& proof,
                          ProveEnvInput const& input){
        Tick tick(__FN__);
        namespace fp = circuit::fp;
        std::vector<G1> com_w(input.s);
        std::vector<Fr> com_w_r(input.s);

        std::cout << "compute com(witness)\n";
        auto parallel_f = [&com_w_r, &com_w, &input](int64_t i) {
            if(i == 0){ 
                com_w_r[i] = FrZero();
                com_w[i] = pc::ComputeSigmaG(0, input.w[0].size());
            }else if(i < 65){
                com_w_r[i] = input.r_com_state[i-1];
                com_w[i] = input.com_state[i-1];
            }else if(i < 69){
                com_w_r[i] = input.r_com_action[i-65];
                com_w[i] = input.com_action[i-65];
            }else{
                com_w_r[i] = FrRand();
                com_w[i] = pc::ComputeCom(input.w[i], com_w_r[i], true);
            }
        };
        parallel::For<int64_t>(input.s, parallel_f);
        UpdateSeed(seed, com_w);

        std::vector<std::vector<Fr>> wa, wb, wc;
        std::vector<Fr> r_com_wa, r_com_wb, r_com_wc;
        ComputeWitness(input.w, env_a, env_b, env_c, wa, wb, wc, com_w_r, r_com_wa, r_com_wb, r_com_wc);
        argument::A7::CommitmentSec a7_sec(r_com_wa, r_com_wb, r_com_wc);
        argument::A7::ProveInput a7_input(wa, wb, wc, pc::kGetRefG1);
        argument::A7::Prove(proof.r1cs_proof, seed, a7_input, a7_sec);
        UpdateSeed(seed, proof.r1cs_proof);

        // same scalar
        Fr r_com_a = com_w_r[input.in_index];
        Fr r_com_b = com_w_r[input.r1cs_ret_index];
        std::vector<Fr> x = input.w[input.r1cs_ret_index];
        std::vector<G1> g1 = pc::CopyG(pc::kGetRefG1, input.n), g2 = g1;
        
        g1.erase(g1.begin(), g1.begin() + 1);
        g2.pop_back();
        x.pop_back();
        
        std::vector<Fr> y(x.size());
        FrRand(y);

        Fr r_com_1 = FrRand(), r_com_2 = FrRand();
        proof.com1 = pc::ComputeCom(input.n-1, g1.data(), y.data(), r_com_1);
        proof.com2 = pc::ComputeCom(input.n-1, g2.data(), y.data(), r_com_2);

        UpdateSeed(seed, proof.com1, proof.com2);
        Fr e = ComputeFst(seed, "same base");

        proof.z = y + x * e;
        proof.r_com_z1 = r_com_1 + r_com_a * e;
        proof.r_com_z2 = r_com_2 + r_com_b * e;
        
        proof.com_w = std::move(com_w);
    }

    static bool EnvVerify(h256_t seed, EnvProof const& proof, VerifyEnvInput const& input){
        Tick tick(__FN__);
        if(proof.com_w[0] != pc::ComputeSigmaG(0, input.n)){
            assert(false);
            return false;
        }

        for(size_t i=0; i<64; i++){
            if(proof.com_w[i+1] != input.com_state[i]){
                assert(false);
                return false;
            }
        }

        for(size_t i=0; i<4; i++){
            if(proof.com_w[i+65] != input.com_action[i]){
                assert(false);
                return false;
            }
        }

        UpdateSeed(seed, proof.com_w);
        bool ret = argument::A7::Verify(input.n, proof.r1cs_proof, seed, env_a, env_b, env_c, proof.com_w, pc::kGetRefG1);
        if(!ret){
            assert(false);
            return false;
        }
        UpdateSeed(seed, proof.r1cs_proof);

        // same scalar
        std::vector<G1> g1 = pc::CopyG(pc::kGetRefG1, input.n), g2 = g1;
        g1.erase(g1.begin(), g1.begin() + 1);
        g2.pop_back();

        G1 com_a = proof.com_w[input.in_index];
        G1 com_b = proof.com_w[input.r1cs_ret_index] - pc::PcG(input.n-1) * (63 *circuit::fp::RationalConst<8, 24>().kFrN);

        UpdateSeed(seed, proof.com1, proof.com2);
        Fr e = ComputeFst(seed, "same base");

        ret &= (proof.com1 + com_a * e == pc::ComputeCom(input.n-1, g1.data(), proof.z.data(), proof.r_com_z1));
        ret &= (proof.com2 + com_b * e == pc::ComputeCom(input.n-1, g2.data(), proof.z.data(), proof.r_com_z2));
        
        if(!ret){
            assert(false);
            return false;
        }
        return true;
    }

    static void InferReluAndCommit(std::vector<std::vector<Fr>> const& in,
                          ProveOutput & out) {
        Tick tick(__FN__);
        namespace fp = circuit::fp;
        out.data.resize(in.size(), std::vector<Fr>(in[0].size()));
        auto parallel_f = [&in, &out](size_t i){
            size_t row = i / in[0].size(), col = i % in[0].size();
            out.data[row][col] = fp::ReducePrecision<8, 24 * 2, 24>(in[row][col]);
            out.data[row][col] = out.data[row][col].isNegative() ? 0 : out.data[row][col];
        };
        parallel::For(in.size() * in[0].size(), parallel_f);
        ComputeOutCom(out);
    }

    static void ComputeOutCom(ProveOutput& output) {
        Tick tick(__FN__);
        if(output.is_row){
            size_t m = output.data.size();
            output.r_com_data.resize(m);
            output.com_data.resize(m);
            FrRand(output.r_com_data);
            auto parallel_f = [&output](int64_t i) {
                output.com_data[i] = pc::ComputeCom(output.data[i], output.r_com_data[i]);
            };
            parallel::For(m, parallel_f);
        }else{
            size_t m = output.data.size();
            size_t n = output.data[0].size();
            output.r_com_data.resize(n);
            output.com_data.resize(n);
            FrRand(output.r_com_data);
            auto parallel_f = [&output, &m, &n](int64_t j) {
                auto get_data = [&output, &j](size_t i) -> Fr const&{
                    return output.data[i][j];
                };
                output.com_data[j] = pc::ComputeCom(m, get_data, output.r_com_data[j]);
            };
            parallel::For(n, parallel_f);
        }
    }

    static void LoadPara(Para& para);

    static void LoadState(std::vector<std::vector<Fr>> &data);

    static void LoadAction(std::vector<std::vector<Fr>> &action);

    static void ComputeParaCom(ParaCommitmentPub& com_pub, ParaCommitmentSec& com_sec, Para const& para);

    static void ModelProve(h256_t seed, ModelProof& proof,
                            ProveOutput const& state,
                            ProveOutput & action,
                            Para const& para,
                            ParaCommitmentPub const& para_com_pub,
                            ParaCommitmentSec const& para_com_sec);

    static bool ModelVerify(h256_t seed, ModelProof const& proof, 
                            std::vector<G1> const& com_data,
                            ParaCommitmentPub const& para_com_pub);


    static bool TestModel();

    static bool TestEnv();

    static bool Test();
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

void FrozenLake::ComputeParaCom(ParaCommitmentPub& com_pub,
                             ParaCommitmentSec& com_sec, Para const& para) {
    Tick tick(__FN__);

    com_pub.dense1.resize(65);
    com_pub.dense2.resize(13);
    com_pub.dense3.resize(9);

    com_sec.r_dense1.resize(65);
    com_sec.r_dense2.resize(13);
    com_sec.r_dense3.resize(9);

    FrRand(com_sec.r_dense1);
    FrRand(com_sec.r_dense2);
    FrRand(com_sec.r_dense3);

    auto parallel_f1 = [&para, &com_sec, &com_pub](int64_t i) {
        com_pub.dense1[i] = pc::ComputeCom(para.dense1[i], com_sec.r_dense1[i]);
        if(i < 13){
            com_pub.dense2[i] = pc::ComputeCom(para.dense2[i], com_sec.r_dense2[i]);
        }
        if(i < 9){
            com_pub.dense3[i] = pc::ComputeCom(para.dense3[i], com_sec.r_dense3[i]);
        }
    };
    parallel::For(65, parallel_f1);
}


// 对于一个prove, 要准备对应的proveinput, 包含: 承诺, 打开(承诺数据 + 随机数), 数据
void FrozenLake::ModelProve(h256_t seed, ModelProof& proof,
                            ProveOutput const& state,
                            ProveOutput & action,
                            Para const& para,
                            ParaCommitmentPub const& para_com_pub,
                            ParaCommitmentSec const& para_com_sec) {
    Tick tick(__FN__);

    // prove dense1
    ProveDenseInput dense1_input(para.dense1, para_com_sec.r_dense1, state);
    ProveOutput dense1_output;
    ProveDense(proof.dense1_proof, dense1_output, seed, dense1_input);
    UpdateSeed(seed, proof.dense1_proof);

    // infer relu1
    ProveOutput relu1_output;
    InferReluAndCommit(dense1_output.data, relu1_output);
    proof.relu_proof.com1 = relu1_output.com_data;

    // prove dense2
    ProveDenseInput dense2_input(para.dense2, para_com_sec.r_dense2, relu1_output);
    ProveOutput dense2_output;
    ProveDense(proof.dense2_proof, dense2_output, seed, dense2_input);
    UpdateSeed(seed, proof.dense2_proof);

    // infer relu2
    ProveOutput relu2_output;
    InferReluAndCommit(dense2_output.data, relu2_output);
    proof.relu_proof.com2 = relu2_output.com_data;

    // prove dense3
    ProveDenseInput dense3_input(para.dense3, para_com_sec.r_dense3, relu2_output);
    ProveOutput dense3_output(false);
    ProveDense(proof.dense3_proof, dense3_output, seed, dense3_input);
    UpdateSeed(seed, proof.dense3_proof);

    // prove combine
    ProveCombineInput combine1_input(dense1_output, dense2_output);
    ProveCombineInput combine2_input(relu1_output, relu2_output);
    ProveCombine(proof.combine_proof, seed, combine1_input, combine2_input);
    UpdateSeed(seed, proof.combine_proof);

    //prove relu
    ProveRelu2Input dense1_relu_input(
            combine1_input.combine_data, combine1_input.r_com_combine_data, combine1_input.com_combine_data,
            combine2_input.combine_data, combine2_input.r_com_combine_data, combine2_input.com_combine_data
    );
    ProveRelu2(proof.relu_proof, seed, dense1_relu_input);
    UpdateSeed(seed, proof.relu_proof);

    // max
    ProveMax2Input max_input(dense3_output);
    ProveOutput max_output;
    ProveMax2(proof.max_proof, max_output, action, seed, max_input);
    UpdateSeed(seed, proof.max_proof);

    misc::PrintVector(max_output.data[0]);
    misc::PrintVector(action.data);
}

bool FrozenLake::ModelVerify(h256_t seed,
                             ModelProof const& proof, 
                             std::vector<G1> const& com_data,
                             ParaCommitmentPub const& para_com_pub){
    Tick tick(__FN__);

    // verify dense1, 输入为列承诺
    VerifyDenseInput dense1_input(14, para_com_pub.n1(), com_data, para_com_pub.dense1, false);
    if (!VerifyDense(proof.dense1_proof, seed, dense1_input, dense1_input.is_row, true)) {
      assert(false);
      return false;
    }
    UpdateSeed(seed, proof.dense1_proof);
    
    // verify dense2
    VerifyDenseInput dense2_input(proof.dense1_proof.com.size(), para_com_pub.n2(), proof.relu_proof.com1, para_com_pub.dense2);
    if (!VerifyDense(proof.dense2_proof, seed, dense2_input)) {
      assert(false);
      return false;
    }
    UpdateSeed(seed, proof.dense2_proof);

    // verify dense3
    VerifyDenseInput dense3_input(proof.dense2_proof.com.size(), para_com_pub.n3(), proof.relu_proof.com2, para_com_pub.dense3);
    if (!VerifyDense(proof.dense3_proof, seed, dense3_input, dense3_input.is_row, false)) {
      assert(false);
      return false;
    }
    UpdateSeed(seed, proof.dense3_proof);

    // verify combine
    VerifyCombineInput combine1_input(para_com_pub.n1(), para_com_pub.n2(), proof.dense1_proof.com, proof.dense2_proof.com, proof.combine_proof.com1);
    VerifyCombineInput combine2_input(para_com_pub.n1(), para_com_pub.n2(), proof.relu_proof.com1, proof.relu_proof.com2, proof.combine_proof.com2);
     if (!VerifyCombine(proof.combine_proof, seed, combine1_input, combine2_input)) {
      assert(false);
      return false;
    }
    UpdateSeed(seed, proof.combine_proof);

    // verify relu
    VerifyRelu2Input relu_input(
        dense1_input.m * dense1_input.n + dense1_input.m * dense2_input.n, 
        proof.combine_proof.com1, proof.combine_proof.com2
    );
    if (!VerifyRelu2(proof.relu_proof, seed, relu_input)) {
      assert(false);
      return false;
    }
    UpdateSeed(seed, proof.relu_proof);

    // ProveMax2Input()
    VerifyMax2Input max_input(dense1_input.m, proof.dense3_proof.com);
    if (!VerifyMax2(proof.max_proof, seed, max_input)) {
      assert(false);
      return false;
    }
    UpdateSeed(seed, proof.max_proof);
                                      
    return true;
}

bool FrozenLake::TestEnv() {
    Tick tick(__FN__);

    std::vector<std::vector<Fr>> state(14, std::vector<Fr>(64, 0)); //col
    std::vector<std::vector<Fr>> action(14, std::vector<Fr>(4, 0)); //row

    ProveOutput out1(false), out2(false);
    LoadState(out1.data);
    LoadAction(out2.data);

    ComputeOutCom(out1);
    ComputeOutCom(out2);

    auto seed = misc::RandH256();

    EnvProof proof;
    ProveEnvInput prove_input(out1, out2);
    EnvProve(seed, proof, prove_input);

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
    VerifyEnvInput verify_input(state.size(), out1.com_data, out2.com_data);
    bool success = EnvVerify(seed, proof, verify_input);

    std::cout << "success:" << success << "\n";
    return success;
}

/**
 * 测试模型推理的正确性
 */
bool FrozenLake::TestModel() {
    Tick tick(__FN__);

    std::unique_ptr<Para> para(new Para);
    LoadPara(*para);

    std::vector<std::vector<Fr>> state;
    LoadState(state); //状态

    ProveOutput output_state(false), output_action;
    output_state.data = state;
    ComputeOutCom(output_state);

    std::unique_ptr<ParaCommitmentPub> para_com_pub(new ParaCommitmentPub); // commitment
    std::unique_ptr<ParaCommitmentSec> para_com_sec(new ParaCommitmentSec); // rnd
    ComputeParaCom(*para_com_pub, *para_com_sec, *para);

    auto seed = misc::RandH256();

    ModelProof proof;
    ModelProve(seed, proof, output_state, output_action, *para, *para_com_pub, *para_com_sec);

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
    bool success = ModelVerify(seed, proof, output_state.com_data, *para_com_pub);
    std::cout << "success:" << success << "\n";
    return success;
}

bool FrozenLake::Test() {
    Tick tick(__FN__);

    size_t block_len = 7;

    std::unique_ptr<Para> para(new Para);
    LoadPara(*para);

    std::vector<std::vector<Fr>> state; //col
    LoadState(state); //状态

    ProveOutput output_state(false), output_action;
    output_state.data = state;
    ComputeOutCom(output_state);

    std::unique_ptr<ParaCommitmentPub> para_com_pub(new ParaCommitmentPub); // commitment
    std::unique_ptr<ParaCommitmentSec> para_com_sec(new ParaCommitmentSec); // rnd
    ComputeParaCom(*para_com_pub, *para_com_sec, *para);

    Message msg;
    Pod::Secret secret;
    auto seed = misc::RandH256();
    Pod::CommitedData commited_data, commited_cph;

    {
        Tick tick("Server Time");
        // 推理证明
        ModelProve(seed, msg.mdl_proof, output_state, output_action, *para, *para_com_pub, *para_com_sec);

        // 答案有效性证明
        ProveEnvInput prove_input(output_state, output_action);
        EnvProve(seed, msg.env_proof, prove_input);
        commited_data.d = output_action.data.back();
        commited_data.com_d = output_action.com_data.back();
        commited_data.r_com_d = output_action.r_com_data.back();
        misc::PrintVector(commited_data.d);

        // 加密证明
        Pod::EncryptAndProve(msg.mimc_proof, seed, secret, commited_cph, commited_data);
        msg.enc_action = commited_cph.d + commited_data.d;
        msg.r_enc_action = commited_cph.r_com_d + commited_data.r_com_d;

        // 密钥交易
        Pod::KeyProve(msg.key_proof, seed, secret, block_len);
    }

#ifndef DISABLE_SERIALIZE_CHECK
    // serializeto buffer
    yas::mem_ostream os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
    oa.serialize(msg);
    std::cout << "msg size: " << os.get_shared_buffer().size << "\n";
    // serialize from buffer
    yas::mem_istream is(os.get_intrusive_buffer());
    yas::binary_iarchive<yas::mem_istream, YasBinF()> ia(is);
    Message msg2;
    ia.serialize(msg2);
    if (msg != msg2) {
      assert(false);
      std::cout << "oops, serialize check failed\n";
      return false;
    }

    {
        yas::mem_ostream os;
        yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
        oa.serialize(msg.mdl_proof);
        std::cout << "model proof size: " << os.get_shared_buffer().size << "\n";
    }

    {
        yas::mem_ostream os;
        yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
        oa.serialize(msg.env_proof);
        std::cout << "env proof size: " << os.get_shared_buffer().size << "\n";
    }

    {
        yas::mem_ostream os;
        yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
        oa.serialize(msg.mimc_proof);
        std::cout << "mimc proof size: " << os.get_shared_buffer().size << "\n";
    }

     {
        yas::mem_ostream os;
        yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
        oa.serialize(msg.key_proof);
        std::cout << "key proof size: " << os.get_shared_buffer().size << "\n";
    }
#endif

    bool success = true;
    {
        Tick tick("Client Time");
        CHECK(msg.mimc_proof.com_w.back() + commited_data.com_d == pc::ComputeCom(msg.enc_action, msg.r_enc_action), "");

        success &= ModelVerify(seed, msg.mdl_proof, output_state.com_data, *para_com_pub);

        VerifyEnvInput verify_input(state.size(), output_state.com_data, output_action.com_data);
        success &= EnvVerify(seed, msg.env_proof, verify_input);

        success &= Pod::VerifyAndBuy(msg.mimc_proof, seed, state.size());

        success &= Pod::KeyVerify(seed, state.size(), secret.com_key, msg.key_proof, block_len);
    }

    std::cout << "success:" << success << "\n";
    return success;
}

}
