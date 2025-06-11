#pragma once

#include "../details.h"
#include "libra/libra.h"

#include "circuit/mimc5_gadget.h"
#include "circuit/fixed_point/fixed_point.h"
#include "clink/equality3.h"

namespace clink::mlp{

size_t const D = 8, N = 24, n = 1000;

Fr key, sk_sel, sk_buy, sk;
G1 pk, pk_sel, pk_buy;

std::vector<std::vector<Fr>> relu_A, relu_B, relu_C;
std::vector<std::vector<Fr>> mimc_A, mimc_B, mimc_C;

struct MLP{

    struct Matrix{ //线性层的输入
        std::vector<std::vector<Fr>> matrix;

        Matrix(){}

        Matrix(size_t const& m_, size_t const& n_){
            matrix.resize(m_, std::vector<Fr>(n_));
        }

        size_t m() const{return matrix.size();}
        size_t n() const{return matrix[0].size();}
    };

    struct MatrixCommitmentPub { // commitment of
        std::vector<G1> com_matrix;

        MatrixCommitmentPub(){}

        MatrixCommitmentPub(size_t const& m_){
            com_matrix.resize(m_);
        }

        size_t m() const{return com_matrix.size();}
    };

    struct MatrixCommitmentSec { // the random used to compute commitment
        std::vector<Fr> r_com_matrix;

        MatrixCommitmentSec(){}

        MatrixCommitmentSec(size_t const& m_){
            r_com_matrix.resize(m_);
        }
    };

    struct ElgamalCph{
        G1 c1, c2;

        ElgamalCph operator*(Fr const& a) const{
            ElgamalCph ret;
            ret.c1 = c1 * a;
            ret.c2 = c2 * a;
            return ret;
        }

        ElgamalCph operator+(ElgamalCph const& right) const{
            ElgamalCph ret;
            ret.c1 = c1 + right.c1;
            ret.c2 = c2 + right.c2;
            return ret;
        }

        bool operator==(ElgamalCph const& right) const {
            return c1 == right.c1 && c2 == right.c2;
        }
        bool operator!=(ElgamalCph const& right) const { return !(*this == right); }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("elc.p", ("c1", c1), ("c2", c2));
        }

        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("elc.p", ("c1", c1), ("c2", c2));
        }
    };

    struct ReluAndEncProof{ //inference proof
        libra::A1::Proof r1cs_proof;

        std::vector<std::vector<Fr>> cph; //密文, 承诺的打开

        std::vector<std::vector<G1>> com_relu_wit;

        std::vector<std::vector<G1>> com_mimc_wit;

        bool operator==(ReluAndEncProof const& right) const {
            return r1cs_proof == right.r1cs_proof && com_relu_wit == right.com_relu_wit 
                    && com_mimc_wit == right.com_mimc_wit && cph == right.cph;
        }
        bool operator!=(ReluAndEncProof const& right) const { return !(*this == right); }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("rl.p", ("r1cs", r1cs_proof), ("rlw", com_relu_wit), ("mmw", com_mimc_wit), ("cph", cph));
        }

        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("rl.p", ("r1cs", r1cs_proof), ("rlw", com_relu_wit), ("mmw", com_mimc_wit), ("cph", cph));
        }
    };

    struct ModelProof{ //inference proof
        ReluAndEncProof relu_enc_proof;

        bool operator==(ModelProof const& right) const {
            return relu_enc_proof == right.relu_enc_proof;
        }
        bool operator!=(ModelProof const& right) const { return !(*this == right); }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("md.p", ("sb.p", relu_enc_proof));
        }

        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("md.p", ("sb.p", relu_enc_proof));
        }
    };

    struct KeyProof{
        G1 com_d, com_w, com_t0, com_t1;
        std::vector<ElgamalCph> enc_b;

        std::vector<Fr> z, r_com_u;
        Fr r_com_z, r_com_v, r_com_t;

        bool operator==(KeyProof const& right) const {
            return com_d == right.com_d && com_w == right.com_w && com_t1 == right.com_t1 &&
                    enc_b == right.enc_b && z == right.z && r_com_u == right.r_com_u && 
                    r_com_z == right.r_com_z && r_com_v == right.r_com_v && com_t0 == right.com_t0;
        }
        bool operator!=(KeyProof const& right) const { return !(*this == right); }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("ky.p", ("cd", com_d), ("cw", com_w), ("eb", enc_b),
                                ("fz", z), ("fu", r_com_u), ("rz", r_com_z), ("rv", r_com_v),
                                ("ct0", com_t0), ("ct0", com_t1), ("ft", r_com_t));
        }

        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("ky.p", ("cd", com_d), ("cw", com_w), ("eb", enc_b),
                                ("fz", z), ("fu", r_com_u), ("rz", r_com_z), ("rv", r_com_v),
                                ("ct0", com_t0), ("ct0", com_t1), ("ft", r_com_t));
        }
    };

    /**
     * 假设对于买方和卖方公钥以及模型参数的承诺已知
     */
    struct Message{
        std::vector<ElgamalCph> enc_sub_key; //子密钥密文
        G1 com_k, com_bits; //密钥承诺, 比特承诺
        ModelProof model_proof; //推理证明
        KeyProof key_proof; //密钥证明

        bool operator==(Message const& right) const {
            return model_proof == right.model_proof && key_proof == right.key_proof &&
                    com_k == right.com_k && com_bits == right.com_bits && enc_sub_key == right.enc_sub_key;
        }
        bool operator!=(Message const& right) const { return !(*this == right); }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("msg.p", ("md.p", model_proof), ("ky.p", key_proof),
                                ("ck", com_k), ("cbs", com_bits), ("esy", enc_sub_key));
        }

        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("msg.p", ("md.p", model_proof), ("ky.p", key_proof),
                                ("ck", com_k), ("cbs", com_bits), ("esy", enc_sub_key));
        }
    };

    static void UpdateSeed(h256_t& seed, G1 const& com_k, G1 const& com_bits, 
                          std::vector<ElgamalCph> const& enc_sub_key);

    static void BuildHpCom(std::vector<std::vector<Fr>> const& w,
                         std::vector<G1> const &com_w,
                         std::vector<Fr> const &com_w_r,
                         libsnark::linear_combination<Fr> const &lc,
                         std::vector<Fr> &data, G1 &com_pub, Fr &com_sec,G1 const &sigma_g);

    static void BuildHpCom(std::vector<G1> const &com_w,
                        libsnark::linear_combination<Fr> const &lc,
                        G1 &com_pub, G1 const &sigma_g);

    static void BuildHpVec(libsnark::linear_combination<Fr> const &lc, std::vector<Fr> & a);

    static void ElgamalEnc(G1 const& pk, std::vector<Fr> const& msg, std::vector<Fr> const& r_enc_msg, std::vector<ElgamalCph> &cph);

    static void ElgamalEnc(G1 const& pk, Fr const& msg, Fr const& r_enc_msg, ElgamalCph &cph);

    static void ElgamalDec(Fr const& sk, std::vector<ElgamalCph> const& cph, std::vector<Fr> &msg);

    static void LoadPara(Matrix& para);

    static void LoadInput(Matrix& input);

    static void ComputeMatrixCom(MatrixCommitmentPub& com_pub, MatrixCommitmentSec& com_sec, Matrix const& para);

    static void ComputeEncWitness(Matrix const& in, std::vector<Matrix> & out);

    static void ComputeReluWitness(Matrix const& in, std::vector<Matrix> & out);

    static void ReluAndEncProve(h256_t seed, ReluAndEncProof& proof,
                            Matrix const& input,
                            MatrixCommitmentPub const& para_com_pub,
                            MatrixCommitmentSec const& para_com_sec);

    static bool ReluAndEncVerify(h256_t seed, ReluAndEncProof const& proof,
                            MatrixCommitmentPub const& input_com_pub);

    static void ModelProve(h256_t seed, ModelProof& proof,
                            Matrix const& input,
                            Matrix const& para,
                            MatrixCommitmentPub const& para_com_pub,
                            MatrixCommitmentSec const& para_com_sec);

    static bool ModelVerify(h256_t seed, ModelProof const& proof,
                            Matrix const& input,
                            MatrixCommitmentPub const& para_com_pub);

    static void KeyProve(h256_t seed, KeyProof & proof,
                          Fr const& k, Fr const& r_com_k, G1 const& com_k,
                          std::vector<Fr> const& bits, Fr const& r_com_bits, G1 const& com_bits, 
                          std::vector<Fr> const& sub_key, std::vector<Fr> const& r_enc_sub_key, std::vector<ElgamalCph> const& enc_sub_key);

    static bool KeyVerify(h256_t seed, KeyProof & proof, G1 const& com_k,
                    G1 const& com_bits, std::vector<ElgamalCph> const& enc_sub_key);

    static void Preprocess(libsnark::protoboard<Fr> const& pb, std::vector<std::vector<Fr>> & a, std::vector<std::vector<Fr>> & b, std::vector<std::vector<Fr>> & c);

    static bool TestModel();

    static bool TestKey();

    static bool Test();
};

void MLP::BuildHpVec(libsnark::linear_combination<Fr> const &lc, std::vector<Fr> & a){
    for (auto const &term : lc.terms) {
        a[term.index] += term.coeff;
    }
}

//预处理
void MLP::Preprocess(libsnark::protoboard<Fr> const& pb, std::vector<std::vector<Fr>> & a, std::vector<std::vector<Fr>> & b, std::vector<std::vector<Fr>> & c){
    a.resize(pb.num_constraints(), std::vector<Fr>(pb.num_variables() + 1, 0));
    b.resize(pb.num_constraints(), std::vector<Fr>(pb.num_variables() + 1, 0));
    c.resize(pb.num_constraints(), std::vector<Fr>(pb.num_variables() + 1, 0));
    auto parallel_f= [&pb, &a, &b, &c](size_t i) {
        BuildHpVec(pb.get_constraint_system().constraints[i].a, a[i]);
        BuildHpVec(pb.get_constraint_system().constraints[i].b, b[i]);
        BuildHpVec(pb.get_constraint_system().constraints[i].c, c[i]);
    };
    parallel::For(pb.num_constraints(), parallel_f);
}

void MLP::UpdateSeed(h256_t& seed, G1 const& com_k, G1 const& com_bits, 
                      std::vector<ElgamalCph> const& enc_sub_key){
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    HashUpdate(hash, com_k);
    HashUpdate(hash, com_bits);
    for(int i=0; i<enc_sub_key.size(); i++){
        HashUpdate(hash, enc_sub_key[i].c1);
        HashUpdate(hash, enc_sub_key[i].c2);
    }
    hash.Final(seed.data());
}

/**
 * w: witness矩阵
 * com_w: witness矩阵的承诺
 * com_w_r: witness矩阵承诺的blind factor
 * lc: 线性组合
 * data: 向量矩阵乘的结果
 * com_pub: data的承诺
 * com_sec: data承诺的blind factor
 * sigma_g: 对向量1的承诺
 */
void MLP::BuildHpCom(std::vector<std::vector<Fr>> const& w, //s*n
                         std::vector<G1> const &com_w, //s
                         std::vector<Fr> const &com_w_r, //s
                         libsnark::linear_combination<Fr> const &lc,
                         std::vector<Fr> &data, G1 &com_pub, Fr &com_sec,G1 const &sigma_g) { //m*n, m, m
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

void MLP::BuildHpCom(std::vector<G1> const &com_w,
                        libsnark::linear_combination<Fr> const &lc,
                        G1 &com_pub, G1 const &sigma_g) {
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

void MLP::ElgamalEnc(G1 const& pk, Fr const& msg, Fr const& r_enc_msg, ElgamalCph &cph){
    cph.c1 = pc::kGetRefG1(0) * r_enc_msg;
    cph.c2 = pk * r_enc_msg + pc::kGetRefG1(0) * msg;
}

void MLP::ElgamalEnc(G1 const& pk, std::vector<Fr> const& msg, std::vector<Fr> const& r_enc_msg, std::vector<ElgamalCph> &cph){
    cph.resize(msg.size());
    for(int i=0; i<msg.size(); i++){
        cph[i].c1 = pc::kGetRefG1(0) * r_enc_msg[i];
        cph[i].c2 = pk * r_enc_msg[i] + pc::kGetRefG1(0) * msg[i];
    }
}

void MLP::ElgamalDec(Fr const& sk, std::vector<ElgamalCph> const& cph, std::vector<Fr> &msg){
    msg.resize(cph.size());
    std::map<G1, Fr> table;
    for(int i=0; i<256; i++){
        table[pc::kGetRefG1(0) * Fr(i)] = Fr(i);
    }
    for(int i=0; i<cph.size(); i++){
        msg[i] = table[cph[i].c2 - cph[i].c1 * sk];
    }
}

void MLP::LoadPara(Matrix& para){
    Tick tick(__FN__);

    namespace fp = circuit::fp;

    std::vector<std::vector<double>> dense;
    std::vector<double> bias;

    std::ifstream weight_infile("/home/dj/1.weight.csv");
    std::ifstream bias_infile("/home/dj/1.bias.csv");

    std::string line;
    while (std::getline(weight_infile, line)) {
        std::istringstream iss(line);
        std::string token;
        dense.push_back(std::vector<double>());
        while (std::getline(iss, token, ',')) {
            dense[dense.size()-1].push_back(std::stod(token));  // 将字符串转换为double
        }
    }

    while (std::getline(bias_infile, line)) {
        std::istringstream iss(line);
        bias.push_back(std::stod(line));  // 将字符串转换为double
    }

    //参数矩阵多一行bias
    for (size_t i = 0; i < n; ++i) { //1024
        for (size_t j = 0; j < n; ++j) { //1024
            para.matrix[j][i] = fp::DoubleToRational<D, N>(dense[i][j]);
        }
    };

    for(size_t i = 0; i < n; ++i){
        para.matrix[n][i] = fp::DoubleToRational<D, N>(bias[i]);
    }
}

void MLP::LoadInput(Matrix& input){ //14 * 4
    Tick tick(__FN__);

    namespace fp = circuit::fp;

    std::vector<std::vector<double>> in;

    std::ifstream input_infile("/home/dj/input_tensor.csv");
  
    std::string line;
    while (std::getline(input_infile, line)) {
        std::istringstream iss(line);
        std::string token;
        in.push_back(std::vector<double>());
        while (std::getline(iss, token, ',')) {
            in[in.size()-1].push_back(std::stod(token));  // 将字符串转换为double
        }
    }

    input.matrix.resize(in.size(), std::vector<Fr>(n+1, 0)); //列数+1, 填充0, 用于乘以bias
    for(int i=0; i<in.size(); i++){
        for(int j=0; j<n; j++){
            input.matrix[i][j] = fp::DoubleToRational<D, N>(in[i][j]);
        }
    }
}

/**
 * 计算矩阵的承诺
 */
void MLP::ComputeMatrixCom(MatrixCommitmentPub& com_pub, MatrixCommitmentSec& com_sec, Matrix const& para) {
    Tick tick(__FN__);

    auto parallel_f = [&para, &com_sec, &com_pub](int64_t i) {
        com_sec.r_com_matrix[i] = FrRand();
        com_pub.com_matrix[i] = pc::ComputeCom(para.matrix[i], com_sec.r_com_matrix[i]);
    };

    parallel::For(para.m(), parallel_f);
}

void MLP::ComputeEncWitness(Matrix const& in, std::vector<Matrix> & out){
    Tick tick(__FN__);

    libsnark::protoboard<Fr> pb;
    circuit::Mimc5Gadget gadget(pb, "Mimc5Gadget");
    out.resize(in.m(), Matrix(pb.num_variables() + 1, in.n())); //添加常数1

    auto parallel_f = [&in, &out](size_t num) {
        libsnark::protoboard<Fr> pb;
        circuit::Mimc5Gadget gadget(pb, "Mimc5Gadget");
        size_t i = num / in.n(), j = num % in.n();
        gadget.Assign(num, key);
        std::vector<Fr> wit = pb.full_variable_assignment();
        wit.insert(wit.begin(), 1);
        CopyRowToLine(out[i].matrix, wit, j);
    };
    parallel::For(in.m() * in.n(), parallel_f);
}

//out = Relu(in)
void MLP::ComputeReluWitness(Matrix const& in, std::vector<Matrix> & out){
    Tick tick(__FN__);

    libsnark::protoboard<Fr> pb;
    circuit::fixed_point::Relu2Gadget<D, 2*N, N> gadget(pb, "relu gadget");
    out.resize(in.m(), Matrix(pb.num_variables() + 1, in.n())); //添加常数1

    auto parallel_f = [&in, &out](size_t num) {
        libsnark::protoboard<Fr> pb;
        circuit::fixed_point::Relu2Gadget<D, 2*N, N> gadget(pb, "relu gadget");
        size_t i = num / in.n(), j = num % in.n();
        gadget.Assign(in.matrix[i][j]);
        std::vector<Fr> wit = pb.full_variable_assignment();
        wit.insert(wit.begin(), 1);
        CopyRowToLine(out[i].matrix, wit, j);
    };
    parallel::For(in.m() * in.n(), parallel_f);
}

void MLP::ReluAndEncProve(h256_t seed, ReluAndEncProof& proof,
                    Matrix const& input,
                    MatrixCommitmentPub const& input_com_pub,
                    MatrixCommitmentSec const& input_com_sec){
    Tick tick(__FN__);

    libsnark::protoboard<Fr> pb_relu;
    circuit::fixed_point::Relu2Gadget<D, 2*N, N> relu_gadget(pb_relu, "relu gadget");

    libsnark::protoboard<Fr> pb_mimc;
    circuit::Mimc5Gadget mimc_gadget(pb_mimc, "Mimc5Gadget");

    //计算 relu 的 witness
    std::vector<Matrix> relu_wit; //(60 + 1) * 1000
    ComputeReluWitness(input, relu_wit);

    //计算 mimc 的 witness
    std::vector<Matrix> mimc_wit; //(332 + 1) * 1000
    ComputeEncWitness(input, mimc_wit);

    std::cout << "relu wit size:" << relu_wit[0].m() << "\t" << relu_wit[0].n() << "\n";
    std::cout << "relu r1cs size:" << relu_A.size() << "\t" << relu_A[0].size() << "\n";

    std::cout << "mimc wit size:" << mimc_wit[0].m() << "\t" << mimc_wit[0].n() << "\n";
    std::cout << "mimc r1cs size:" << mimc_A.size() << "\t" << mimc_A[0].size() << "\n";

    //计算 relu witness 的承诺
    std::vector<MatrixCommitmentPub> relu_wit_com_pub(relu_wit.size(), MatrixCommitmentPub(relu_wit[0].m()));
    std::vector<MatrixCommitmentSec> relu_wit_com_sec(relu_wit.size(), MatrixCommitmentSec(relu_wit[0].m()));

    auto pds_sigma_g = pc::ComputeSigmaG(0, relu_wit[0].n());
    {
        Tick tick("parallel_f1");
        auto parallel_f1 = [&input, &input_com_pub, &input_com_sec, &relu_wit, &relu_wit_com_pub, &relu_wit_com_sec, &pds_sigma_g](int64_t num) {
            int i = num / relu_wit.size(), j = num % relu_wit.size();
            if(i == 0){
                relu_wit_com_pub[j].com_matrix[i] = pds_sigma_g;
                relu_wit_com_sec[j].r_com_matrix[i] = 0;
            }else if(i == 1){
                relu_wit_com_pub[j].com_matrix[i] = input_com_pub.com_matrix[j];
                relu_wit_com_sec[j].r_com_matrix[i] = input_com_sec.r_com_matrix[j];
            }else{
                relu_wit_com_sec[j].r_com_matrix[i] = FrRand();
                relu_wit_com_pub[j].com_matrix[i] = pc::ComputeCom(relu_wit[j].matrix[i], relu_wit_com_sec[j].r_com_matrix[i]);
            }
            assert(pc::ComputeCom(relu_wit[j].matrix[i], relu_wit_com_sec[j].r_com_matrix[i]) == relu_wit_com_pub[j].com_matrix[i]);
        }; 
        parallel::For(relu_wit.size() * relu_wit[0].m(), parallel_f1);
    }

    //计算 mimc witness 的承诺
    std::vector<MatrixCommitmentPub> mimc_wit_com_pub(mimc_wit.size(), MatrixCommitmentPub(mimc_wit[0].m()));
    std::vector<MatrixCommitmentSec> mimc_wit_com_sec(mimc_wit.size(), MatrixCommitmentSec(mimc_wit[0].m()));
    {
        Tick tick("parallel_f2");
        auto parallel_f2 = [&mimc_wit, &mimc_wit_com_pub, &mimc_wit_com_sec](int64_t num) {
            int i = num / mimc_wit.size(), j = num % mimc_wit.size();
            if(i == 0 || i == 1){ //i=0: 常数项1; i=1: ctr
                mimc_wit_com_sec[j].r_com_matrix[i] = 0;
            }else{
                mimc_wit_com_sec[j].r_com_matrix[i] = FrRand();
            }
            mimc_wit_com_pub[j].com_matrix[i] = pc::ComputeCom(mimc_wit[j].matrix[i], mimc_wit_com_sec[j].r_com_matrix[i]);
            assert(pc::ComputeCom(mimc_wit[j].matrix[i], mimc_wit_com_sec[j].r_com_matrix[i]) == mimc_wit_com_pub[j].com_matrix[i]);
        }; 
        parallel::For(mimc_wit.size() * mimc_wit[0].m(), parallel_f2);
    }

    //使用 R1CS 计算 ReLu 哈达吗积矩阵的承诺
    std::vector<std::vector<std::vector<Fr>>> relu_a(relu_wit.size(), std::vector<std::vector<Fr>>(pb_relu.num_constraints(), std::vector<Fr>(relu_wit[0].n(), 0)));
    std::vector<std::vector<std::vector<Fr>>> relu_b(relu_wit.size(), std::vector<std::vector<Fr>>(pb_relu.num_constraints(), std::vector<Fr>(relu_wit[0].n(), 0)));
    std::vector<std::vector<std::vector<Fr>>> relu_c(relu_wit.size(), std::vector<std::vector<Fr>>(pb_relu.num_constraints(), std::vector<Fr>(relu_wit[0].n(), 0)));
    std::vector<std::vector<Fr>> r_com_relu_a(relu_wit.size(), std::vector<Fr>(pb_relu.num_constraints(), 0));
    std::vector<std::vector<Fr>> r_com_relu_b(relu_wit.size(), std::vector<Fr>(pb_relu.num_constraints(), 0));
    std::vector<std::vector<Fr>> r_com_relu_c(relu_wit.size(), std::vector<Fr>(pb_relu.num_constraints(), 0));
    std::vector<std::vector<G1>> com_relu_a(relu_wit.size(), std::vector<G1>(pb_relu.num_constraints(), G1Zero()));
    std::vector<std::vector<G1>> com_relu_b(relu_wit.size(), std::vector<G1>(pb_relu.num_constraints(), G1Zero()));
    std::vector<std::vector<G1>> com_relu_c(relu_wit.size(), std::vector<G1>(pb_relu.num_constraints(), G1Zero()));
                     
    {
        Tick tick("parallel_f3");
        auto parallel_f3= [&relu_wit, &relu_wit_com_pub, &relu_wit_com_sec, &relu_a, &com_relu_a, &r_com_relu_a, &relu_b, &com_relu_b, &r_com_relu_b, &relu_c, &com_relu_c, &r_com_relu_c](size_t i) {
            MatrixMul(relu_A, relu_wit[i].matrix, relu_a[i]);
            MatrixMul(relu_B, relu_wit[i].matrix, relu_b[i]);
            MatrixMul(relu_C, relu_wit[i].matrix, relu_c[i]);

            MultiExpBdlo12(relu_A, relu_wit_com_pub[i].com_matrix, com_relu_a[i]);
            MultiExpBdlo12(relu_B, relu_wit_com_pub[i].com_matrix, com_relu_b[i]);
            MultiExpBdlo12(relu_C, relu_wit_com_pub[i].com_matrix, com_relu_c[i]);

            MatrixVectorMul(relu_A, relu_wit_com_sec[i].r_com_matrix, r_com_relu_a[i]);
            MatrixVectorMul(relu_B, relu_wit_com_sec[i].r_com_matrix, r_com_relu_b[i]);
            MatrixVectorMul(relu_C, relu_wit_com_sec[i].r_com_matrix, r_com_relu_c[i]);
        };
        parallel::For(relu_a.size(), parallel_f3);
    }

    //使用 R1CS 计算 Mimc 哈达吗积矩阵的承诺
    std::vector<std::vector<std::vector<Fr>>> mimc_a(mimc_wit.size(), std::vector<std::vector<Fr>>(pb_mimc.num_constraints(), std::vector<Fr>(mimc_wit[0].n(), 0)));
    std::vector<std::vector<std::vector<Fr>>> mimc_b(mimc_wit.size(), std::vector<std::vector<Fr>>(pb_mimc.num_constraints(), std::vector<Fr>(mimc_wit[0].n(), 0)));
    std::vector<std::vector<std::vector<Fr>>> mimc_c(mimc_wit.size(), std::vector<std::vector<Fr>>(pb_mimc.num_constraints(), std::vector<Fr>(mimc_wit[0].n(), 0)));
    std::vector<std::vector<Fr>> r_com_mimc_a(mimc_wit.size(), std::vector<Fr>(pb_mimc.num_constraints(), 0));
    std::vector<std::vector<Fr>> r_com_mimc_b(mimc_wit.size(), std::vector<Fr>(pb_mimc.num_constraints(), 0));
    std::vector<std::vector<Fr>> r_com_mimc_c(mimc_wit.size(), std::vector<Fr>(pb_mimc.num_constraints(), 0));
    std::vector<std::vector<G1>> com_mimc_a(mimc_wit.size(), std::vector<G1>(pb_mimc.num_constraints(), G1Zero()));
    std::vector<std::vector<G1>> com_mimc_b(mimc_wit.size(), std::vector<G1>(pb_mimc.num_constraints(), G1Zero()));
    std::vector<std::vector<G1>> com_mimc_c(mimc_wit.size(), std::vector<G1>(pb_mimc.num_constraints(), G1Zero()));
    {
        Tick tick("parallel_f4");
        auto parallel_f4= [&mimc_wit, &mimc_wit_com_pub, &mimc_wit_com_sec, &mimc_a, &com_mimc_a, &r_com_mimc_a, &mimc_b, &com_mimc_b, &r_com_mimc_b, &mimc_c, &com_mimc_c, &r_com_mimc_c](size_t i) {
            MatrixMul(mimc_A, mimc_wit[i].matrix, mimc_a[i]);
            MatrixMul(mimc_B, mimc_wit[i].matrix, mimc_b[i]);
            MatrixMul(mimc_C, mimc_wit[i].matrix, mimc_c[i]);

            MultiExpBdlo12(mimc_A, mimc_wit_com_pub[i].com_matrix, com_mimc_a[i]);
            MultiExpBdlo12(mimc_B, mimc_wit_com_pub[i].com_matrix, com_mimc_b[i]);
            MultiExpBdlo12(mimc_C, mimc_wit_com_pub[i].com_matrix, com_mimc_c[i]);

            MatrixVectorMul(mimc_A, mimc_wit_com_sec[i].r_com_matrix, r_com_mimc_a[i]);
            MatrixVectorMul(mimc_B, mimc_wit_com_sec[i].r_com_matrix, r_com_mimc_b[i]);
            MatrixVectorMul(mimc_C, mimc_wit_com_sec[i].r_com_matrix, r_com_mimc_c[i]);
        };
        parallel::For(mimc_a.size(), parallel_f4);
    }

    //生成r1cs证明 
    std::vector<std::vector<Fr>> a(relu_a.size() * (relu_a[0].size() + mimc_a[0].size()), std::vector<Fr>(n, 0));
    std::vector<std::vector<Fr>> b(a.size(), std::vector<Fr>(n, 0));
    std::vector<std::vector<Fr>> c(a.size(), std::vector<Fr>(n, 0));
    std::vector<Fr> r_com_a(a.size());
    std::vector<Fr> r_com_b(a.size());
    std::vector<Fr> r_com_c(a.size());
    std::vector<G1> com_a(a.size());
    std::vector<G1> com_b(a.size());
    std::vector<G1> com_c(a.size());
    {
        Tick tick("parallel_f5");
        auto parallel_f5= [&mimc_a, &com_mimc_a, &r_com_mimc_a, &mimc_b, &com_mimc_b, &r_com_mimc_b, &mimc_c, &com_mimc_c, &r_com_mimc_c, 
                        &relu_a, &com_relu_a, &r_com_relu_a, &relu_b, &com_relu_b, &r_com_relu_b, &relu_c, &com_relu_c, &r_com_relu_c,
                        &a, &com_a, &r_com_a, &b, &com_b, &r_com_b, &c, &com_c, &r_com_c](size_t i) {
            size_t begin = i * (relu_a[0].size() + mimc_a[0].size()), end = i * (relu_a[0].size() + mimc_a[0].size()) + relu_a[0].size();
            for(int j=begin, k=0; j<end; j++, k++){
                a[j] = std::move(relu_a[i][k]);
                b[j] = std::move(relu_b[i][k]);
                c[j] = std::move(relu_c[i][k]);
            }

            begin = end;
            end = end + mimc_b[0].size();

            for(int j=begin, k=0; j<end; j++, k++){
                a[j] = std::move(mimc_a[i][k]);
                b[j] = std::move(mimc_b[i][k]);
                c[j] = std::move(mimc_c[i][k]);
            }

            std::move(
                com_relu_a[i].begin(), com_relu_a[i].end(),
                com_a.begin() + i * (com_relu_a[0].size() + com_mimc_a[0].size())
            );

            std::move(
                com_mimc_a[i].begin(), com_mimc_a[i].end(),
                com_a.begin() + i * (com_relu_a[0].size() + com_mimc_a[0].size()) + com_relu_a[0].size()
            );

            std::move(
                com_relu_b[i].begin(), com_relu_b[i].end(),
                com_b.begin() + i * (com_relu_b[0].size() + com_mimc_b[0].size())
            );

            std::move(
                com_mimc_b[i].begin(), com_mimc_b[i].end(),
                com_b.begin() + i * (com_relu_b[0].size() + com_mimc_b[0].size()) + com_relu_b[0].size()
            );

            std::move(
                com_relu_c[i].begin(), com_relu_c[i].end(),
                com_c.begin() + i * (com_relu_c[0].size() + com_mimc_c[0].size())
            );

            std::move(
                com_mimc_c[i].begin(), com_mimc_c[i].end(),
                com_c.begin() + i * (com_relu_c[0].size() + com_mimc_c[0].size()) + com_relu_c[0].size()
            );

            std::move(
                r_com_relu_a[i].begin(), r_com_relu_a[i].end(),
                r_com_a.begin() + i * (r_com_relu_a[0].size() + r_com_mimc_a[0].size())
            );

            std::move(
                r_com_mimc_a[i].begin(), r_com_mimc_a[i].end(),
                r_com_a.begin() + i * (r_com_relu_a[0].size() + r_com_mimc_a[0].size()) + r_com_relu_a[0].size()
            );

            std::move(
                r_com_relu_b[i].begin(), r_com_relu_b[i].end(),
                r_com_b.begin() + i * (r_com_relu_b[0].size() + r_com_mimc_b[0].size())
            );

            std::move(
                r_com_mimc_b[i].begin(), r_com_mimc_b[i].end(),
                r_com_b.begin() + i * (r_com_relu_b[0].size() + r_com_mimc_b[0].size()) + r_com_relu_b[0].size()
            );

            std::move(
                r_com_relu_c[i].begin(), r_com_relu_c[i].end(),
                r_com_c.begin() + i * (r_com_relu_c[0].size() + r_com_mimc_c[0].size())
            );

            std::move(
                r_com_mimc_c[i].begin(), r_com_mimc_c[i].end(),
                r_com_c.begin() + i * (r_com_relu_c[0].size() + r_com_mimc_c[0].size()) + r_com_relu_c[0].size()
            );
        };
        parallel::For(mimc_wit.size(), parallel_f5);
    }
    libra::A1::ProveInput a1_input(a, b, c, pc::kGetRefG1);
    libra::A1::CommitmentPub a1_com_pub(com_a, com_b, com_c);
    libra::A1::CommitmentSec a1_com_sec(r_com_a, r_com_b, r_com_c);
    libra::A1::Prove(proof.r1cs_proof, seed, a1_input, a1_com_pub, a1_com_sec);

    //拷贝加密消息
    size_t relu_out_idx = relu_gadget.ret().index - 1, mimc_out_idx = mimc_gadget.result().index - 1;
    proof.cph.resize(mimc_wit.size());
    for(int i=0; i<mimc_wit.size(); i++){
        proof.cph[i] = relu_wit[i].matrix[relu_out_idx] + mimc_wit[i].matrix[mimc_out_idx];
        proof.cph[i].push_back(relu_wit_com_sec[i].r_com_matrix[relu_out_idx] + mimc_wit_com_sec[i].r_com_matrix[mimc_out_idx]);
        // misc::PrintVector(relu_wit[i].matrix[relu_out_idx]);
    }

    //将witness的承诺拷贝发布
    proof.com_mimc_wit.resize(mimc_wit.size());
    proof.com_relu_wit.resize(relu_wit.size());
    auto parallel_f6= [&proof, &relu_wit_com_pub, &mimc_wit_com_pub](size_t i) {
        proof.com_mimc_wit[i].insert(
            proof.com_mimc_wit[i].end(),
            std::make_move_iterator(mimc_wit_com_pub[i].com_matrix.begin() + 2),
            std::make_move_iterator(mimc_wit_com_pub[i].com_matrix.end())
        );

        proof.com_relu_wit[i].insert(
            proof.com_relu_wit[i].end(),
            std::make_move_iterator(relu_wit_com_pub[i].com_matrix.begin() + 2),
            std::make_move_iterator(relu_wit_com_pub[i].com_matrix.end())
        );
    };
    parallel::For(mimc_wit_com_pub.size(), parallel_f6);
}

bool MLP::ReluAndEncVerify(h256_t seed, ReluAndEncProof const& proof,
                    MatrixCommitmentPub const& input_com_pub){
    Tick tick(__FN__);

    libsnark::protoboard<Fr> pb_relu;
    circuit::fixed_point::Relu2Gadget<D, 2*N, N> relu_gadget(pb_relu, "relu gadget");

    libsnark::protoboard<Fr> pb_mimc;
    circuit::Mimc5Gadget mimc_gadget(pb_mimc, "Mimc5Gadget");

    // relu证据中的第一行可以由前一层的输出计算得到
    std::vector<std::vector<G1>> com_relu_a(input_com_pub.m(), std::vector<G1>(pb_relu.num_constraints(), G1Zero()));
    std::vector<std::vector<G1>> com_relu_b(input_com_pub.m(), std::vector<G1>(pb_relu.num_constraints(), G1Zero()));
    std::vector<std::vector<G1>> com_relu_c(input_com_pub.m(), std::vector<G1>(pb_relu.num_constraints(), G1Zero()));
    std::vector<std::vector<G1>> com_relu_wit(input_com_pub.m());

    auto pds_sigma_g = pc::ComputeSigmaG(0, n);
    auto parallel_f1= [&proof, &input_com_pub, &com_relu_wit, &pds_sigma_g](size_t i) {
        com_relu_wit[i].push_back(pds_sigma_g);
        com_relu_wit[i].push_back(input_com_pub.com_matrix[i]);
        com_relu_wit[i].insert(com_relu_wit[i].end(), proof.com_relu_wit[i].begin(), proof.com_relu_wit[i].end());
    };
    parallel::For(input_com_pub.m(), parallel_f1);

    //使用relu的R1CS构建哈达玛矩阵
    auto parallel_f2= [&com_relu_wit, &com_relu_a, &com_relu_b, &com_relu_c](size_t i) {
        MultiExpBdlo12(relu_A, com_relu_wit[i], com_relu_a[i]);
        MultiExpBdlo12(relu_B, com_relu_wit[i], com_relu_b[i]);
        MultiExpBdlo12(relu_C, com_relu_wit[i], com_relu_c[i]);
    };
    parallel::For(com_relu_a.size(), parallel_f2);

    //mimc证据中的第一行是0, 1, 2, ...
    std::vector<std::vector<G1>> com_mimc_a(input_com_pub.m(), std::vector<G1>(pb_mimc.num_constraints(), G1Zero()));
    std::vector<std::vector<G1>> com_mimc_b(input_com_pub.m(), std::vector<G1>(pb_mimc.num_constraints(), G1Zero()));
    std::vector<std::vector<G1>> com_mimc_c(input_com_pub.m(), std::vector<G1>(pb_mimc.num_constraints(), G1Zero()));
    std::vector<std::vector<G1>> com_mimc_wit(input_com_pub.m());

    std::vector<std::vector<Fr>> ctr(input_com_pub.m(), std::vector<Fr>(n, 0));
    auto parallel_f3= [&proof, &ctr, &com_mimc_wit, &pds_sigma_g](size_t i) {
        std::iota(ctr[i].begin(), ctr[i].end(), i*n);
        com_mimc_wit[i].push_back(pds_sigma_g);
        com_mimc_wit[i].push_back(pc::ComputeCom(ctr[i], FrZero()));
        com_mimc_wit[i].insert(com_mimc_wit[i].end(), proof.com_mimc_wit[i].begin(), proof.com_mimc_wit[i].end());
    };
    parallel::For(input_com_pub.m(), parallel_f3);

    //构建哈达吗积的矩阵
    auto parallel_f4= [&com_mimc_wit, &com_mimc_a, &com_mimc_b, &com_mimc_c](size_t i) {
        MultiExpBdlo12(mimc_A, com_mimc_wit[i], com_mimc_a[i]);
        MultiExpBdlo12(mimc_B, com_mimc_wit[i], com_mimc_b[i]);
        MultiExpBdlo12(mimc_C, com_mimc_wit[i], com_mimc_c[i]);
    };
    parallel::For(com_mimc_a.size(), parallel_f4);

    //组合witness
    std::vector<G1> com_a(com_mimc_a.size() * (com_relu_a[0].size() + com_mimc_a[0].size()));
    std::vector<G1> com_b(com_a.size());
    std::vector<G1> com_c(com_a.size());

    auto parallel_f5= [&com_mimc_a,&com_mimc_b,&com_mimc_c, 
                       &com_relu_a,&com_relu_b,&com_relu_c,
                       &com_a, &com_b, &com_c](size_t i) {
        std::move(
            com_relu_a[i].begin(), com_relu_a[i].end(),
            com_a.begin() + i * (com_relu_a[0].size() + com_mimc_a[0].size())
        );

        std::move(
            com_mimc_a[i].begin(), com_mimc_a[i].end(),
            com_a.begin() + i * (com_relu_a[0].size() + com_mimc_a[0].size()) + com_relu_a[0].size()
        );

        std::move(
            com_relu_b[i].begin(), com_relu_b[i].end(),
            com_b.begin() + i * (com_relu_b[0].size() + com_mimc_b[0].size())
        );

        std::move(
            com_mimc_b[i].begin(), com_mimc_b[i].end(),
            com_b.begin() + i * (com_relu_b[0].size() + com_mimc_b[0].size()) + com_relu_b[0].size()
        );

        std::move(
            com_relu_c[i].begin(), com_relu_c[i].end(),
            com_c.begin() + i * (com_relu_c[0].size() + com_mimc_c[0].size())
        );

        std::move(
            com_mimc_c[i].begin(), com_mimc_c[i].end(),
            com_c.begin() + i * (com_relu_c[0].size() + com_mimc_c[0].size()) + com_relu_c[0].size()
        );
    };
    parallel::For(com_mimc_a.size(), parallel_f5);

    libra::A1::CommitmentPub a1_com_pub(com_a, com_b, com_c);
    libra::A1::VerifyInput a1_input(com_a.size(), n, a1_com_pub, pc::kGetRefG1, pc::kGetRefG1(0));
    bool ret = libra::A1::Verify(proof.r1cs_proof, seed, a1_input);

    size_t relu_out_idx = relu_gadget.ret().index - 1, mimc_out_idx = mimc_gadget.result().index - 1;
    auto parallel_f6= [&ret, &proof, &com_relu_wit, &com_mimc_wit, &relu_out_idx, &mimc_out_idx](size_t i) {
       ret = ret && (pc::ComputeCom(n, proof.cph[i].data(), proof.cph[i][n]) == com_relu_wit[i][relu_out_idx] + com_mimc_wit[i][mimc_out_idx]);
    };
    parallel::For(com_mimc_a.size(), parallel_f6);

    return ret;
}

void MLP::ModelProve(h256_t seed, ModelProof& proof,
                        Matrix const& input,
                        Matrix const& para,
                        MatrixCommitmentPub const& para_com_pub,
                        MatrixCommitmentSec const& para_com_sec){
    Tick tick(__FN__);
    // 第一个线性层, 输入公开, 参数私有, 利用同态计算结果
    Matrix next_in;
    MatrixMul(input.matrix, para.matrix, next_in.matrix);
    MatrixCommitmentPub next_com_pub(input.m());
    MatrixCommitmentSec next_com_sec(input.m());

    auto parallel_f = [&para_com_sec, &para_com_pub, &next_com_pub, &next_com_sec, &next_in, &input](int64_t i) {
        next_com_pub.com_matrix[i] = MultiExpBdlo12(para_com_pub.com_matrix, input.matrix[i]);
        next_com_sec.r_com_matrix[i] = InnerProduct(para_com_sec.r_com_matrix, input.matrix[i]);
        assert(pc::ComputeCom(next_in.matrix[i], next_com_sec.r_com_matrix[i]) == next_com_pub.com_matrix[i]);
    };
    parallel::For(input.m(), parallel_f);

    //Relu and Enc
    ReluAndEncProve(seed, proof.relu_enc_proof, next_in, next_com_pub, next_com_sec);
}

bool MLP::ModelVerify(h256_t seed, ModelProof const& proof,
                        Matrix const& input,
                        MatrixCommitmentPub const& para_com_pub){
    //通过同态计算矩阵的承诺
    MatrixCommitmentPub next_com_pub(input.m());

    auto parallel_f = [&para_com_pub, &next_com_pub, &input](int64_t i) {
        next_com_pub.com_matrix[i] = MultiExpBdlo12(para_com_pub.com_matrix, input.matrix[i]);
    };
    parallel::For(input.m(), parallel_f);

    bool ret = ReluAndEncVerify(seed, proof.relu_enc_proof, next_com_pub);

    return ret;
}  

void MLP::KeyProve(h256_t seed, KeyProof & proof,
                          Fr const& k, Fr const& r_com_k, G1 const& com_k,
                          std::vector<Fr> const& bits, Fr const& r_com_bits, G1 const& com_bits, 
                          std::vector<Fr> const& sub_key, std::vector<Fr> const& r_enc_sub_key, std::vector<ElgamalCph> const& enc_sub_key){
    Tick tick(__FN__);
    size_t bits_len = bits.size();
    size_t sub_key_num = sub_key.size();
    size_t sub_key_len = bits_len / sub_key.size();

    //计算比特对应的承诺
    std::vector<Fr> d(bits_len);
    Fr r_com_d = FrRand();
    FrRand(d);
    G1 com_d = pc::ComputeCom(d, r_com_d);

    //密钥k对应的承诺
    Fr w = 0;
    Fr r_com_w = FrRand();

    //子密钥对应的密文
    std::vector<Fr> b(sub_key_num);
    std::vector<Fr> r_enc_b(sub_key_num);
    std::vector<ElgamalCph> enc_b(sub_key_num);

    Fr item = 0, pow2 = 1;
    for(int i=0; i<bits_len; i++){
        w += d[i] * pow2;
        item += d[i] * (1 << (i % sub_key_len));
        if(i % sub_key_len == sub_key_len - 1){
            b[i / sub_key_len] = item;
            item = 0;
        }
        pow2 *= 2;
    }

    G1 com_w = pc::ComputeCom(w, r_com_w);

    FrRand(r_enc_b);
    ElgamalEnc(pk, b, r_enc_b, enc_b);

    //用于证明bits \in {0, 1}
    std::vector<Fr> t0 = HadamardProduct(d, d), t1 = HadamardProduct(bits, d) * Fr(2) - d;
    Fr r_com_t0 = FrRand(), r_com_t1 = FrRand();
    G1 com_t0 = pc::ComputeCom(t0, r_com_t0), com_t1 = pc::ComputeCom(t1, r_com_t1);

    //挑战
    UpdateSeed(seed, com_w, com_d, enc_b);
    Fr e = H256ToFr(seed);

    //响应
    std::vector<Fr> z = d + bits * e;
    Fr r_com_z = r_com_d + r_com_bits * e;
    Fr r_com_v = r_com_w + r_com_k * e;
    Fr r_com_t = r_com_t0 + r_com_t1 * e;
    std::vector<Fr> r_com_u(sub_key_num);
    for(int i=0; i<sub_key_num; i++){
        r_com_u[i] = r_enc_b[i] + r_enc_sub_key[i] * e;
    }

    //将数据拷贝到proof
    proof.com_t0 = std::move(com_t0);
    proof.com_t1 = std::move(com_t1);
    proof.com_d = std::move(com_d);
    proof.com_w = std::move(com_w);
    proof.enc_b = std::move(enc_b);
    proof.z = std::move(z);
    proof.r_com_t = std::move(r_com_t);
    proof.r_com_u = std::move(r_com_u);
    proof.r_com_z = std::move(r_com_z);
    proof.r_com_v = std::move(r_com_v);
}

bool MLP::KeyVerify(h256_t seed, KeyProof & proof, G1 const& com_k,
                    G1 const& com_bits, std::vector<ElgamalCph> const& enc_sub_key){
    Tick tick(__FN__);
    size_t bits_len = 256, sub_key_num = 32, sub_key_len = 8;

    //生成挑战
    UpdateSeed(seed, proof.com_w, proof.com_d, proof.enc_b);
    Fr e = H256ToFr(seed);

    bool ret = (proof.com_d + com_bits * e == pc::ComputeCom(proof.z, proof.r_com_z));
    Fr v = 0, u = 0, pow2 = 1;
    for(int i=0; i<bits_len; i++){
        v += proof.z[i] * pow2; //需要考虑2^256的溢出
        u += proof.z[i] * (1 << (i % sub_key_len)); //这里最多只有8位, 无需考虑一处
        if(i % sub_key_len == sub_key_len - 1){
            size_t idx = i / sub_key_len;
            ElgamalCph enc_u;
            ElgamalEnc(pk, u, proof.r_com_u[idx], enc_u);
            ret = ret && (proof.enc_b[idx] + enc_sub_key[idx] * e == enc_u);
            u = 0;
        }
        pow2 *= 2;
    }
    ret = ret && (proof.com_w + com_k * e == pc::ComputeCom(v, proof.r_com_v));

    //验证bits \in {0, 1}
    ret = ret && (proof.com_t0 + proof.com_t1 * e == pc::ComputeCom(
                                                        HadamardProduct(
                                                            proof.z, 
                                                            proof.z - std::vector<Fr>(proof.z.size(), e)
                                                        ), proof.r_com_t
                                                    ));
    return ret;
}

bool MLP::TestKey(){
    Tick tick(__FN__);
    size_t bits_len = 256, sub_key_len = 8;
    
    //对密钥承诺
    Fr k = key;
    Fr r_com_k = FrRand();
    G1 com_k = pc::ComputeCom(k, r_com_k);

    //子密钥, 每个8bit
    std::vector<ElgamalCph> enc_sub_key;
    std::vector<Fr> sub_key(bits_len / sub_key_len, 0);
    std::vector<Fr> r_enc_sub_key(sub_key.size());
    
    //密钥比特
    Fr r_com_bits = FrRand();
    std::vector<Fr> bits(bits_len, 0);

    //将密钥 k 分解为比特, 并生成子密钥
    Fr key_item = 0;
    for(int i=0; i<bits_len; i++){
        if(k.isOdd()){
            key_item = key_item + (1 << (i % sub_key_len));
            bits[i] = 1;
            k = k - 1;
        }
        k = k / 2;
        if(i % sub_key_len == sub_key_len - 1){
            sub_key[i / sub_key_len] = key_item;
            key_item = 0;
        }
    }

    //对比特承诺
    G1 com_bits = pc::ComputeCom(bits, r_com_bits);

    //对子密钥加密
    FrRand(r_enc_sub_key);
    ElgamalEnc(pk, sub_key, r_enc_sub_key, enc_sub_key);
 
    //随机数种子
    auto seed = misc::RandH256();
    KeyProof proof;

    //生成子密钥证明
    KeyProve(seed, proof, key, r_com_k, com_k, bits, r_com_bits, com_bits, 
                sub_key, r_enc_sub_key, enc_sub_key);

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
    bool success = KeyVerify(seed, proof, com_k, com_bits, enc_sub_key);

    std::cout << "success:" << success << "\n";
    return success;
}

bool MLP::TestModel() {
    Tick tick(__FN__);

    //参数
    Matrix para(n+1, n);
    LoadPara(para);

    //输入
    Matrix input;
    LoadInput(input);

    //参数承诺
    MatrixCommitmentPub para_com_pub(n+1); // commitment
    MatrixCommitmentSec para_com_sec(n+1); // rnd
    ComputeMatrixCom(para_com_pub, para_com_sec, para);

    auto seed = misc::RandH256();

    ModelProof proof;
    ModelProve(seed, proof, input, para, para_com_pub, para_com_sec);

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
    bool success = ModelVerify(seed, proof, input, para_com_pub);;

    std::cout << "success:" << success << "\n";
    return 1;
}

bool MLP::Test(){
    Tick tick(__FN__);

    size_t bits_len = 256, sub_key_len = 8;

    //参数
    Matrix para(n+1, n);
    LoadPara(para);

    //输入
    Matrix input;
    LoadInput(input);

    //参数承诺
    MatrixCommitmentPub para_com_pub(n+1); // commitment
    MatrixCommitmentSec para_com_sec(n+1); // rnd
    ComputeMatrixCom(para_com_pub, para_com_sec, para);

    auto seed = misc::RandH256();
    ModelProof model_proof;
    ModelProve(seed, model_proof, input, para, para_com_pub, para_com_sec);

    //密钥承诺
    //对密钥承诺
    Fr k = key;
    Fr r_com_k = FrRand();
    G1 com_k = pc::ComputeCom(k, r_com_k);

    //子密钥, 每个8bit
    std::vector<ElgamalCph> enc_sub_key;
    std::vector<Fr> sub_key(bits_len / sub_key_len, 0);
    std::vector<Fr> r_enc_sub_key(sub_key.size());
    
    //密钥比特
    Fr r_com_bits = FrRand();
    std::vector<Fr> bits(bits_len, 0);

    //将密钥 k 分解为比特, 并生成子密钥
    Fr key_item = 0;
    for(int i=0; i<bits_len; i++){
        if(k.isOdd()){
            key_item = key_item + (1 << (i % sub_key_len));
            bits[i] = 1;
            k = k - 1;
        }
        k = k / 2;
        if(i % sub_key_len == sub_key_len - 1){
            sub_key[i / sub_key_len] = key_item;
            key_item = 0;
        }
    }

    //对比特承诺
    G1 com_bits = pc::ComputeCom(bits, r_com_bits);

    //对子密钥加密
    FrRand(r_enc_sub_key);
    ElgamalEnc(pk, sub_key, r_enc_sub_key, enc_sub_key);

    KeyProof key_proof;

    //生成子密钥证明
    KeyProve(seed, key_proof, key, r_com_k, com_k, bits, r_com_bits, com_bits, 
                sub_key, r_enc_sub_key, enc_sub_key);

    //构造传输的消息
    Message msg;
    msg.enc_sub_key = std::move(enc_sub_key);
    msg.com_k = std::move(com_k); //在实际场景中应该使用model proof中的密钥承诺
    msg.com_bits = std::move(com_bits);
    msg.model_proof = std::move(model_proof);
    msg.key_proof = std::move(key_proof);

    //验证者只能使用msg中的消息进行验证

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
#endif
    //input 以及参数承诺已知
    bool success = ModelVerify(seed, msg.model_proof, input, para_com_pub);
    success = success && KeyVerify(seed, msg.key_proof, msg.com_k, msg.com_bits, msg.enc_sub_key);
    assert(success);

    //一旦验证成功, 可以获取私钥, 并解密数据
    libsnark::protoboard<Fr> pb_relu;
    circuit::fixed_point::Relu2Gadget<D, 2*N, N> relu_gadget(pb_relu, "relu gadget");
    size_t relu_out_idx = relu_gadget.ret().index - 1;

    std::vector<std::vector<Fr>> ctr(input.m(), std::vector<Fr>(n, 0));
    std::vector<std::vector<Fr>> data(input.m(), std::vector<Fr>(n, 0));
    for(int i=0; i<input.m(); i++){
        std::iota(ctr[i].begin(), ctr[i].end(), i*n);
        for(int j=0; j<n; j++){
            ctr[i][j] =  circuit::Mimc5Enc(ctr[i][j], key);
            data[i][j] = msg.model_proof.relu_enc_proof.cph[i][j] - ctr[i][j];
        }
        // misc::PrintVector(data[i]);
    }
    std::cout << "success:" << success << "\n";
    return success;
}
}
