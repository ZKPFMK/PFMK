#pragma once

#include "./details.h"
#include "hyrax/hyrax.h"
namespace libra{

// Ai, Bi, Ci: secret Fr, m*n
// open: com(gx, Ai), com(gy, Bi), com(gz,Ci)
// prove: Ai \circ Bi = Ci, 哈达吗积
// proof size:
// prove cost:
// verify cost:

struct A3{

    struct CommitmentPub {
        std::vector<std::vector<G1>> a;  // a.size = m
        std::vector<std::vector<G1>> b;  // b.size = k
        std::vector<std::vector<G1>> c;  // c.size = m
        CommitmentPub(){}
        CommitmentPub(std::vector<std::vector<G1>> const& a,
                      std::vector<std::vector<G1>> const& b,
                      std::vector<std::vector<G1>> const& c)
            :   a(a), b(b), c(c) {
            assert(!a.empty() && a.size() == b.size() && b.size() == c.size());
            if(DEBUG_CHECK){
                for(int i=1; i<a.size(); i++){
                    assert(a[i].size() == a[0].size() && a[i].size() == b[i].size() && b[i].size() == c[i].size());
                }
            }
        }

        int64_t m() const { return a[0].size(); }
        int64_t k() const { return a.size(); }
    };

    struct CommitmentSec {
        std::vector<std::vector<Fr>> alpha;  // r.size = m
        std::vector<std::vector<Fr>> beta;  // s.size = k
        std::vector<std::vector<Fr>> theta;  // t.size = m
        CommitmentSec(){}

        CommitmentSec(std::vector<std::vector<Fr>> const& alpha,
                      std::vector<std::vector<Fr>> const& beta,
                      std::vector<std::vector<Fr>> const& theta)
            :   alpha(alpha), beta(beta), theta(theta) {}
    };
    
    struct CommitmentExtPub {
        CommitmentExtPub() {}
        std::vector<G1> com_u;
        std::vector<G1> com_w;
    
        bool operator==(CommitmentExtPub const& right) const {
            return com_u == right.com_u && com_w == right.com_w;
        }
        bool operator!=(CommitmentExtPub const& right) const {
            return !(*this == right);
        }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("a2.cep", ("u", com_u), ("w", com_w));
        }
        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("a2.cep", ("u", com_u), ("w", com_w));
        }
    };

    struct CommitmentExtSec {
        std::vector<Fr> r_u;
        std::vector<Fr> r_w;

        CommitmentExtSec(std::vector<Fr> const& r_u, std::vector<Fr> const& r_w)
            :   r_u(r_u), r_w(r_w){
            assert(r_w.size() == 4);
        }
    };

    struct ProveExtInput{
        std::vector<std::vector<Fr>> u; // logk * 3
        std::vector<Fr> w;
        std::vector<Fr> r; //随机数

        ProveExtInput(std::vector<std::vector<Fr>> const& u,
                      std::vector<Fr> const& r, std::vector<Fr> const& w)
            : u(u), w(w), r(r){
            assert(u.size() == r.size());
            assert(u[0].size() == 4);
            assert(w.size() == 5);
        }
    };

    struct Proof{
        CommitmentExtPub com_ext_pub;
        hyrax::A1::Proof proof_a1;
        hyrax::A7::Proof proof_a7_open;
        hyrax::A7::Proof proof_a7;

        bool operator==(Proof const& right) const {
            return com_ext_pub == right.com_ext_pub && proof_a1 == right.proof_a1 &&
                proof_a7_open == right.proof_a7_open && proof_a7 == right.proof_a7;
        }
        bool operator!=(Proof const& right) const { return !(*this == right); }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("a2.pf", ("c", com_ext_pub), ("1p", proof_a1),
                            ("7.1p", proof_a7_open), ("7.2p", proof_a7));
        }

        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("a2.pf", ("c", com_ext_pub), ("1p", proof_a1),
                            ("7.1p", proof_a7_open), ("7.2p", proof_a7));
        }
    };


    struct ProveInput{
        std::vector<std::vector<std::vector<Fr>>> a; // m*k
        std::vector<std::vector<std::vector<Fr>>> b; // k*n
        std::vector<std::vector<std::vector<Fr>>> c; // m*n
        GetRefG1 const& get_g;

        int64_t m() const { return a[0].size(); }
        int64_t n() const { return a[0][0].size(); }
        int64_t k() const { return a.size(); }
        std::string to_string() const {
            return std::to_string(k()) + "*" + std::to_string(m()) + "*" + std::to_string(n());
        }

        ProveInput(GetRefG1 const& get_g)
            :  get_g(get_g){
        }

        ProveInput(std::vector<std::vector<std::vector<Fr>>> const& a,
                   std::vector<std::vector<std::vector<Fr>>> const& b,
                   std::vector<std::vector<std::vector<Fr>>> const& c, 
                   GetRefG1 const& get_g)
            :   a(a),
                b(b),
                c(c),
                get_g(get_g){
            Check();
        }

        private:
        void Check(){
            CHECK(!a.empty(), "");
            CHECK(a.size() == b.size() && a.size() == c.size() && 
                  a[0].size() == b[0].size() && a[0].size() == c[0].size() &&
                  a[0][0].size() == b[0][0].size() && a[0][0].size() == c[0][0].size(), "");
            if(DEBUG_CHECK){
                for(int i=0; i<k(); i++){
                    for(int j=0; j<m(); j++){
                        CHECK(HadamardProduct(a[i][j], b[i][j]) == c[i][j], std::to_string(i) + "\t" +std::to_string(j));
                    }
                }
            }
        }
    };


    struct VerifyInput {
        VerifyInput(int64_t const& k_, int64_t const& m_, int64_t const& n_,
                    CommitmentPub const& com_pub, GetRefG1 const& get_g)
            :   m_(m_),
                n_(n_),
                k_(k_),
                com_pub(com_pub),
                get_g(get_g) {
                CHECK(com_pub.m() == m_ && com_pub.k() == k_, "");
            }
            CommitmentPub const& com_pub;
            GetRefG1 const& get_g;
            size_t m_, n_, k_;
            size_t m() const { return m_; }
            size_t n() const { return n_; }
            size_t k() const { return k_; }
            std::string to_string() const {
            return std::to_string(k_) + "*" + std::to_string(m_) + "*" + std::to_string(n_);
        }
    };

    static void Prove(Proof& proof, h256_t seed, ProveInput const& input,
                      CommitmentPub const& com_pub, CommitmentSec const& com_sec);

    static void ProveFinal(Proof& proof, h256_t& seed, ProveInput const& input, ProveExtInput const& ext_input, 
                           CommitmentPub const& com_pub, CommitmentSec const& com_sec, CommitmentExtSec const& com_ext_sec);

    static bool Verify(Proof const& proof, h256_t seed, VerifyInput const& input);

    static void ComputeCom(CommitmentPub& com_pub, CommitmentSec& com_sec, 
                            ProveInput const& input);

    static void UpdateSeed(h256_t& seed, G1 const& a, G1 const& b, 
                           G1 const& c, G1 const& d);

    static void UpdateSeed(h256_t &seed, G1 const& a);

    static void UpdateSeed(h256_t& seed, CommitmentPub const& com_pub,
                    int64_t const& k, int64_t const& m, int64_t const& n);

    template <typename ProofT>
    static void UpdateSeed(h256_t& seed, ProofT const& proof) {
        CryptoPP::Keccak_256 hash;
        HashUpdate(hash, seed);
        yas::mem_ostream os;
        yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
        oa.serialize(proof);
        auto buf = os.get_shared_buffer();
        HashUpdate(hash, buf.data.get(), buf.size);
        hash.Final(seed.data());
    }

    template <typename T>
    static void Divide(std::vector<T> const& t, std::vector<T>& t1,
                        std::vector<T>& t2, T const& t0) { //将t分为左右两半存储到t1, t2, 如果 |t| != 2^k, 则补0
        auto n = t.size();
        auto half = misc::Pow2UB(n) / 2;
        t1.resize(half); //x的前半部分
        t2.resize(half);
        std::copy(t.begin(), t.begin() + half, t1.begin());
        std::copy(t.begin() + half, t.end(), t2.begin());
        std::fill(t2.begin() + (n - half), t2.end(), t0);
    };

    static void BuildS(std::vector<Fr>& s, std::vector<Fr> const& c) {
        Tick tick(__FN__);
        auto round = c.size();
        s[0] = 1;
        for (size_t i = 0; i < round; ++i) {
            size_t bound = 1 << i;
            for(size_t j=bound; j>=1; j--){
                int l = (j << 1) - 1, r = l-1;
                if(r >= s.size()) continue;
                else {
                    if(l < s.size()){
                        s[l] = s[j-1] * c[i];
                    }
                    s[r] = s[j-1] * (1 - c[i]);
                }
            }
        }
    };

    static bool Test(uint64_t m, uint64_t n, uint64_t k);
};

//update u
void A3::UpdateSeed(h256_t &seed, G1 const& a) {
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    HashUpdate(hash, a);
    hash.Final(seed.data());
}

//update statement
void A3::UpdateSeed(h256_t& seed, CommitmentPub const& com_pub,
                    int64_t const& k, int64_t const& m, int64_t const& n){
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    for(int i=0; i<com_pub.k(); i++){
        for(int j=0; j<com_pub.m(); j++){
            HashUpdate(hash, com_pub.a[i][j]);
            HashUpdate(hash, com_pub.b[i][j]);
            HashUpdate(hash, com_pub.c[i][j]);
        }
    }
    HashUpdate(hash, k);
    HashUpdate(hash, m);
    HashUpdate(hash, n);
    hash.Final(seed.data());
}


//update w1, w2, w3, w
void A3::UpdateSeed(h256_t& seed, G1 const& a, G1 const& b, G1 const& c, G1 const& d){
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    HashUpdate(hash, a);
    HashUpdate(hash, b);
    HashUpdate(hash, c);
    HashUpdate(hash, d);
    hash.Final(seed.data());
}


void A3::ProveFinal(Proof& proof, h256_t& seed, ProveInput const& input, ProveExtInput const& ext_input, 
                    CommitmentPub const& com_pub, CommitmentSec const& com_sec, CommitmentExtSec const& com_ext_sec){
    //计算挑战
    int64_t roundm = (int64_t)misc::Log2UB(input.m()), roundn = (int64_t)misc::Log2UB(input.n()*input.k());
    int64_t round = roundm + roundn;

    auto & r = ext_input.r;

    auto & u = ext_input.u;
    auto & r_com_u = com_ext_sec.r_u;
    auto & com_u = proof.com_ext_pub.com_u;
    
    auto & w = ext_input.w;
    auto & r_com_w = com_ext_sec.r_w;
    auto & com_w = proof.com_ext_pub.com_w;

    std::vector<Fr> e(round + 1);
    UpdateSeed(seed, com_w[1], com_w[2], com_w[3], com_w[0]);
    ComputeFst(seed, "e", e);
    
    //乘积证明
    hyrax::A1::ProveInput input_a1(w[1], w[2], w[0], input.get_g(0), input.get_g(0));
    hyrax::A1::CommitmentPub com_pub_a1(com_w[1], com_w[2], com_w[0]);
    hyrax::A1::CommitmentSec com_sec_a1(r_com_w[1], r_com_w[2], r_com_w[0]);
    hyrax::A1::Prove(proof.proof_a1, seed, input_a1, com_pub_a1, com_sec_a1);
    UpdateSeed(seed, proof.proof_a1);
    
    //open证明
    std::vector<Fr> s_rl(input.m()), s_rr(input.n() * input.k());
    std::vector<std::vector<Fr>> s_rr_vec(input.k(), std::vector<Fr>(input.n()));

     auto parallel_f1 = [&s_rl, &s_rr, &r, &roundm](int i){
        if(i == 0){
            BuildS(s_rl, std::vector<Fr>(r.begin(), r.begin() + roundm));
        }else{
            BuildS(s_rr, std::vector<Fr>(r.begin()+roundm, r.end()));
        }
    };
    parallel::For(2, parallel_f1);

    std::vector<std::vector<std::vector<Fr>>> abc(3, std::vector<std::vector<Fr>>(input.k(), std::vector<Fr>(input.n())));
    std::vector<std::vector<Fr>> r_com_abc(3, std::vector<Fr>(input.k()));
    std::vector<std::vector<G1>> com_abc(3, std::vector<G1>(input.k()));
    
    auto parallel_f2 = [&input, &com_pub, &com_sec, &com_abc, &r_com_abc, &abc, &s_rl, &s_rr, &s_rr_vec](size_t i) {
        com_abc[0][i] = MultiExpBdlo12(com_pub.a[i], s_rl);
        com_abc[1][i] = MultiExpBdlo12(com_pub.b[i], s_rl);
        com_abc[2][i] = MultiExpBdlo12(com_pub.c[i], s_rl);

        r_com_abc[0][i] = InnerProduct(com_sec.alpha[i], s_rl);
        r_com_abc[1][i] = InnerProduct(com_sec.beta[i], s_rl);
        r_com_abc[2][i] = InnerProduct(com_sec.theta[i], s_rl);

        MatrixVectorMul(s_rl, input.a[i], abc[0][i]);
        MatrixVectorMul(s_rl, input.b[i], abc[1][i]);
        MatrixVectorMul(s_rl, input.c[i], abc[2][i]);

        int64_t begin_i = i * input.n(), end_i = begin_i + input.n();
        std::copy(s_rr.begin() + begin_i, s_rr.begin() + end_i, s_rr_vec[i].begin());
    };
    parallel::For(input.k(), parallel_f2);


    // std::vector<std::vector<Fr>> d = abc[0] * e[0] + abc[1] * e[1] + abc[2] * e[2];
    // std::vector<G1> com_d = com_abc[0] * e[0] + com_abc[1] * e[1] + com_abc[2] * e[2];
    // std::vector<Fr> r_com_d = r_com_abc[0] * e[0] + r_com_abc[1] * e[1] + r_com_abc[2] * e[2];

    // Fr t = w[1] * e[0] + w[2] * e[1] + w[3] * e[2];
    // G1 com_t = com_w[1] * e[0] + com_w[2] * e[1] + com_w[3] * e[2];
    // Fr r_com_t = r_com_w[1] * e[0] + r_com_w[2] * e[1] + r_com_w[3] * e[2];

    // hyrax::A7::CommitmentPub com_pub_a7_open(com_d, com_t);
    // hyrax::A7::CommitmentSec com_sec_a7_open(r_com_d, r_com_t);

    // hyrax::A7::ProveInput input_a7_open("mle", d, s_rr_vec, t, input.get_g, input.get_g(0));
    // hyrax::A7::Prove(proof.proof_a7_open, seed, input_a7_open, com_pub_a7_open, com_sec_a7_open);
    // UpdateSeed(seed, proof.proof_a7_open);

    // //SumCheck证明
    // Fr exp = e[e.size() - 1] * w[4];
    // t = (w[0] - w[3]) * exp;
    // com_t = (com_w[0] - com_w[3]) * exp;
    // r_com_t = (r_com_w[0] - r_com_w[3]) * exp;
    
    // std::vector<std::vector<Fr>> v(round, std::vector<Fr>(4));
    // auto parallel_f3 = [&r, &v, &e](size_t i) {
    //     v[i][0] = e[i+1] - e[i] - e[i];
    //     v[i][1] = r[i] * e[i+1];
    //     v[i][2] = v[i][1] * r[i];
    //     v[i][3] = v[i][2] * r[i];
    //     v[i][1] = v[i][1] - e[i];
    //     v[i][2] = v[i][2] - e[i];
    //     v[i][3] = v[i][3] - e[i];
    // };
    // parallel::For(round, parallel_f3);

    // hyrax::A7::CommitmentPub com_pub_a7(com_u, com_t);
    // hyrax::A7::CommitmentSec com_sec_a7(r_com_u, r_com_t);
    // hyrax::A7::ProveInput input_a7("sumcheck", u, v, t, pc::kGetRefG1, pc::kGetRefG1(0));
    // hyrax::A7::Prove(proof.proof_a7, seed, input_a7, com_pub_a7, com_sec_a7);
}

void A3::Prove(Proof& proof, h256_t seed, ProveInput const& input,
                    CommitmentPub const& com_pub, CommitmentSec const& com_sec){
    Tick tick(__FN__, std::to_string(input.k()) + "*" + std::to_string(input.m()) + "*" + std::to_string(input.n()));

    if(DEBUG_CHECK){
        for(int i=0; i<input.k(); i++){
            for(int j=0; j<input.m(); j++){
                assert(pc::ComputeCom(input.a[i][j], com_sec.alpha[i][j]) == com_pub.a[i][j]);
                assert(pc::ComputeCom(input.b[i][j], com_sec.beta[i][j]) == com_pub.b[i][j]);
                assert(pc::ComputeCom(input.c[i][j], com_sec.theta[i][j]) == com_pub.c[i][j]);
            }
        }
    }
    
    int64_t k = input.k(), m = input.m(), n = input.n();
    
    std::vector<Fr> r_com_a(k*m), r_com_b(k*m), r_com_c(k*m);
    std::vector<std::vector<Fr>> a(k*m), b(k*m), c(k*m);
    std::vector<G1> com_a(k*m), com_b(k*m), com_c(k*m);

    //  auto parallel_f = [&input, &com_sec, &com_pub](int64_t i) {
    //     com_sec.r_com_matrix[i] = FrRand();
    //     com_pub.com_matrix[i] = pc::ComputeCom(para.matrix[i], com_sec.r_com_matrix[i]);
    // };

    // parallel::For(k * m, parallel_f);
   

    // ProveExtInput ext_input(u, r, w);
    // CommitmentExtSec com_ext_sec(r_com_u, r_com_w);
    // proof.com_ext_pub.com_u = std::move(com_u);
    // proof.com_ext_pub.com_w = std::move(com_w);
    // ProveFinal(proof, seed, input, ext_input, com_pub, com_sec, com_ext_sec);
}

bool A3::Verify(Proof const& proof, h256_t seed, VerifyInput const& input){
    Tick tick(__FN__, input.to_string());

    bool ret1 = false, ret2 = false, ret3 = false;

    int64_t m = input.m(), n = input.n() * input.k();
    int64_t roundm = (int64_t)misc::Log2UB(m), roundn = (int64_t)misc::Log2UB(n);
    int64_t round = roundm + roundn;

    auto const& com_a = input.com_pub.a;
    auto const& com_b = input.com_pub.b;
    auto const& com_c = input.com_pub.c;
    auto const& com_u = proof.com_ext_pub.com_u;
    auto const& com_w = proof.com_ext_pub.com_w;

    std::vector<Fr> rx(round), r(round), e(round+1);
    std::vector<Fr> s_rl(m), s_rr(n);

    UpdateSeed(seed, input.com_pub, input.k(), input.m(), input.n());

    ComputeFst(seed, "libra::A3::rx", rx);

    for(int64_t loop = 0; loop < round; ++loop){
        UpdateSeed(seed, com_u[loop]);
        r[loop] = H256ToFr(seed);
    }

    UpdateSeed(seed, com_w[1], com_w[2], com_w[3], com_w[0]);
    ComputeFst(seed, "e", e);

    //验证1: 乘积证明
     hyrax::A1::CommitmentPub com_pub_a1(com_w[1], com_w[2], com_w[0]);
    hyrax::A1::VerifyInput verify_input_a1(com_pub_a1, input.get_g(0), input.get_g(0));
    ret1 = hyrax::A1::Verify(proof.proof_a1, seed, verify_input_a1);
    UpdateSeed(seed, proof.proof_a1);
     
    //验证2: open证明
    auto parallel_f1 = [&s_rl, &s_rr, &r, &roundm](int i){
        if(i == 0){
            BuildS(s_rl, std::vector<Fr>(r.begin(), r.begin() + roundm));
        }else{
            BuildS(s_rr, std::vector<Fr>(r.begin()+roundm, r.end()));
        }
    };
    parallel::For(2, parallel_f1);

    std::vector<std::vector<G1>> com_abc(3, std::vector<G1>(input.k()));
    std::vector<std::vector<Fr>> s_rr_vec(input.k(), std::vector<Fr>(input.n()));
    auto parallel_f2 = [&input, &com_a, &com_b, &com_c, &com_abc, &s_rl, &s_rr, &s_rr_vec](size_t i) {
        com_abc[0][i] = MultiExpBdlo12(com_a[i], s_rl);
        com_abc[1][i] = MultiExpBdlo12(com_b[i], s_rl);
        com_abc[2][i] = MultiExpBdlo12(com_c[i], s_rl);


        int64_t begin_i = i * input.n(), end_i = begin_i + input.n();
        std::copy(s_rr.begin() + begin_i, s_rr.begin() + end_i, s_rr_vec[i].begin());
    };
    parallel::For(input.k(), parallel_f2);

    std::vector<G1> com_d = com_abc[0] * e[0] + com_abc[1] * e[1] + com_abc[2] * e[2];
    G1 com_t = com_w[1] * e[0] + com_w[2] * e[1] + com_w[3] * e[2];

    hyrax::A7::CommitmentPub com_pub_a7_open(com_d, com_t);
    hyrax::A7::VerifyInput verify_input_a7_open("mle", com_pub_a7_open, input.get_g, s_rr_vec, input.get_g(0));
    ret2 = hyrax::A7::Verify(proof.proof_a7_open, seed, verify_input_a7_open);
    UpdateSeed(seed, proof.proof_a7_open);

    //验证3: \sum ai * bi = c
     Fr exp = e[e.size() - 1];
    std::vector<Fr> exps(round);
    std::vector<std::vector<Fr>> v(round, std::vector<Fr>(4));

    auto parallel_f3 = [&r, &rx, &v, &exps, &e](size_t i) {
        v[i][0] = e[i+1] - e[i] - e[i];
        v[i][1] = r[i] * e[i+1];
        v[i][2] = v[i][1] * r[i];
        v[i][3] = v[i][2] * r[i];
        v[i][1] = v[i][1] - e[i];
        v[i][2] = v[i][2] - e[i];
        v[i][3] = v[i][3] - e[i];

        exps[i] = rx[i] * r[i] + (1 - rx[i]) * (1 - r[i]);
    };
    parallel::For(round, parallel_f3);

    for(int i=0; i<round; i++){
        exp *= exps[i];
    }
    com_t = (com_w[0] - com_w[3]) * exp;

    hyrax::A7::CommitmentPub com_pub_a7(com_u, com_t);
    hyrax::A7::VerifyInput verify_input_a7("sumcheck", com_pub_a7, input.get_g, v, input.get_g(0));
    ret3 = hyrax::A7::Verify(proof.proof_a7, seed, verify_input_a7);

    if(!(ret1 && ret2 && ret3)){
        std::cout << "ret:" << ret1 << "\t" << ret2 << "\t" << ret3 << "\n";
        return false;
    }
    return true;
}

void A3::ComputeCom(CommitmentPub& com_pub, CommitmentSec& com_sec,
                         ProveInput const& input){
     Tick tick(__FN__, input.to_string());
    int64_t k = input.k(), m = input.m();

    com_pub.a.resize(k, std::vector<G1>(m));
    com_pub.b.resize(k, std::vector<G1>(m));
    com_pub.c.resize(k, std::vector<G1>(m));

    com_sec.alpha.resize(k, std::vector<Fr>(m));
    com_sec.beta.resize(k, std::vector<Fr>(m));
    com_sec.theta.resize(k, std::vector<Fr>(m));
    
    auto parallel_f = [&com_sec, &com_pub, &input](int64_t i) {
        int64_t row = i / input.m(), col = i % input.m();
        com_sec.alpha[row][col] = FrRand();
        com_sec.beta[row][col] = FrRand();
        com_sec.theta[row][col] = FrRand();
        com_pub.a[row][col] = pc::ComputeCom(input.a[row][col], com_sec.alpha[row][col]);
        com_pub.b[row][col] = pc::ComputeCom(input.b[row][col], com_sec.beta[row][col]);
        com_pub.c[row][col] = pc::ComputeCom(input.c[row][col], com_sec.theta[row][col]);
    };
    parallel::For(k*m, parallel_f);
}

inline bool A3::Test(uint64_t k, uint64_t m, uint64_t n) {
    Tick tick(__FN__, std::to_string(k) + " * " + std::to_string(m) + " * " + std::to_string(n));

    h256_t seed = misc::RandH256();
    
    std::vector<std::vector<std::vector<Fr>>> a(k, std::vector<std::vector<Fr>>(m, std::vector<Fr>(n))); //m*n
    std::vector<std::vector<std::vector<Fr>>> b(k, std::vector<std::vector<Fr>>(m, std::vector<Fr>(n))); //m*n
    std::vector<std::vector<std::vector<Fr>>> c(k, std::vector<std::vector<Fr>>(m, std::vector<Fr>(n))); //m*n 
        
    for(int i=0; i<k; i++){
        for(int j=0; j<m; j++){
            FrRand(a[i][j]);
            FrRand(b[i][j]);
            c[i][j] = HadamardProduct(a[i][j], b[i][j]);
        }
    }
      
    ProveInput prove_input(a, b, c, pc::kGetRefG1);
    CommitmentPub com_pub;
    CommitmentSec com_sec;

    ComputeCom(com_pub, com_sec, prove_input);
    
    Proof proof;
    Prove(proof, seed, prove_input, com_pub, com_sec);
    

#ifndef DISABLE_SERIALIZE_CHECK
    // serializeto buffer
    yas::mem_ostream os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
    oa.serialize(proof);
    std::cout << "proof size: " << os.get_shared_buffer().size << "\n";
    // serialize from buffer
    yas::mem_istream is(os.get_intrusive_buffer());
    yas::binary_iarchive<yas::mem_istream, YasBinF()> ia(is);
    Proof proof2;
    ia.serialize(proof2);
    if (proof != proof2) {
      assert(false);
      std::cout << "oops, serialize check failed\n";
      return false;
    }
#endif

    VerifyInput verify_input(k, m, n, com_pub, pc::kGetRefG1);
    bool success = Verify(proof, seed, verify_input);
    std::cout << Tick::GetIndentString() << success << "\n\n\n\n\n\n";
    return success;
}
}