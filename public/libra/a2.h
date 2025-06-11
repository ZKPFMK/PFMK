#pragma once

#include "./details.h"
#include "hyrax/hyrax.h"
namespace libra{

// A, B, C: secret Fr, m*k, k*n, m*n
// open: com(gx, A), com(gy, B), com(gz,C)
// prove: A B = C
// proof size:
// prove cost:
// verify cost:

struct A2{

    struct CommitmentPub {
        std::vector<G1> a;  // a.size = m
        std::vector<G1> b;  // b.size = k
        std::vector<G1> c;  // c.size = m
        CommitmentPub(){}
        CommitmentPub(std::vector<G1> const& a, std::vector<G1> const& b,
                      std::vector<G1> const& c)
            :   a(a), b(b), c(c) {}
    };

    struct CommitmentSec {
        std::vector<Fr> alpha;  // r.size = m
        std::vector<Fr> beta;  // s.size = k
        std::vector<Fr> theta;  // t.size = m
        CommitmentSec(){}
        CommitmentSec(std::vector<Fr> const& alpha, std::vector<Fr> const& beta,
                      std::vector<Fr> const& theta)
            :   alpha(alpha), beta(beta), theta(theta) {}
    };
    
    struct CommitmentExtPub {
        CommitmentExtPub() {}
        std::vector<G1> com_u;
        std::vector<G1> com_w;
    
        bool operator==(CommitmentExtPub const& right) const {
            return com_u == right.com_u && 
                   com_w == right.com_w;
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
        std::vector<Fr> s_rx, s_ry, r;
        std::vector<std::vector<Fr>> u, table; // logk * 3
        std::vector<Fr> w;

        ProveExtInput(std::vector<std::vector<Fr>> const& u,
                    std::vector<std::vector<Fr>> const& table,
                    std::vector<Fr> const& w, std::vector<Fr> const& r,
                    std::vector<Fr> const& s_rx, std::vector<Fr> const& s_ry)
            : u(u), table(table), w(w), r(r), s_rx(s_rx), s_ry(s_ry){
            assert(u.size() == r.size());
            assert(u[0].size() == 3 && table.size() == 3);
            assert(w.size() == 4);
        }
    };

    struct Proof{
        CommitmentExtPub com_ext_pub;
        hyrax::A1::Proof proof_a1;
        hyrax::A6::Proof proof_a6_a;
        hyrax::A6::Proof proof_a6_b;
        hyrax::A6::Proof proof_a6_c;
        hyrax::A7::Proof proof_a7;

        bool operator==(Proof const& right) const {
            return com_ext_pub == right.com_ext_pub && proof_a1 == right.proof_a1 &&
                proof_a6_a == right.proof_a6_a && proof_a6_b == right.proof_a6_b &&
                proof_a6_c == right.proof_a6_c && proof_a7 == right.proof_a7;
        }
        bool operator!=(Proof const& right) const { return !(*this == right); }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("a2.pf", ("c", com_ext_pub), ("1p", proof_a1), ("6ap", proof_a6_a), 
                             ("6bp", proof_a6_b), ("6cp", proof_a6_c), ("7p", proof_a7));
        }

        template <typename Ar>
        void serialize(Ar& ar) {
             ar& YAS_OBJECT_NVP("a2.pf", ("c", com_ext_pub), ("1p", proof_a1), ("6ap", proof_a6_a), 
                             ("6bp", proof_a6_b), ("6cp", proof_a6_c), ("7p", proof_a7));
        }
    };


    struct ProveInput{
        std::vector<std::vector<Fr>> a; // m*k
        std::vector<std::vector<Fr>> b; // k*n
        std::vector<std::vector<Fr>> c; // m*n
        GetRefG1 const& get_g;

        bool row_a, row_b, row_c;

        int64_t m() const { return a.size(); }
        int64_t k() const { return a[0].size(); }
        int64_t n() const { return b[0].size(); }

        std::string to_string() const {
            return std::to_string(m()) + "*" + std::to_string(k()) + "*" + std::to_string(n());
        }

        ProveInput(GetRefG1 const& get_g, bool row_a=false,
               bool row_b=false, bool row_c=false)
            :   get_g(get_g), row_a(row_a), row_b(row_b), row_c(row_c){
        }

        ProveInput(std::vector<std::vector<Fr>> const& a,
               std::vector<std::vector<Fr>> const& b,
               std::vector<std::vector<Fr>> const& c,
               GetRefG1 const& get_g, bool row_a=false, 
               bool row_b=false, bool row_c=false)
            :   a(a),
                b(b),
                c(c),
                row_a(row_a),
                row_b(row_b),
                row_c(row_c),
                get_g(get_g){
            Check();
        }

        private:
        void Check(){
            assert(!a.empty());
            assert(a.size() == c.size() && a[0].size() == b.size() && b[0].size() == c[0].size());
        }
    };


    struct VerifyInput {
        VerifyInput(size_t const& m_, int64_t const& k_, int64_t const& n_, CommitmentPub const& com_pub,
                    GetRefG1 const& get_g, bool row_a=false, bool row_b=false, bool row_c=false)
            :   m_(m_),
                n_(n_),
                k_(k_),
                row_a(row_a),
                row_b(row_b),
                row_c(row_c),
                com_pub(com_pub),
                get_g(get_g) {
                if(row_a){
                    CHECK(com_pub.a.size() == m_, std::to_string(com_pub.a.size()) + " " + std::to_string(m_));
                }else{
                    CHECK(com_pub.a.size() == k_, std::to_string(com_pub.a.size()) + " " + std::to_string(k_));
                }
                if(row_b){
                    CHECK(com_pub.b.size() == k_, std::to_string(com_pub.b.size()) + " " + std::to_string(k_));
                }else{
                    CHECK(com_pub.b.size() == n_, std::to_string(com_pub.b.size()) + " " + std::to_string(n_));
                }
                if(row_c){
                    CHECK(com_pub.c.size() == m_, std::to_string(com_pub.c.size()) + " " + std::to_string(m_));
                }else{
                    CHECK(com_pub.c.size() == n_, std::to_string(com_pub.c.size()) + " " + std::to_string(n_));
                }
            }

            bool row_a, row_b, row_c;

            CommitmentPub const& com_pub;
            GetRefG1 const& get_g;
            size_t m_, n_, k_;
            size_t m() const { return m_; }
            size_t k() const { return k_; }
            size_t n() const { return n_; }
            std::string to_string() const {
            return std::to_string(m()) + "*" + std::to_string(n());
        }
    };

    static void Prove(Proof& proof, h256_t seed, ProveInput const& input,
                    CommitmentPub const& com_pub, CommitmentSec const& com_sec);

    static void ProveFinal(Proof& proof, h256_t& seed, ProveInput const& input,
                           ProveExtInput const& ext_input, CommitmentPub const& com_pub,
                           CommitmentSec const& com_sec, CommitmentExtSec const& com_ext_sec);

    static bool Verify(Proof const& proof, h256_t seed, VerifyInput const& input);

    static void ComputeCom(CommitmentPub& com_pub, CommitmentSec& com_sec, 
                            ProveInput const& input);

    static void UpdateSeed(h256_t& seed, G1 const& a, G1 const& b, 
                           G1 const& c, G1 const& d);

    static void UpdateSeed(h256_t &seed, G1 const& a);

    static void UpdateSeed(h256_t& seed, CommitmentPub const& com_pub,
                           int64_t m, int64_t k, int64_t n);
    
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
    }

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
    }

    static bool Test(int64_t m, int64_t k, int64_t n);
};

//update u
void A2::UpdateSeed(h256_t &seed, G1 const& a) {
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    HashUpdate(hash, a);
    hash.Final(seed.data());
}

//update statement
void A2::UpdateSeed(h256_t& seed, CommitmentPub const& com_pub,
                    int64_t m, int64_t k, int64_t n){
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    HashUpdate(hash, com_pub.a);
    HashUpdate(hash, com_pub.b);
    HashUpdate(hash, com_pub.c);
    HashUpdate(hash, m);
    HashUpdate(hash, k);
    HashUpdate(hash, n);
    hash.Final(seed.data());
}


//update w1, w2, w3, w
void A2::UpdateSeed(h256_t& seed, G1 const& a, G1 const& b, G1 const& c, G1 const& d){
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    HashUpdate(hash, a);
    HashUpdate(hash, b);
    HashUpdate(hash, c);
    HashUpdate(hash, d);
    hash.Final(seed.data());
}


void A2::ProveFinal(Proof& proof, h256_t& seed, ProveInput const& input, ProveExtInput const& ext_input, 
                    CommitmentPub const& com_pub, CommitmentSec const& com_sec, CommitmentExtSec const& com_ext_sec){
    //计算挑战
    int64_t round = (int64_t)misc::Log2UB(input.k());

    auto & r = ext_input.r;
    auto & s_rx = ext_input.s_rx;
    auto & s_ry = ext_input.s_ry;

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
    std::vector<std::vector<Fr>> abc = ext_input.table;
    std::vector<Fr> r_com_abc(3);
    std::vector<G1> com_abc(3);
    
    std::vector<Fr> s_r(input.k());

    BuildS(s_r, r);
    auto parallel_f2 = [&input, &abc, &com_pub, &com_sec, &r_com_abc, &com_abc, &s_r, &s_rx, &s_ry](size_t i) {
       if(i == 0){
            if(input.row_a){
                com_abc[i] = MultiExpBdlo12(com_pub.a, s_rx);
                r_com_abc[i] = InnerProduct(com_sec.alpha, s_rx);
            }else{
                com_abc[i] = MultiExpBdlo12(com_pub.a, s_r);
                r_com_abc[i] = InnerProduct(com_sec.alpha, s_r);
                MatrixVectorMul(input.a, s_r, abc[i]);
            }
       }else if(i == 1){
            if(input.row_b){
                MatrixVectorMul(s_r, input.b, abc[i]);
                com_abc[i] = MultiExpBdlo12(com_pub.b, s_r);
                r_com_abc[i] = InnerProduct(com_sec.beta, s_r);
            }else{
                com_abc[i] = MultiExpBdlo12(com_pub.b, s_ry);
                r_com_abc[i] = InnerProduct(com_sec.beta, s_ry);
            }
       }else{
            if(input.row_c){
                com_abc[i] = MultiExpBdlo12(com_pub.c, s_rx);
                r_com_abc[i] = InnerProduct(com_sec.theta, s_rx);
            }else{
                com_abc[i] = MultiExpBdlo12(com_pub.c, s_ry);
                r_com_abc[i] = InnerProduct(com_sec.theta, s_ry);
                MatrixVectorMul(input.c, s_ry, abc[i]);
            }
       }
    };
    parallel::For(3, parallel_f2);


    //open a 
    hyrax::A6::CommitmentPub com_pub_a6_a(com_abc[0], com_w[1]);
    hyrax::A6::CommitmentSec com_sec_a6_a(r_com_abc[0], r_com_w[1]);
    std::unique_ptr<hyrax::A6::ProveInput> input_a6_a;
    if(input.row_a){
        input_a6_a.reset(new hyrax::A6::ProveInput("mle_a", abc[0], s_r, w[1], input.get_g, input.get_g(0)));
    }else{
        input_a6_a.reset(new hyrax::A6::ProveInput("mle_a", abc[0], s_rx, w[1], input.get_g, input.get_g(0)));
    }
    hyrax::A6::Prove(proof.proof_a6_a, seed, *input_a6_a, com_pub_a6_a, com_sec_a6_a);
    UpdateSeed(seed, proof.proof_a6_a);
    
    //open b
    hyrax::A6::CommitmentPub com_pub_a6_b(com_abc[1], com_w[2]);
    hyrax::A6::CommitmentSec com_sec_a6_b(r_com_abc[1], r_com_w[2]);
    std::unique_ptr<hyrax::A6::ProveInput> input_a6_b;
    if(input.row_b){
        input_a6_b.reset(new hyrax::A6::ProveInput("mle_b", abc[1], s_ry, w[2], input.get_g, input.get_g(0)));
    }else{
        input_a6_b.reset(new hyrax::A6::ProveInput("mle_b", abc[1], s_r, w[2], input.get_g, input.get_g(0)));
    }
    hyrax::A6::Prove(proof.proof_a6_b, seed, *input_a6_b, com_pub_a6_b, com_sec_a6_b);
    UpdateSeed(seed, proof.proof_a6_b);

    //open c
    hyrax::A6::CommitmentPub com_pub_a6_c(com_abc[2], com_w[3]);
    hyrax::A6::CommitmentSec com_sec_a6_c(r_com_abc[2], r_com_w[3]);
    std::unique_ptr<hyrax::A6::ProveInput> input_a6_c;
    if(input.row_c){
        input_a6_c.reset(new hyrax::A6::ProveInput("mle_c", abc[2], s_ry, w[3], input.get_g, input.get_g(0)));
    }else{
        input_a6_c.reset(new hyrax::A6::ProveInput("mle_c", abc[2], s_rx, w[3], input.get_g, input.get_g(0)));
    }
    hyrax::A6::Prove(proof.proof_a6_c, seed, *input_a6_c, com_pub_a6_c, com_sec_a6_c);
    UpdateSeed(seed, proof.proof_a6_c);

    //SumCheck证明
    Fr t = w[0] * e[e.size()-1] - w[3] * e[0];
    G1 com_t = com_w[0] * e[e.size() - 1] - com_w[3] * e[0];
    Fr r_com_t = r_com_w[0] * e[e.size() - 1] - r_com_w[3] * e[0];
    
    std::vector<std::vector<Fr>> v(round, std::vector<Fr>(3));
    auto parallel_f = [&r, &v, &e](size_t i) {
        v[i][0] = e[i+1] - e[i] - e[i];
        v[i][1] = r[i] * e[i+1];
        v[i][2] = v[i][1] * r[i];
        v[i][1] = v[i][1] - e[i];
        v[i][2] = v[i][2] - e[i];
    };
    parallel::For(round, parallel_f);
    
    hyrax::A7::CommitmentPub com_pub_a7(com_u, com_t);
    hyrax::A7::CommitmentSec com_sec_a7(r_com_u, r_com_t);
    hyrax::A7::ProveInput input_a7("sumcheck", u, v, t, input.get_g, input.get_g(0));
    hyrax::A7::Prove(proof.proof_a7, seed, input_a7, com_pub_a7, com_sec_a7);
}

void A2::Prove(Proof& proof, h256_t seed, ProveInput const& input,
                    CommitmentPub const& com_pub, CommitmentSec const& com_sec){
    Tick tick(__FN__, input.to_string());

    if(DEBUG_CHECK){
        if(input.row_a){ //m*k, k*n, m*n
            for(int64_t i=0; i<input.m(); i++){
                assert(pc::ComputeCom(input.get_g, input.a[i], com_sec.alpha[i]) == com_pub.a[i]);
            }
        }else{
            for(int64_t i=0; i<input.k(); i++){
                auto get_a = [&input, &i](int64_t j) -> Fr const& { return input.a[j][i]; };
                assert(pc::ComputeCom(input.m(), input.get_g, get_a, com_sec.alpha[i]) == com_pub.a[i]);
            }
        }
        if(input.row_b){
            for(int64_t i=0; i<input.k(); i++){
                assert(pc::ComputeCom(input.get_g, input.b[i], com_sec.beta[i]) == com_pub.b[i]);
            }
        }else{
            for(int64_t i=0; i<input.n(); i++){
                auto get_b = [&input, &i](int64_t j) -> Fr const& { return input.b[j][i]; };
                assert(pc::ComputeCom(input.k(), input.get_g, get_b, com_sec.beta[i]) == com_pub.b[i]);
            }
        }
        if(input.row_c){
            for(int64_t i=0; i<input.m(); i++){
                assert(pc::ComputeCom(input.get_g, input.c[i], com_sec.theta[i]) == com_pub.c[i]);
            }
        }else{
            for(int64_t i=0; i<input.n(); i++){
                auto get_c = [&input, &i](int64_t j) -> Fr const& { return input.c[j][i]; };
                assert(pc::ComputeCom(input.m(), input.get_g, get_c, com_sec.theta[i]) == com_pub.c[i]);
            }
        }
    }

    int64_t roundm = (int64_t)misc::Log2UB(input.m()), round = (int64_t)misc::Log2UB(input.k()), roundn = (int64_t)misc::Log2UB(input.n());

    std::vector<Fr> rx(roundm), ry(roundn), r(round);
    std::vector<Fr> s_r(input.k()), s_rx(input.m()), s_ry(input.n());

    std::vector<Fr> table_a(input.k());
    std::vector<Fr> table_b(input.k());
    std::vector<Fr> table_c(input.n());
    std::vector<std::vector<Fr>> copy_table(3);

    UpdateSeed(seed, com_pub, input.m(), input.k(), input.n());
    ComputeFst(seed, "libra::A2::rx", rx);
    ComputeFst(seed, "libra::A2::ry", ry);

    {
        Tick tick(__FN__, "init table");

        auto parallel_f1 = [&s_rx, &s_ry, &rx, &ry](int i){
            if(i == 0){
                BuildS(s_rx, rx);
            }else{
                BuildS(s_ry, ry);
            }
        };
        parallel::For(2, parallel_f1);

        MatrixVectorMul(s_rx, input.a, table_a);
        MatrixVectorMul(input.b, s_ry, table_b);
        MatrixVectorMul(s_rx, input.c, table_c);

        copy_table[0] = table_a;
        copy_table[1] = table_b;
        copy_table[2] = table_c;

        table_a.resize(1 << round, FrZero());
        table_b.resize(1 << round, FrZero());
    }

    std::vector<std::vector<Fr>> u(round, std::vector<Fr>(3));
    std::vector<Fr> w(4); //a(r) * b(r), a(r), b(r), c(r), x(r)
    std::vector<Fr> r_com_u(round), r_com_w(4);
    std::vector<G1> com_u(round), com_w(4);
    
    FrRand(r_com_u);
    FrRand(r_com_w);

    {
        Tick tick(__FN__, "compute sumcheck");
        for(int64_t loop = 0; loop < round; ++loop){ //round msg
            int64_t mid = table_a.size() >> 1;

            std::vector<Fr> table_al(table_a.begin(), table_a.begin() + mid), table_ar(table_a.begin() + mid, table_a.end());
            std::vector<Fr> table_bl(table_b.begin(), table_b.begin() + mid), table_br(table_b.begin() + mid, table_b.end());
            
            std::vector<Fr> ab(4); 
            ab[0] = InnerProduct(table_al, table_bl);
            ab[1] = InnerProduct(table_al, table_br);
            ab[2] = InnerProduct(table_ar, table_bl);
            ab[3] = InnerProduct(table_ar, table_br);
            
            u[loop][0] = ab[0];
            u[loop][1] = ab[2] + ab[1] - 2*ab[0];
            u[loop][2] = ab[0] + ab[3] - ab[2] - ab[1];
        
            com_u[loop] = pc::ComputeCom(input.get_g, u[loop], r_com_u[loop]);

            UpdateSeed(seed, com_u[loop]);
            r[loop] = H256ToFr(seed); //计算挑战
            
            //更新table
            Fr lv = 1 - r[loop], rv = r[loop];
            std::vector<Fr> table_ap = table_al * lv + table_ar * rv;
            std::vector<Fr> table_bp = table_bl * lv + table_br * rv;
        
            table_ap.swap(table_a);
            table_bp.swap(table_b);
        }

        w = {table_a[0] * table_b[0], table_a[0], table_b[0], InnerProduct(table_c, s_ry)};
        for(int i=0; i<4; i++){
            com_w[i] = pc::ComputeCom(input.get_g(0), w[i], r_com_w[i]);
        }
    }

    ProveExtInput ext_input(u, copy_table, w, r, s_rx, s_ry);
    CommitmentExtSec com_ext_sec(r_com_u, r_com_w);
    proof.com_ext_pub.com_u = std::move(com_u);
    proof.com_ext_pub.com_w = std::move(com_w);

    ProveFinal(proof, seed, input, ext_input, com_pub, com_sec, com_ext_sec);
}

bool A2::Verify(Proof const& proof, h256_t seed, VerifyInput const& input){
    Tick tick(__FN__, input.to_string());

    bool ret1 = false, ret21 = false, ret22 = false, ret23 = false, ret3 = false;

    int64_t roundm = (int64_t)misc::Log2UB(input.m()), round = (int64_t)misc::Log2UB(input.k()), roundn = (int64_t)misc::Log2UB(input.n());

    auto const& com_a = input.com_pub.a;
    auto const& com_b = input.com_pub.b;
    auto const& com_c = input.com_pub.c;
    auto const& com_u = proof.com_ext_pub.com_u;
    auto const& com_w = proof.com_ext_pub.com_w;

    std::vector<Fr> rx(roundm), ry(roundn), r(round), e(round+1);
    std::vector<Fr> s_rx(input.m()), s_ry(input.n()), s_r(input.k());

    UpdateSeed(seed, input.com_pub, input.m(), input.k(), input.n());
    ComputeFst(seed, "libra::A2::rx", rx);
    ComputeFst(seed, "libra::A2::ry", ry);

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
    G1 com_da, com_db, com_dc;
    std::array<parallel::VoidTask, 3> tasks1;
    tasks1[0] = [&s_rx, &rx]() {
        BuildS(s_rx, rx);
    };
    tasks1[1] = [&s_ry, &ry]() {
        BuildS(s_ry, ry);
    };
    tasks1[2] = [&s_r, &r]() {
        BuildS(s_r, r);
    };
    parallel::Invoke(tasks1);

    std::vector<G1> com_abc(3);
    std::array<parallel::VoidTask, 3> tasks2;
    tasks2[0] = [&input, &com_abc, &com_a, &s_rx, &s_r]() {
        if(input.row_a){
            com_abc[0] = MultiExpBdlo12(com_a, s_rx);
        }else{
            com_abc[0] = MultiExpBdlo12(com_a, s_r);
        }
    };
    tasks2[1] = [&input, &com_abc, &com_b, &s_ry, &s_r]() {
        if(input.row_b){
            com_abc[1] = MultiExpBdlo12(com_b, s_r);
        }else{
            com_abc[1] = MultiExpBdlo12(com_b, s_ry);
        }
    };
    tasks2[2] = [&input, &com_abc, &com_c, &s_rx, &s_ry]() {
        if(input.row_c){
            com_abc[2] = MultiExpBdlo12(com_c, s_rx);
        }else{
            com_abc[2] = MultiExpBdlo12(com_c, s_ry);
        }
    };
    parallel::Invoke(tasks2);
    
    //open a
    hyrax::A6::CommitmentPub com_pub_a6_a(com_abc[0], com_w[1]);
    std::unique_ptr<hyrax::A6::VerifyInput> verify_input_a6_a;
    if(input.row_a){
        verify_input_a6_a.reset(new hyrax::A6::VerifyInput("mle_a", s_r, com_pub_a6_a, input.get_g, input.get_g(0)));
    }else{
        verify_input_a6_a.reset(new hyrax::A6::VerifyInput("mle_a", s_rx, com_pub_a6_a, input.get_g, input.get_g(0)));
    }
    ret21 = hyrax::A6::Verify(proof.proof_a6_a, seed, *verify_input_a6_a);
    UpdateSeed(seed, proof.proof_a6_a);

    //open b
    hyrax::A6::CommitmentPub com_pub_a6_b(com_abc[1], com_w[2]);
    std::unique_ptr<hyrax::A6::VerifyInput> verify_input_a6_b;
    if(input.row_b){
        verify_input_a6_b.reset(new hyrax::A6::VerifyInput("mle_b", s_ry, com_pub_a6_b, input.get_g, input.get_g(0)));
    }else{
        verify_input_a6_b.reset(new hyrax::A6::VerifyInput("mle_b", s_r, com_pub_a6_b, input.get_g, input.get_g(0)));
    }
    ret22 = hyrax::A6::Verify(proof.proof_a6_b, seed, *verify_input_a6_b);
     UpdateSeed(seed, proof.proof_a6_b);

    //open c
    hyrax::A6::CommitmentPub com_pub_a6_c(com_abc[2], com_w[3]);
    std::unique_ptr<hyrax::A6::VerifyInput> verify_input_a6_c;
    if(input.row_c){
        verify_input_a6_c.reset(new hyrax::A6::VerifyInput("mle_c", s_ry, com_pub_a6_c, input.get_g, input.get_g(0)));
    }else{
        verify_input_a6_c.reset(new hyrax::A6::VerifyInput("mle_c", s_rx, com_pub_a6_c, input.get_g, input.get_g(0)));
    }
    ret23 = hyrax::A6::Verify(proof.proof_a6_c, seed, *verify_input_a6_c);
     UpdateSeed(seed, proof.proof_a6_c);

    //验证3: \sum ai * bi = c
    std::vector<std::vector<Fr>> v(round, std::vector<Fr>(3));
    auto parallel_f = [&r, &v, &e](size_t i) {
        v[i][0] = e[i+1] - e[i] - e[i];
        v[i][1] = r[i] * e[i+1];
        v[i][2] = v[i][1] * r[i];
        v[i][1] = v[i][1] - e[i];
        v[i][2] = v[i][2] - e[i];
    };
    parallel::For(round, parallel_f);

    G1 com_t = com_w[0] * e[e.size() - 1] - com_w[3] * e[0];
    hyrax::A7::CommitmentPub com_pub_a7(com_u, com_t);
    hyrax::A7::VerifyInput verify_input_a7("sumcheck", com_pub_a7, input.get_g, v, input.get_g(0));
    ret3 = hyrax::A7::Verify(proof.proof_a7, seed, verify_input_a7);
 

    if(!(ret1 && ret21 && ret22 && ret3)){
        std::cout << "ret:" << ret1 << "\t" << ret21 << "\t" << ret22 << "\t" << ret3 << "\n";
        return false;
    }
    return true;
}

void A2::ComputeCom(CommitmentPub& com_pub, CommitmentSec& com_sec,
                         ProveInput const& input){
    Tick tick(__FN__, input.to_string());
    auto const m = input.m(); // m*k
    auto const k = input.k(); // k*n
    auto const n = input.n(); // m*n

    if(input.row_a){
        com_pub.a.resize(m);
        com_sec.alpha.resize(m);
        FrRand(com_sec.alpha);
    }else{
        com_pub.a.resize(k);
        com_sec.alpha.resize(k);
        FrRand(com_sec.alpha);
    }

    if(input.row_b){
        com_pub.b.resize(k);
        com_sec.beta.resize(k);
        FrRand(com_sec.beta);
    }else{
         com_pub.b.resize(n);
        com_sec.beta.resize(n);
        FrRand(com_sec.beta);
    }

    if(input.row_c){
        com_pub.c.resize(m);
        com_sec.theta.resize(m);
        FrRand(com_sec.theta);
    }else{
        com_pub.c.resize(n);
        com_sec.theta.resize(n);
        FrRand(com_sec.theta);
    }
    
    int64_t mkn = k >= n ? (k>=m ? k : m) : (n>=m ? n:m);
    
    auto parallel_f = [&com_sec, &com_pub, &input](int64_t i) {
        std::array<parallel::VoidTask, 3> tasks;
        tasks[0] = [&com_pub, &input, &com_sec, i]() { //m*k
            if(input.row_a){
                if(i < input.m()){
                    com_pub.a[i] = pc::ComputeCom(input.a[i], com_sec.alpha[i]);
                }
            }else{
                if(i < input.k()){
                    auto get_a = [&input, &i](int64_t j) -> Fr const& { return input.a[j][i]; };
                    com_pub.a[i] = pc::ComputeCom(input.m(), input.get_g, get_a, com_sec.alpha[i]);
                }
            }
            
        };
        tasks[1] = [&com_pub, &input, &com_sec, i]() { //k*n
            if(input.row_b){
                if(i < input.k()){
                    com_pub.b[i] = pc::ComputeCom(input.b[i], com_sec.beta[i]);
                }
            }else{
                if(i < input.n()){
                    auto get_b = [&input, &i](int64_t j) -> Fr const& { return input.b[j][i]; };
                    com_pub.b[i] = pc::ComputeCom(input.k(), input.get_g, get_b, com_sec.beta[i]);
                }
            }
        };
        tasks[2] = [&com_pub, &input, &com_sec, i]() { //m*n
            if(input.row_c){
                if(i < input.m()){
                    com_pub.c[i] = pc::ComputeCom(input.c[i], com_sec.theta[i]);
                }
            }else{
                if(i < input.n()){
                    auto get_c = [&input, &i](int64_t j) -> Fr const& { return input.c[j][i]; };
                    com_pub.c[i] = pc::ComputeCom(input.m(), input.get_g, get_c, com_sec.theta[i]);
                }
            }
        };
        parallel::Invoke(tasks);
    };
    parallel::For(mkn, parallel_f);
}

inline bool A2::Test(int64_t m, int64_t k, int64_t n) {
    bool row_a = FrRand().isOdd();
    bool row_b = FrRand().isOdd();
    bool row_c = FrRand().isOdd();

    Tick tick(__FN__, std::to_string(m) + " " + std::to_string(row_a) + " " +
                      std::to_string(k) + " " + std::to_string(row_b) + " " +
                      std::to_string(n) + " " + std::to_string(row_c));


    h256_t seed = misc::RandH256();

    std::vector<std::vector<Fr>> a(m, std::vector<Fr>(k, 0)); //m*k
    std::vector<std::vector<Fr>> b(k, std::vector<Fr>(n, 0)); //k*n
    std::vector<std::vector<Fr>> c; //m*n 

    for(uint64_t i=0; i<m; i++){
        FrRand(a[i]);
    }
    for(uint64_t i=0; i<k; i++){
        FrRand(b[i]);
    }
   
   MatrixMul(a, b, c);

    ProveInput prove_input(a, b, c, pc::kGetRefG1, row_a, row_b, row_c);

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

    VerifyInput verify_input(m, k, n, com_pub, pc::kGetRefG1, row_a, row_b, row_c);
    bool success = Verify(proof, seed, verify_input);
    std::cout << Tick::GetIndentString() << success << "\n\n\n\n\n\n";
    return success;
}
}