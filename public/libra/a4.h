#pragma once

#include "./details.h"
#include "hyrax/hyrax.h"
namespace libra{

// A, B, C: secret Fr, m*k, k*n, m*n
// open: com(gx, A), com(gy, B), com(gz, C): col commitment
// prove: A B = C
// proof size:
// prove cost:
// verify cost:



struct A4{

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
        G1 com_w1, com_w2, com_w3, com_w;
    
        bool operator==(CommitmentExtPub const& right) const {
            return com_u == right.com_u && com_w1 == right.com_w1 &&
                   com_w2 == right.com_w2 && com_w3 == right.com_w3 && 
                   com_w == right.com_w;
        }
        bool operator!=(CommitmentExtPub const& right) const {
            return !(*this == right);
        }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("a2.cep", ("u", com_u), ("w1", com_w1), 
                              ("w2", com_w2), ("w3", com_w3), ("w", com_w));
        }
        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("a2.cep", ("u", com_u), ("w1", com_w1), 
                              ("w2", com_w2), ("w3", com_w3), ("w", com_w));
        }
    };

    struct CommitmentExtSec {
        std::vector<Fr> r_u;
        Fr r_w1, r_w2, r_w3, r_w;
    };

    struct ProveExtInput{
        std::vector<Fr> s_rx, s_ry, s_r, r;
        std::vector<std::vector<Fr>> u; // logk * 3
        Fr w1, w2, w3, w;
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
                proof_a6_a == right.proof_a6_a && proof_a6_b == right.proof_a6_b && proof_a6_c == right.proof_a6_c && proof_a7 == right.proof_a7;
        }
        bool operator!=(Proof const& right) const { return !(*this == right); }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("a2.pf", ("c", com_ext_pub), ("1p", proof_a1),
                            ("6pa", proof_a6_a), ("6pb", proof_a6_b), ("6pc", proof_a6_c), ("7p", proof_a7));
        }

        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("a2.pf", ("c", com_ext_pub), ("1p", proof_a1),
                            ("6pa", proof_a6_a), ("6pb", proof_a6_b), ("6pc", proof_a6_c), ("7p", proof_a7));
        }
    };


    struct ProveInput{
        std::vector<std::vector<Fr>> a; // m*k
        std::vector<std::vector<Fr>> b; // k*n
        std::vector<std::vector<Fr>> c; // m*n
        GetRefG1 const& get_g;
        G1 const& u;

        bool row_a, row_b, row_c;

        int64_t m() const { return a.size(); }
        int64_t k() const { return a[0].size(); }
        int64_t n() const { return b[0].size(); }

        std::string to_string() const {
            return std::to_string(m()) + "*" + std::to_string(k()) + "*" + std::to_string(n());
        }

        ProveInput(GetRefG1 const& get_g, G1 const& u)
            :   get_g(get_g),
                u(u) {
        }

        ProveInput(std::vector<std::vector<Fr>> const& a,
               std::vector<std::vector<Fr>> const& b,
               std::vector<std::vector<Fr>> const& c, 
               GetRefG1 const& get_g, G1 const& u,
               bool row_a=false, bool row_b=false, bool row_c=false)
            :   a(a),
                b(b),
                c(c),
                row_a(row_a),
                row_b(row_b),
                row_c(row_c),
                get_g(get_g),
                u(u) {
            Check();
        }

        private:
        void Check(){
            CHECK(!a.empty(), "");
            CHECK(a.size() == c.size() && a[0].size() == b.size() && b[0].size() == c[0].size(), "");
        }
    };


    struct VerifyInput {
        VerifyInput(size_t const& m_, size_t const& k_, size_t const& n_, CommitmentPub const& com_pub,
                    GetRefG1 const& get_g, G1 const& u, bool row_a=false, bool row_b=false, bool row_c=false)
            :   m_(m_),
                k_(k_),
                n_(n_),
                u(u),
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
            G1 const& u;
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

    static void BuildS2(std::vector<Fr>& s, std::vector<Fr> const& c) {
        Tick tick(__FN__);
        auto round = c.size();
        s[0] = 1;
        for (size_t i = 0; i < round; ++i) {
            size_t bound = 1 << i;
            for(size_t j=bound; j>=1; j--){
                int l = (j << 1) - 1, r = l-1;
                s[r] = s[j-1] * (1 - c[i]);
                s[l] = s[j-1] * c[i];
            }
        }
    }

    static bool Test(uint64_t m, uint64_t k, uint64_t n, bool, bool, bool);
};

//update u
void A4::UpdateSeed(h256_t &seed, G1 const& a) {
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    HashUpdate(hash, a);
    hash.Final(seed.data());
}

//update statement
void A4::UpdateSeed(h256_t& seed, CommitmentPub const& com_pub,
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
void A4::UpdateSeed(h256_t& seed, G1 const& a, G1 const& b, G1 const& c, G1 const& d){
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    HashUpdate(hash, a);
    HashUpdate(hash, b);
    HashUpdate(hash, c);
    HashUpdate(hash, d);
    hash.Final(seed.data());
}


void A4::ProveFinal(Proof& proof, h256_t& seed, ProveInput const& input, ProveExtInput const& ext_input, 
                    CommitmentPub const& com_pub, CommitmentSec const& com_sec, CommitmentExtSec const& com_ext_sec){
    //计算挑战
    int64_t round = (int64_t)misc::Log2UB(input.k());

    auto &com_ext_pub = proof.com_ext_pub;

    auto &u=ext_input.u;
    auto &r_com_u=com_ext_sec.r_u;
    auto &com_u=com_ext_pub.com_u;

    auto &s_r=ext_input.s_r, &s_rx=ext_input.s_rx, &s_ry=ext_input.s_ry, &r=ext_input.r;

    auto &w=ext_input.w, &w1=ext_input.w1, &w2=ext_input.w2, &w3=ext_input.w3;
    auto &com_w1 = com_ext_pub.com_w1, &com_w2 = com_ext_pub.com_w2, &com_w3 = com_ext_pub.com_w3, &com_w = com_ext_pub.com_w;
    auto &r_com_w1 = com_ext_sec.r_w1, &r_com_w2 = com_ext_sec.r_w2, &r_com_w3 = com_ext_sec.r_w3, &r_com_w = com_ext_sec.r_w;

    std::vector<Fr> e(round + 1);

    UpdateSeed(seed, com_w1, com_w2, com_w3, com_w);
    ComputeFst(seed, "e", e);

    //乘积证明
    hyrax::A1::ProveInput input_a1(w1, w2, w, input.get_g(0), input.get_g(0));
    hyrax::A1::CommitmentPub com_pub_a1(com_w1, com_w2, com_w);
    hyrax::A1::CommitmentSec com_sec_a1(r_com_w1, r_com_w2, r_com_w);
    hyrax::A1::Prove(proof.proof_a1, seed, input_a1, com_pub_a1, com_sec_a1);

    //open证明
    std::vector<Fr> da, db, dc;
    G1 com_da, com_db, com_dc;
    Fr r_com_da, r_com_db , r_com_dc;

    std::array<parallel::VoidTask, 3> tasks3;
    tasks3[0] = [&input, &com_pub, &com_sec, &com_da, &r_com_da, &da, &s_rx, &s_r]() {
        if(input.row_a){
            com_da = MultiExpBdlo12(com_pub.a, s_rx);
            r_com_da = InnerProduct(com_sec.alpha, s_rx);
            MatrixVectorMul(s_rx, input.a, da);
        }else{
            com_da = MultiExpBdlo12(com_pub.a, s_r);
            r_com_da = InnerProduct(com_sec.alpha, s_r);
            MatrixVectorMul(input.a, s_r, da);
        }
    };
    tasks3[1] = [&input, &com_pub, &com_sec, &com_db, &r_com_db, &db, &s_ry, &s_r]() {
        if(input.row_b){
            com_db = MultiExpBdlo12(com_pub.b, s_r);
            r_com_db = InnerProduct(com_sec.beta, s_r);
            MatrixVectorMul(s_r, input.b, db);
        }else{
            com_db = MultiExpBdlo12(com_pub.b, s_ry);
            r_com_db = InnerProduct(com_sec.beta, s_ry);
            MatrixVectorMul(input.b, s_ry, db);
        }
    };
    tasks3[2] = [&input, &com_pub, &com_sec, &com_dc, &r_com_dc, &dc, &s_rx, &s_ry]() {
        if(input.row_c){
            com_dc = MultiExpBdlo12(com_pub.c, s_rx);
            r_com_dc = InnerProduct(com_sec.theta, s_rx);
            MatrixVectorMul(s_rx, input.c, dc);
        }else{
            com_dc = MultiExpBdlo12(com_pub.c, s_ry);
            r_com_dc = InnerProduct(com_sec.theta, s_ry);
            MatrixVectorMul(input.c, s_ry, dc);
        }
        
    };
    parallel::Invoke(tasks3);

    hyrax::A6::CommitmentPub com_pub_a6_a(com_da, com_w1);
    hyrax::A6::CommitmentSec com_sec_a6_a(r_com_da, r_com_w1);
    std::unique_ptr<hyrax::A6::ProveInput> input_a6_a;

    if(input.row_a){
        input_a6_a.reset(new hyrax::A6::ProveInput("mle_a", da, s_r, w1, input.get_g, input.get_g(0)));
    }else{
        input_a6_a.reset(new hyrax::A6::ProveInput("mle_a", da, s_rx, w1, input.get_g, input.get_g(0)));
    }

    hyrax::A6::CommitmentPub com_pub_a6_b(com_db, com_w2);
    hyrax::A6::CommitmentSec com_sec_a6_b(r_com_db, r_com_w2);
    std::unique_ptr<hyrax::A6::ProveInput> input_a6_b;

    if(input.row_b){
        input_a6_b.reset(new hyrax::A6::ProveInput("mle_b", db, s_ry, w2, input.get_g, input.get_g(0)));
    }else{
        input_a6_b.reset(new hyrax::A6::ProveInput("mle_b", db, s_r, w2, input.get_g, input.get_g(0)));
    }

    hyrax::A6::CommitmentPub com_pub_a6_c(com_dc, com_w3);
    hyrax::A6::CommitmentSec com_sec_a6_c(r_com_dc, r_com_w3);
    std::unique_ptr<hyrax::A6::ProveInput> input_a6_c;

    if(input.row_c){
        input_a6_c.reset(new hyrax::A6::ProveInput("mle_c", dc, s_ry, w3, input.get_g, input.get_g(0)));
    }else{
        input_a6_c.reset(new hyrax::A6::ProveInput("mle_c", dc, s_rx, w3, input.get_g, input.get_g(0)));
    }

    hyrax::A6::Prove(proof.proof_a6_a, seed, *input_a6_a, com_pub_a6_a, com_sec_a6_a);
    hyrax::A6::Prove(proof.proof_a6_b, seed, *input_a6_b, com_pub_a6_b, com_sec_a6_b);
    hyrax::A6::Prove(proof.proof_a6_c, seed, *input_a6_c, com_pub_a6_c, com_sec_a6_c);

    //SumCheck证明
    Fr z = w*e[e.size()-1] - w3*e[0];
    hyrax::A7::CommitmentPub com_pub_a7(com_u, com_w * e[e.size() - 1] - com_w3 * e[0]);
    hyrax::A7::CommitmentSec com_sec_a7(com_ext_sec.r_u, r_com_w * e[e.size() - 1] - r_com_w3 * e[0]);

    std::vector<std::vector<Fr>> v(round);
    auto parallel_f = [&r, &v, &e](size_t i) {
        v[i].resize(3);
        Fr neg_e = -e[i];
        v[i][0] = e[i+1] + neg_e + neg_e;
        v[i][1] = r[i] * e[i+1];
        v[i][2] = v[i][1] * r[i];
        v[i][1] = v[i][1] + neg_e;
        v[i][2] = v[i][2] + neg_e;
    };
    parallel::For(round, parallel_f);
    
    hyrax::A7::ProveInput input_a7("sumcheck", u, v, z, input.get_g, input.get_g(0));
    hyrax::A7::Prove(proof.proof_a7, seed, input_a7, com_pub_a7, com_sec_a7);
}

void A4::Prove(Proof& proof, h256_t seed, ProveInput const& input,
                    CommitmentPub const& com_pub, CommitmentSec const& com_sec){
    Tick tick(__FN__, input.to_string());

    int64_t roundm = (int64_t)misc::Log2UB(input.m()), round = (int64_t)misc::Log2UB(input.k()), roundn = (int64_t)misc::Log2UB(input.n());

    ProveExtInput ext_input;
    std::vector<Fr> rx(roundm), ry(roundn);
    auto &s_r=ext_input.s_r, &s_rx=ext_input.s_rx, &s_ry=ext_input.s_ry, &r=ext_input.r;

    r.resize(round);
    s_r.resize(input.k());
    s_rx.resize(input.m());
    s_ry.resize(input.n());
    
    std::vector<Fr> table_arx(input.k(), 0);
    std::vector<Fr> table_crx(input.n(), 0);
    std::vector<Fr> table_bry(input.k());
    Fr &w=ext_input.w, &w1=ext_input.w1, &w2=ext_input.w2, &w3=ext_input.w3;

    UpdateSeed(seed, com_pub, input.m(), input.k(), input.n());
    ComputeFst(seed, "libra::A4::rx", rx);
    ComputeFst(seed, "libra::A4::ry", ry);

    {
        Tick tick(__FN__, "compute A(rx, x), B(x, ry), C(rx, ry)");
        std::array<parallel::VoidTask, 2> tasks;
        tasks[0] = [&input, &table_arx, &table_crx, &s_rx, &rx]() {
            BuildS(s_rx, rx);
            MatrixVectorMul(s_rx, input.a, table_arx);
            MatrixVectorMul(s_rx, input.c, table_crx);
        };

        tasks[1] = [&input, &table_bry, &table_crx, &w3, &s_ry, &ry, &roundn]() {
            BuildS(s_ry, ry);
            MatrixVectorMul(input.b, s_ry, table_bry);
        };
        parallel::Invoke(tasks);
        w3 = InnerProduct(table_crx, s_ry);
    }

    CommitmentExtSec com_ext_sec;
    CommitmentExtPub & com_ext_pub = proof.com_ext_pub;
    
    com_ext_sec.r_u.resize(round);
    com_ext_pub.com_u.resize(round);
    ext_input.u.resize(round, std::vector<Fr>(3));

    auto& u = ext_input.u;
    auto& com_u = com_ext_pub.com_u;
    auto& r_com_u = com_ext_sec.r_u;
    
    auto &com_w1 = com_ext_pub.com_w1, &com_w2 = com_ext_pub.com_w2, &com_w3 = com_ext_pub.com_w3, &com_w = com_ext_pub.com_w;
    auto &r_com_w1 = com_ext_sec.r_w1, &r_com_w2 = com_ext_sec.r_w2, &r_com_w3 = com_ext_sec.r_w3, &r_com_w = com_ext_sec.r_w;
    {
        Tick tick(__FN__, "compute sumcheck");
        for(int64_t loop = 0; loop < round; ++loop){ //round msg
            Fr ll, lr, rl, rr;
            int64_t mid = misc::Pow2UB(table_arx.size()) >> 1;
            int64_t len = (mid << 1) == table_arx.size() ? mid : table_arx.size() - mid;
            std::array<parallel::VoidTask, 4> tasks1;
            tasks1[0] = [&table_arx, &table_bry, &mid, &ll]() {
                ll = InnerProduct(&table_arx[0], &table_bry[0], mid);
            };
            tasks1[1] = [&table_arx, &table_bry, &mid, &len, &lr]() {
                lr = InnerProduct(&table_arx[0], &table_bry[mid], len);
            };
            tasks1[2] = [&table_arx, &table_bry, &mid, &len, &rl]() {
                rl = InnerProduct(&table_arx[mid], &table_bry[0], len);
            };
            tasks1[3] = [&table_arx, &table_bry, &mid, &len, &rr]() {
                rr = InnerProduct(&table_arx[mid], &table_bry[mid], len);
            };
            parallel::Invoke(tasks1);

            u[loop][0] = ll;
            u[loop][1] = rl+lr-2*ll;
            u[loop][2] = ll+rr-rl-lr;
            
            r_com_u[loop] = FrRand();
            com_u[loop] = pc::ComputeCom(input.get_g, u[loop], r_com_u[loop]);

            UpdateSeed(seed, com_u[loop]);
            r[loop] = H256ToFr(seed); //计算挑战

            //更新table
            Fr lv = 1 - r[loop], rv = r[loop];
            std::array<parallel::VoidTask, 2> tasks2;
            tasks2[0] = [&table_arx, &lv, &rv, &mid]() {
                std::vector<Fr> table_a1(mid), table_a2(mid);
                Divide(table_arx, table_a1, table_a2, FrZero());
                std::vector<Fr> table_ap = table_a1 * lv + table_a2 * rv;
                table_arx.swap(table_ap);
            };
            tasks2[1] = [&table_bry, &lv, &rv, &mid]() {
                std::vector<Fr> table_b1(mid), table_b2(mid);
                Divide(table_bry, table_b1, table_b2, FrZero());
                std::vector<Fr> table_bp = table_b1 * lv + table_b2 * rv;
                table_bry.swap(table_bp);
            };
            parallel::Invoke(tasks2);
        }
        
        BuildS(s_r, r);
    
        w1 = table_arx[0];
        w2 = table_bry[0];
        w = table_arx[0] * table_bry[0];

        r_com_w = FrRand();
        r_com_w1 = FrRand();
        r_com_w2 = FrRand();
        r_com_w3 = FrRand();
        
        com_w = pc::ComputeCom(input.get_g(0), w, r_com_w);
        com_w1 = pc::ComputeCom(input.get_g(0), w1, r_com_w1);
        com_w2 = pc::ComputeCom(input.get_g(0), w2, r_com_w2);
        com_w3 = pc::ComputeCom(input.get_g(0), w3, r_com_w3);
    }
   
    ProveFinal(proof, seed, input, ext_input, com_pub, com_sec, com_ext_sec);
}

bool A4::Verify(Proof const& proof, h256_t seed, VerifyInput const& input){
    Tick tick(__FN__, input.to_string());

    bool ret1 = false, ret21 = false, ret22 = false, ret23 = false, ret3 = false;

    int64_t roundm = (int64_t)misc::Log2UB(input.m()), round = (int64_t)misc::Log2UB(input.k()), roundn = (int64_t)misc::Log2UB(input.n());

    auto const& com_pub = input.com_pub;
    auto const& com_ext_pub = proof.com_ext_pub;

    auto const& com_u = com_ext_pub.com_u;
    auto const& com_w1 = com_ext_pub.com_w1, &com_w2 = com_ext_pub.com_w2, &com_w3 = com_ext_pub.com_w3, &com_w = com_ext_pub.com_w;

    std::vector<Fr> rx(roundm), ry(roundn), r(round), e(round+1);
    std::vector<Fr> s_rx(input.m()), s_ry(input.n()), s_r(input.k());

  
    UpdateSeed(seed, com_pub, input.m(), input.k(), input.n());
    ComputeFst(seed, "libra::A4::rx", rx);
    ComputeFst(seed, "libra::A4::ry", ry);

    for(int64_t loop = 0; loop < round; ++loop){
        UpdateSeed(seed, com_u[loop]);
        r[loop] = H256ToFr(seed);
    }

    UpdateSeed(seed, com_w1, com_w2, com_w3, com_w);
    ComputeFst(seed, "e", e);

    //验证1: 乘积证明

    hyrax::A1::CommitmentPub com_pub_a1(com_w1, com_w2, com_w);
    hyrax::A1::VerifyInput verify_input_a1(com_pub_a1, input.get_g(0), input.get_g(0));
    ret1 = hyrax::A1::Verify(proof.proof_a1, seed, verify_input_a1);

    //验证2: open证明
    G1 com_da, com_db, com_dc;
    std::array<parallel::VoidTask, 3> tasks1;
    tasks1[0] = [&s_rx, &rx]() {
        BuildS(s_rx, rx);
    };
    tasks1[1] = [&s_r, &r]() {
        BuildS(s_r, r);
    };
    tasks1[2] = [&s_ry, &ry]() {
        BuildS(s_ry, ry);
    };
    parallel::Invoke(tasks1);

    std::array<parallel::VoidTask, 3> tasks2;
    tasks2[0] = [&input, &com_pub, &com_da, &s_rx, &s_r]() {
         if(input.row_a){
            com_da = MultiExpBdlo12(com_pub.a, s_rx);
        }else{
            com_da = MultiExpBdlo12(com_pub.a, s_r);
        }
    };
    tasks2[1] = [&input, &com_pub, &com_db, &s_ry, &s_r]() {
        if(input.row_b){
            com_db = MultiExpBdlo12(com_pub.b, s_r);
        }else{
            com_db = MultiExpBdlo12(com_pub.b, s_ry);
        }
    };
    tasks2[2] = [&input, &com_pub, &com_dc, &s_rx, &s_ry]() {
        if(input.row_c){
            com_dc = MultiExpBdlo12(com_pub.c, s_rx);
        }else{
            com_dc = MultiExpBdlo12(com_pub.c, s_ry);
        }
    };
    parallel::Invoke(tasks2);
    
    hyrax::A6::CommitmentPub com_pub_a6_a(com_da, com_w1);
    std::unique_ptr<hyrax::A6::VerifyInput> verify_input_a6_a;
    if(input.row_a){
        verify_input_a6_a.reset(new hyrax::A6::VerifyInput("mle_a", s_r, com_pub_a6_a, input.get_g, input.get_g(0)));
    }else{
        verify_input_a6_a.reset(new hyrax::A6::VerifyInput("mle_a", s_rx, com_pub_a6_a, input.get_g, input.get_g(0)));
    }
    ret21 = hyrax::A6::Verify(proof.proof_a6_a, seed, *verify_input_a6_a);

    hyrax::A6::CommitmentPub com_pub_a6_b(com_db, com_w2);
    std::unique_ptr<hyrax::A6::VerifyInput> verify_input_a6_b;
    if(input.row_b){
        verify_input_a6_b.reset(new hyrax::A6::VerifyInput("mle_b", s_ry, com_pub_a6_b, input.get_g, input.get_g(0)));
    }else{
        verify_input_a6_b.reset(new hyrax::A6::VerifyInput("mle_b", s_r, com_pub_a6_b, input.get_g, input.get_g(0)));
    }
    ret22 = hyrax::A6::Verify(proof.proof_a6_b, seed, *verify_input_a6_b);

    hyrax::A6::CommitmentPub com_pub_a6_c(com_dc, com_w3);
    std::unique_ptr<hyrax::A6::VerifyInput> verify_input_a6_c;
    if(input.row_c){
        verify_input_a6_c.reset(new hyrax::A6::VerifyInput("mle_c", s_ry, com_pub_a6_c, input.get_g, input.get_g(0)));
    }else{
        verify_input_a6_c.reset(new hyrax::A6::VerifyInput("mle_c", s_rx, com_pub_a6_c, input.get_g, input.get_g(0)));
    }
    ret23 = hyrax::A6::Verify(proof.proof_a6_c, seed, *verify_input_a6_c);


    //验证3: \sum ai * bi = c
    std::vector<std::vector<Fr>> v(round);
    auto parallel_f = [&r, &v, &e](size_t i) {
        v[i].resize(3);
        Fr neg_e = -e[i];
        v[i][0] = e[i+1] + neg_e + neg_e;
        v[i][1] = r[i] * e[i+1];
        v[i][2] = v[i][1] * r[i];
        v[i][1] = v[i][1] + neg_e;
        v[i][2] = v[i][2] + neg_e;
    };
    parallel::For(round, parallel_f);
    hyrax::A7::CommitmentPub com_pub_a7(com_u, com_w * e[e.size() - 1] - com_w3 * e[0]);
    hyrax::A7::VerifyInput verify_input_a7("sumcheck", com_pub_a7, input.get_g, v, input.get_g(0));
    ret3 = hyrax::A7::Verify(proof.proof_a7, seed, verify_input_a7);


    if(!(ret1 && ret21 && ret22 && ret23 && ret3)){
        std::cout << "ret:" << ret1 << "\t" << ret21 << "\t" << ret22 << "\t" << ret23 << "\t" << ret3 << "\n";
    }
    return ret1 && ret21 && ret22 &&ret23 && ret3;
}

void A4::ComputeCom(CommitmentPub& com_pub, CommitmentSec& com_sec,
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

inline bool A4::Test(uint64_t m, uint64_t k, uint64_t n, bool row_a, bool row_b, bool row_c) {
    Tick tick(__FN__);

    h256_t seed = misc::RandH256();

    std::vector<std::vector<Fr>> a(m); //m*k
    std::vector<std::vector<Fr>> b(k); //k*n
    std::vector<std::vector<Fr>> c(m, std::vector<Fr>(n)); //m*n 

    for(uint64_t i=0; i<m; i++){
        a[i].resize(k);
        FrRand(a[i]);
    }

    for(uint64_t i=0; i<k; i++){
        b[i].resize(n);
        FrRand(b[i]);
    }
    MatrixMul(a, b, c);

    ProveInput prove_input(a, b, c, pc::kGetRefG1, pc::kGetRefG1(0), row_a, row_b, row_c);

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

    VerifyInput verify_input(m, k, n, com_pub, pc::kGetRefG1, pc::kGetRefG1(0), row_a, row_b, row_c);
    bool success = Verify(proof, seed, verify_input);
    std::cout << Tick::GetIndentString() << success << "\n\n\n\n\n\n";
    return success;
}
}