#pragma once

#include "./details.h"
#include "hyrax/hyrax.h"
namespace libra{

// A, B, C: secret Fr, m*n
// open: com(gx, A), com(gy, B), com(gz,C)
// prove: A \circ B = C, 哈达吗积
// proof size:
// prove cost:
// verify cost:

struct A1{

    struct CommitmentPub {
        std::vector<G1> a;  // a.size = m
        std::vector<G1> b;  // b.size = m
        std::vector<G1> c;  // c.size = m
        CommitmentPub(){}
        CommitmentPub(int64_t m){
            a.resize(m, G1Zero());
            b.resize(m, G1Zero());
            c.resize(m, G1Zero());
        }
        CommitmentPub(std::vector<G1> const& a, std::vector<G1> const& b,
                      std::vector<G1> const& c)
            :   a(a), b(b), c(c) {}
        int64_t m() const { return a.size(); }
    };

    struct CommitmentSec {
        std::vector<Fr> alpha;  // r.size = m
        std::vector<Fr> beta;  // s.size = m
        std::vector<Fr> theta;  // t.size = m
        CommitmentSec(){}
        CommitmentSec(int64_t m){
            alpha.resize(m, FrZero());
            beta.resize(m, FrZero());
            theta.resize(m, FrZero());
        }
        CommitmentSec(std::vector<Fr> const& alpha, std::vector<Fr> const& beta,
                      std::vector<Fr> const& theta)
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
        hyrax::A6::Proof proof_a6;
        hyrax::A7::Proof proof_a7;

        bool operator==(Proof const& right) const {
            return com_ext_pub == right.com_ext_pub && proof_a1 == right.proof_a1 &&
                proof_a6 == right.proof_a6 && proof_a7 == right.proof_a7;
        }
        bool operator!=(Proof const& right) const { return !(*this == right); }

        template <typename Ar>
        void serialize(Ar& ar) const {
            ar& YAS_OBJECT_NVP("a2.pf", ("c", com_ext_pub), ("1p", proof_a1),
                            ("6p", proof_a6), ("7p", proof_a7));
        }

        template <typename Ar>
        void serialize(Ar& ar) {
            ar& YAS_OBJECT_NVP("a2.pf", ("c", com_ext_pub), ("1p", proof_a1),
                            ("6p", proof_a6), ("7p", proof_a7));
        }
    };


    struct ProveInput{
        std::vector<std::vector<Fr>> a; // m*n
        std::vector<std::vector<Fr>> b; // m*n
        std::vector<std::vector<Fr>> c; // m*n
        GetRefG1 const& get_g;

      

        int64_t m() const { return a.size(); }
        int64_t n() const { return b[0].size(); }

        std::string to_string() const {
            return std::to_string(m()) + "*" + std::to_string(n());
        }

        ProveInput(GetRefG1 const& get_g)
            :   get_g(get_g){
        }

        ProveInput(int64_t m, int64_t n, GetRefG1 const& get_g)
            :   get_g(get_g){
            assert(m !=0 && n !=0);
            a.resize(m, std::vector<Fr>(n, 0));
            b.resize(m, std::vector<Fr>(n, 0));
            c.resize(m, std::vector<Fr>(n, 0));
        }

        ProveInput(std::vector<std::vector<Fr>> const& a,
               std::vector<std::vector<Fr>> const& b,
               std::vector<std::vector<Fr>> const& c,
               GetRefG1 const& get_g)
            :   a(a),
                b(b),
                c(c),
                
                get_g(get_g){
            Check();
        }

        void Check(){
            assert(!a.empty() && a.size() == b.size() && a.size() == c.size() && a[0].size() == b[0].size() && b[0].size() == c[0].size());
            if(DEBUG_CHECK){
                for(int i=0; i<a.size(); i++){
                    assert(HadamardProduct(a[i], b[i]) == c[i]);
                    assert(a[i].size() == a[0].size() && b[i].size() == a[0].size() && c[i].size() == c[0].size());
                }
            }
        }
    };


    struct VerifyInput {
        VerifyInput(size_t const& m_,  int64_t const& n_, CommitmentPub const& com_pub,
                    GetRefG1 const& get_g, G1 const& u)
            :   m_(m_),
                n_(n_),
                u(u),
                com_pub(com_pub),
                get_g(get_g) {
                CHECK(com_pub.a.size() == m_ && com_pub.b.size() == m_ && com_pub.c.size() == m_, "");
            }
            CommitmentPub const& com_pub;
            GetRefG1 const& get_g;
            G1 const& u;
            size_t m_, n_, k_;
            size_t m() const { return m_; }
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

    static bool TestQuickMul();

    static void ComputeCom(CommitmentPub& com_pub, CommitmentSec& com_sec, 
                            ProveInput const& input);

    static void UpdateSeed(h256_t& seed, G1 const& a, G1 const& b, 
                           G1 const& c, G1 const& d);

    static void UpdateSeed(h256_t &seed, G1 const& a);

    static void UpdateSeed(h256_t& seed, CommitmentPub const& com_pub,
                           int64_t m, int64_t n);

    template <typename ProofT>
    static void UpdateSeed(h256_t& seed, ProofT const& proof);

    template <typename T>
    static void Divide(std::vector<T> const& t, std::vector<T>& t1,
                        std::vector<T>& t2, T const& t0) { //将t分为左右两半存储到t1, t2, 如果 |t| != 2^k, 则补0
        auto n = t.size();
        auto half = misc::Pow2UB(n) / 2;
        t1.resize(half, t0); //x的前半部分
        t2.resize(half, t0);
        std::copy(t.begin(), t.begin() + half, t1.begin());
        std::copy(t.begin() + half, t.end(), t2.begin());
    };

    static void BuildS(std::vector<Fr>& s, std::vector<Fr> const& c) {
        Tick tick(__FN__);
        s[0] = 1;
        for (size_t i = 0; i < c.size(); ++i) {
            for(int64_t j=(1 << i)-1; j>=0; j--){
                int64_t l = (j << 1), r = l+1;
                if(l >= s.size()) continue;
                else {
                    if(r < s.size()){
                        s[r] = s[j] * c[i];
                    }
                    s[l] = s[j] * (1 - c[i]);
                }
            }
        }
    };

    static bool Test(uint64_t m, uint64_t n);
};

template <typename ProofT>
void A1::UpdateSeed(h256_t& seed, ProofT const& proof) {
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    yas::mem_ostream os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
    oa.serialize(proof);
    auto buf = os.get_shared_buffer();
    HashUpdate(hash, buf.data.get(), buf.size);
    hash.Final(seed.data());
}

//update u
void A1::UpdateSeed(h256_t &seed, G1 const& a) {
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    HashUpdate(hash, a);
    hash.Final(seed.data());
}

//update statement
void A1::UpdateSeed(h256_t& seed, CommitmentPub const& com_pub,
                    int64_t m, int64_t n){
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    HashUpdate(hash, com_pub.a);
    HashUpdate(hash, com_pub.b);
    HashUpdate(hash, com_pub.c);
    HashUpdate(hash, m);
    HashUpdate(hash, n);
    hash.Final(seed.data());
}


//update w1, w2, w3, w
void A1::UpdateSeed(h256_t& seed, G1 const& a, G1 const& b, G1 const& c, G1 const& d){
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    HashUpdate(hash, a);
    HashUpdate(hash, b);
    HashUpdate(hash, c);
    HashUpdate(hash, d);
    hash.Final(seed.data());
}


void A1::ProveFinal(Proof& proof, h256_t& seed, ProveInput const& input, ProveExtInput const& ext_input, 
                    CommitmentPub const& com_pub, CommitmentSec const& com_sec, CommitmentExtSec const& com_ext_sec){
    //计算挑战
    int64_t roundm = (int64_t)misc::Log2UB(input.m()), roundn = (int64_t)misc::Log2UB(input.n());
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
    std::vector<Fr> s_rl(input.m()), s_rr(input.n());
    auto parallel_f1 = [&s_rl, &s_rr, &r, &roundm](int i){
        if(i == 0){
            BuildS(s_rl, std::vector<Fr>(r.begin(), r.begin() + roundm));
        }else{
            BuildS(s_rr, std::vector<Fr>(r.begin()+roundm, r.end()));
        }
    };
    parallel::For(2, parallel_f1);

    std::vector<std::vector<Fr>> abc(3);
    std::vector<Fr> r_com_abc(3);
    std::vector<G1> com_abc(3);

    auto parallel_f2 = [&input, &com_pub, &com_sec, &abc, &r_com_abc, &com_abc, &s_rl](size_t i) {
       if(i == 0){
            MatrixVectorMul(s_rl, input.a, abc[i]);
            com_abc[i] = MultiExpBdlo12(com_pub.a, s_rl);
            r_com_abc[i] = InnerProduct(com_sec.alpha, s_rl);
       }else if(i == 1){
            MatrixVectorMul(s_rl, input.b, abc[i]);
            com_abc[i] = MultiExpBdlo12(com_pub.b, s_rl);
            r_com_abc[i] = InnerProduct(com_sec.beta, s_rl);
       }else{
            MatrixVectorMul(s_rl, input.c, abc[i]);
            com_abc[i] = MultiExpBdlo12(com_pub.c, s_rl);
            r_com_abc[i] = InnerProduct(com_sec.theta, s_rl);
       }
    };
    parallel::For(3, parallel_f2);

    // CHECK(InnerProduct(abc[0], s_rr) == w[1], "");
    // CHECK(InnerProduct(abc[1], s_rr) == w[2], "");
    // CHECK(InnerProduct(abc[2], s_rr) == w[3], "");
    
    std::vector<Fr> d = abc[0] * e[0] + abc[1] * e[1] + abc[2] * e[2];
    G1 com_d = com_abc[0] * e[0] + com_abc[1] * e[1] + com_abc[2] * e[2];
    Fr r_com_d = r_com_abc[0] * e[0] + r_com_abc[1] * e[1] + r_com_abc[2] * e[2];

    Fr t = w[1] * e[0] + w[2] * e[1] + w[3] * e[2];
    G1 com_t = com_w[1] * e[0] + com_w[2] * e[1] + com_w[3] * e[2];
    Fr r_com_t = r_com_w[1] * e[0] + r_com_w[2] * e[1] + r_com_w[3] * e[2];

    hyrax::A6::CommitmentPub com_pub_a6(com_d, com_t);
    hyrax::A6::CommitmentSec com_sec_a6(r_com_d, r_com_t);
    hyrax::A6::ProveInput input_a6("mle_bc", d, s_rr, t, input.get_g, input.get_g(0));
    hyrax::A6::Prove(proof.proof_a6, seed, input_a6, com_pub_a6, com_sec_a6);
    UpdateSeed(seed, proof.proof_a6);

    //SumCheck证明
    Fr exp = e[e.size() - 1] * w[4];
    t = (w[0] - w[3]) * exp;
    com_t = (com_w[0] - com_w[3]) * exp;
    r_com_t = (r_com_w[0] - r_com_w[3]) * exp;
    
    std::vector<std::vector<Fr>> v(round, std::vector<Fr>(4));
    auto parallel_f3 = [&r, &v, &e](size_t i) {
        v[i][0] = e[i+1] - e[i] - e[i];
        v[i][1] = r[i] * e[i+1];
        v[i][2] = v[i][1] * r[i];
        v[i][3] = v[i][2] * r[i];
        v[i][1] = v[i][1] - e[i];
        v[i][2] = v[i][2] - e[i];
        v[i][3] = v[i][3] - e[i];
    };
    parallel::For(round, parallel_f3);

    hyrax::A7::CommitmentPub com_pub_a7(com_u, com_t);
    hyrax::A7::CommitmentSec com_sec_a7(r_com_u, r_com_t);
    hyrax::A7::ProveInput input_a7("sumcheck", u, v, t, pc::kGetRefG1, pc::kGetRefG1(0));
    hyrax::A7::Prove(proof.proof_a7, seed, input_a7, com_pub_a7, com_sec_a7);
}

void A1::Prove(Proof& proof, h256_t seed, ProveInput const& input,
                    CommitmentPub const& com_pub, CommitmentSec const& com_sec){
    Tick tick(__FN__, input.to_string());

    if(DEBUG_CHECK){
        for(int64_t i=0; i<input.m(); i++){
            assert(pc::ComputeCom(input.get_g, input.a[i], com_sec.alpha[i]) == com_pub.a[i]);
            assert(pc::ComputeCom(input.get_g, input.b[i], com_sec.beta[i]) == com_pub.b[i]);
            assert(pc::ComputeCom(input.get_g, input.c[i], com_sec.theta[i]) == com_pub.c[i]);
        }
    }
    
    int64_t roundm = (int64_t)misc::Log2UB(input.m()), roundn = (int64_t)misc::Log2UB(input.n());
    int64_t round = roundm + roundn;
    int64_t new_n = 1 << roundn;

    std::vector<Fr> rx(round), r(round);
    
    std::vector<Fr> table_a(1 << round, FrZero());
    std::vector<Fr> table_b(1 << round, FrZero());
    std::vector<Fr> table_c(1 << round, FrZero());
    std::vector<Fr> table_x(1 << round, FrZero());

    UpdateSeed(seed, com_pub, input.m(), input.n());
    ComputeFst(seed, "libra::A1::rx", rx);

    
    {
        Tick tick(__FN__, "build table");
        BuildS(table_x, rx);
        auto parallel_f = [&table_a, &table_b, &table_c, &input, &new_n](size_t i) {
            int64_t begin_i = i * new_n;
            std::copy(input.a[i].begin(), input.a[i].end(), table_a.begin() + begin_i);
            std::copy(input.b[i].begin(), input.b[i].end(), table_b.begin() + begin_i);
            std::copy(input.c[i].begin(), input.c[i].end(), table_c.begin() + begin_i);
        };
        parallel::For(input.m(), parallel_f);
    }

    std::vector<std::vector<Fr>> u(round, std::vector<Fr>(4));
    std::vector<Fr> w(5); //a(r) * b(r), a(r), b(r), c(r), x(r)
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
            std::vector<Fr> table_cl(table_c.begin(), table_c.begin() + mid), table_cr(table_c.begin() + mid, table_c.end());
            std::vector<Fr> table_xl(table_x.begin(), table_x.begin() + mid), table_xr(table_x.begin() + mid, table_x.end());

            std::vector<Fr> cd(4);
            std::vector<std::vector<Fr>> abd(8, std::vector<Fr>(mid));
            /**
             * i = 1：j=1, j=0, 0, 1, 2, 3
             * i = 2：j=3, j=2, j=1, j=0, 0, 1, 2, 3, 4, 5, 6, 7, 8
             * 
             */
            for(int i=1; i<3; i++){
                for(int j=(1 << i)-1; j>=0; j--){
                    int lt = j << 1, rt = lt + 1;
                    if(i == 1){
                        if(j == 1){
                            abd[rt] = HadamardProduct(table_ar, table_br);
                            abd[lt] = HadamardProduct(table_ar, table_bl);
                        }else{
                            abd[rt] = HadamardProduct(table_al, table_br);
                            abd[lt] = HadamardProduct(table_al, table_bl);
                        }
                    }else{
                        abd[rt][0] = InnerProduct(abd[j], table_xr);
                        abd[lt][0] = InnerProduct(abd[j], table_xl);
                    }
                }
            }
            cd[0] = InnerProduct(table_cl, table_xl);
            cd[1] = InnerProduct(table_cl, table_xr);
            cd[2] = InnerProduct(table_cr, table_xl);
            cd[3] = InnerProduct(table_cr, table_xr);

            Fr u1 = abd[0][0] - cd[0];
            Fr u2 = abd[7][0] - cd[3];
            Fr u3 = 8*abd[7][0] - 4*abd[5][0] - 4*abd[3][0] + 2*abd[1][0] - 4*abd[6][0] + 2*abd[4][0] + 2*abd[2][0] - abd[0][0] - cd[0] + 2*cd[1] + 2*cd[2] - 4*cd[3];
            Fr u4 = 8*abd[0][0] - 4*abd[2][0] - 4*abd[4][0] + 2*abd[6][0] - 4*abd[1][0] + 2*abd[3][0] + 2*abd[5][0] - abd[7][0] - cd[3] + 2*cd[2] + 2*cd[1] - 4*cd[0];

            //u1=f(0), u2=f(1), u3=f(2), u4=f(-1)
            u[loop][0] = u1;
            u[loop][1] = (6*u2 - 2*u4 - 3*u1 - u3) / 6;
            u[loop][2] = (u2 + u4 - 2*u1) / 2;
            u[loop][3] = (3*u1 - 3*u2 - u4 + u3) / 6;
        
            com_u[loop] = pc::ComputeCom(input.get_g, u[loop], r_com_u[loop]);

            UpdateSeed(seed, com_u[loop]);
            r[loop] = H256ToFr(seed); //计算挑战
            
            //更新table
            Fr lv = 1 - r[loop], rv = r[loop];
            std::vector<Fr> table_ap = table_al * lv + table_ar * rv;
            std::vector<Fr> table_bp = table_bl * lv + table_br * rv;
            std::vector<Fr> table_cp = table_cl * lv + table_cr * rv;
            std::vector<Fr> table_xp = table_xl * lv + table_xr * rv;
            

            table_ap.swap(table_a);
            table_bp.swap(table_b);
            table_cp.swap(table_c);
            table_xp.swap(table_x);
        }

        w = {table_a[0] * table_b[0], table_a[0], table_b[0], table_c[0], table_x[0]};
        for(int i=0; i<4; i++){
            com_w[i] = pc::ComputeCom(input.get_g(0), w[i], r_com_w[i]);
        }
    }

    ProveExtInput ext_input(u, r, w);
    CommitmentExtSec com_ext_sec(r_com_u, r_com_w);
    proof.com_ext_pub.com_u = std::move(com_u);
    proof.com_ext_pub.com_w = std::move(com_w);

    ProveFinal(proof, seed, input, ext_input, com_pub, com_sec, com_ext_sec);
}


bool A1::Verify(Proof const& proof, h256_t seed, VerifyInput const& input){
    Tick tick(__FN__, input.to_string());

    bool ret1 = false, ret2 = false, ret3 = false;

    int64_t roundm = (int64_t)misc::Log2UB(input.m()), roundn = (int64_t)misc::Log2UB(input.n());
    int64_t round = roundm + roundn;

    auto const& com_a = input.com_pub.a;
    auto const& com_b = input.com_pub.b;
    auto const& com_c = input.com_pub.c;
    auto const& com_u = proof.com_ext_pub.com_u;
    auto const& com_w = proof.com_ext_pub.com_w;

    std::vector<Fr> rx(round), r(round), e(round+1);
    std::vector<Fr> s_rl(input.m()), s_rr(input.n());

    UpdateSeed(seed, input.com_pub, input.m(), input.n());
    ComputeFst(seed, "libra::A1::rx", rx);

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


    std::vector<G1> com_abc(3);
    auto parallel_f2 = [&com_abc, &com_a, &com_b, &com_c, &s_rl](int i){
        if(i == 0){
            com_abc[0] = MultiExpBdlo12(com_a, s_rl);
        }else if(i == 1){
            com_abc[1] = MultiExpBdlo12(com_b, s_rl);
        }else{
            com_abc[2] = MultiExpBdlo12(com_c, s_rl);
        }
    };
    parallel::For(3, parallel_f2);

    G1 com_d = com_abc[0] * e[0] + com_abc[1] * e[1] + com_abc[2] * e[2];
    G1 com_t = com_w[1] * e[0] + com_w[2] * e[1] + com_w[3] * e[2];

    hyrax::A6::CommitmentPub com_pub_a6(com_d, com_t);
    hyrax::A6::VerifyInput verify_input_a6("mle_abc", s_rr, com_pub_a6, input.get_g, input.get_g(0));
    ret2 = hyrax::A6::Verify(proof.proof_a6, seed, verify_input_a6);
    UpdateSeed(seed, proof.proof_a6);

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

void A1::ComputeCom(CommitmentPub& com_pub, CommitmentSec& com_sec,
                         ProveInput const& input){
    Tick tick(__FN__, input.to_string());
    int64_t m = input.m();

    com_pub.a.resize(m);
    com_sec.alpha.resize(m);
    FrRand(com_sec.alpha);

    com_pub.b.resize(m);
    com_sec.beta.resize(m);
    FrRand(com_sec.beta);

    com_pub.c.resize(m);
    com_sec.theta.resize(m);
    FrRand(com_sec.theta);
    
    auto parallel_f = [&com_sec, &com_pub, &input](int64_t i) {
        com_pub.a[i] = pc::ComputeCom(input.a[i], com_sec.alpha[i]);
        com_pub.b[i] = pc::ComputeCom(input.b[i], com_sec.beta[i]);
        com_pub.c[i] = pc::ComputeCom(input.c[i], com_sec.theta[i]);
    };
    parallel::For(m, parallel_f);
}

bool A1::TestQuickMul(){
    int n = 1024, half = 512;
    std::vector<Fr> a(n), b(n), c(n), d(n);

    FrRand(a);
    FrRand(b);
    FrRand(c);
    FrRand(d);

    std::vector<Fr> al(a.begin(), a.begin() + half), ar(a.begin() + half, a.end());
    std::vector<Fr> bl(b.begin(), b.begin() + half), br(b.begin() + half, b.end());
    std::vector<Fr> cl(c.begin(), c.begin() + half), cr(c.begin() + half, c.end());
    std::vector<Fr> dl(d.begin(), d.begin() + half), dr(d.begin() + half, d.end());

    std::vector<std::vector<Fr>> abd(8, std::vector<Fr>(half, FrOne()));
    for(int i=0; i<3; i++){
        for(int j=(1 << i)-1; j>=0; j--){
            int lt = j << 1, rt = lt + 1;
            if(i == 0){
                abd[rt] = ar;
                abd[lt] = al;
            }else if(i == 1){
                abd[rt] = HadamardProduct(abd[j], br);
                abd[lt] = HadamardProduct(abd[j], bl);
            }else{
                abd[rt] = HadamardProduct(abd[j], dr);
                abd[lt] = HadamardProduct(abd[j], dl);
            }
        }
    }
    std::vector<Fr> cd(4);
    cd[0] = InnerProduct(cl, dl);
    cd[1] = InnerProduct(cl, dr);
    cd[2] = InnerProduct(cr, dl);
    cd[3] = InnerProduct(cr, dr);

    Fr left = -cd[0] + cd[1] * 2 + 2 * cd[2] - 4 * cd[3];
    left += 8 * InnerProduct(abd[7], std::vector<Fr>(half, FrOne()));
    left += -4 * InnerProduct(abd[5], std::vector<Fr>(half, FrOne()));
    left += -4 * InnerProduct(abd[3], std::vector<Fr>(half, FrOne()));
    left += 2 * InnerProduct(abd[1], std::vector<Fr>(half, FrOne()));
    left += -4 * InnerProduct(abd[6], std::vector<Fr>(half, FrOne()));
    left += 2 * InnerProduct(abd[4], std::vector<Fr>(half, FrOne()));
    left += 2 * InnerProduct(abd[2], std::vector<Fr>(half, FrOne()));
    left += -1 * InnerProduct(abd[0], std::vector<Fr>(half, FrOne()));
    

    Fr right = InnerProduct(HadamardProduct(ar * Fr(2) - al, br * Fr(2) - bl) - (cr * Fr(2) - cl), dr * Fr(2) - dl);
    assert(left == right);

    return (left == right);
}

inline bool A1::Test(uint64_t m, uint64_t n) {
    Tick tick(__FN__, std::to_string(m) + " " + std::to_string(n));

    h256_t seed = misc::RandH256();

    std::vector<std::vector<Fr>> a(m, std::vector<Fr>(n)); //m*n
    std::vector<std::vector<Fr>> b(m, std::vector<Fr>(n)); //m*n

    for(int i=0; i<a.size(); i++){
        FrRand(a[i]);
        FrRand(b[i]);
    }

    std::vector<std::vector<Fr>> c = HadamardProduct(a, b); //m*n 

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

    VerifyInput verify_input(m, n, com_pub, pc::kGetRefG1, pc::kGetRefG1(0));
    bool success = Verify(proof, seed, verify_input);
    std::cout << Tick::GetIndentString() << success << "\n\n\n\n\n\n";
    return success;
}
}