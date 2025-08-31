#pragma once

#include "./details.h"
#include "./a1.h"
#include "./a5.h"
#include "./sumcheck.h"
namespace argument{

// A, B, C: secret Fr, m*n
// open: com(gx, A), com(gy, B), com(gz,C)
// prove: A \circ B = C, 哈达吗积
// proof size:
// prove cost:
// verify cost:

struct A7{

  struct CommitmentPub {
    std::vector<G1> com_a;
    std::vector<G1> com_b;
    std::vector<G1> com_c;
    CommitmentPub(){}
    CommitmentPub(std::vector<G1> const& com_a, std::vector<G1> const& com_b,
                    std::vector<G1> const& com_c)
        :   com_a(com_a), com_b(com_b), com_c(com_c) {}
    int64_t m() const { return com_a.size(); }
  };

  struct CommitmentSec {
    std::vector<Fr> r_com_a;
    std::vector<Fr> r_com_b;
    std::vector<Fr> r_com_c;
    CommitmentSec(){}
    CommitmentSec(int64_t m){
        r_com_a.resize(m, FrZero());
        r_com_b.resize(m, FrZero());
        r_com_c.resize(m, FrZero());
    }
    CommitmentSec(std::vector<Fr> const& r_com_a,
                  std::vector<Fr> const& r_com_b,
                  std::vector<Fr> const& r_com_c)
        :   r_com_a(r_com_a), r_com_b(r_com_b), r_com_c(r_com_c) {}
  };

  struct Proof{
    std::vector<G1> com_t0;
    std::vector<G1> com_t2;
    std::array<G1,2> com_u;
    A1::Proof sub_proof1;
    A5::Proof sub_proof2;

    size_t FrSize(){
      return sub_proof1.FrSize() + sub_proof2.FrSize();
    }

    size_t G1Size(){
      return 2 + (com_t0.size() << 1) + sub_proof1.G1Size() + sub_proof2.G1Size();
    }

    bool operator==(Proof const& right) const {
      return com_t0 == right.com_t0 && com_t2 == right.com_t2 && 
             sub_proof1 == right.sub_proof1 && sub_proof2 == right.sub_proof2;
    }
    bool operator!=(Proof const& right) const { return !(*this == right); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("a4.p", ("0", com_t0), ("2", com_t2), ("u", com_u), ("p1", sub_proof1), ("p2", sub_proof2));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("a4.p", ("0", com_t0), ("2", com_t2), ("u", com_u), ("p1", sub_proof1), ("p2", sub_proof2));
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

    ProveInput(std::vector<std::vector<Fr>> const& a,
               std::vector<std::vector<Fr>> const& b,
               std::vector<std::vector<Fr>> const& c,
               GetRefG1 const& get_g)
        :   a(a),
            b(b),
            c(c),
            get_g(get_g){
    }
  };


  struct VerifyInput {
    VerifyInput(size_t const& m_,  int64_t const& n_, CommitmentPub const& com_pub,
                GetRefG1 const& get_g)
        :   m_(m_),
            n_(n_),
            com_pub(com_pub),
            get_g(get_g) {
        }

        CommitmentPub const& com_pub;
        GetRefG1 const& get_g;
        size_t m_, n_;

        size_t m() const { return m_; }
        size_t n() const { return n_; }

        std::string to_string() const {
            return std::to_string(m()) + "*" + std::to_string(n());
        }
  };
  
  static void CheckInput(ProveInput const& input){
    auto const& a = input.a, &b = input.b, &c = input.c;
    assert(!a.empty() && !a[0].empty() && a.size() == b.size() && a.size() == c.size() && a[0].size() == b[0].size() && b[0].size() == c[0].size());
    for(int i=0; i<a.size(); i++){
        assert(HadamardProduct(a[i], b[i]) == c[i]);
        assert(a[i].size() == a[0].size() && b[i].size() == a[0].size() && c[i].size() == c[0].size());
    }
  };

  static void CheckWitness(ProveInput const& input, 
                            CommitmentPub const& com_pub,
                            CommitmentSec const& com_sec){
    CheckInput(input);
    for(int64_t i=0; i<input.m(); i++){
        assert(pc::ComputeCom(input.get_g, input.a[i], com_sec.r_com_a[i]) == com_pub.com_a[i]);
        assert(pc::ComputeCom(input.get_g, input.b[i], com_sec.r_com_b[i]) == com_pub.com_b[i]);
        assert(pc::ComputeCom(input.get_g, input.c[i], com_sec.r_com_c[i]) == com_pub.com_c[i]);
    }
  };


  struct HPProveInput{
    std::vector<std::vector<Fr>> const& a; // m*n
    std::vector<std::vector<Fr>> const& b; // m*n
    std::vector<std::vector<Fr>> const& c; // m*n
    GetRefG1 const& get_g;

    int64_t m() const { return a.size(); }
    int64_t n() const { return a[0].size(); }

    std::string to_string() const {
        return std::to_string(m()) + "*" + std::to_string(n());
    }

    HPProveInput(std::vector<std::vector<Fr>> const& a,
            std::vector<std::vector<Fr>> const& b,
            std::vector<std::vector<Fr>> const& c,
               GetRefG1 const& get_g)
        :   a(a),
            b(b),
            c(c),
            get_g(get_g){
    }
  };

   struct HPVerifyInput{
    size_t _m, _n;
    std::vector<G1> const& com_t0;
    std::vector<G1> const& com_t2;
    int64_t m() const { return _m; }
    int64_t n() const { return _n; }

    std::string to_string() const {
        return std::to_string(m()) + "*" + std::to_string(n());
    }

    HPVerifyInput(size_t _m, size_t _n, 
                  std::vector<G1> const& com_t0, std::vector<G1> const& com_t2)
        :   _m(_m),
            _n(_n),
            com_t0(com_t0),
            com_t2(com_t2){
    }
  };

  struct HPProveOutput{
    std::vector<G1> com_t0;
    std::vector<G1> com_t2;
    std::array<G1, 2> com_ab;
    Fr a, b, c;
    Fr r_com_a, r_com_b, r_com_c;
    std::vector<Fr> sl_hat_l, sl_hat_r, sr_hat;
    std::vector<Fr> sl_chk_l, sl_chk_r, sr_chk;

    A1::Proof sm_proof;
  };

  struct HPVerifyOutput{
    G1 com_c;
    std::vector<Fr> sl_hat_l, sl_hat_r, sr_hat;
    std::vector<Fr> sl_chk_l, sl_chk_r, sr_chk;
  };

  static void Verify(h256_t & seed, HPVerifyInput const& input, HPVerifyOutput & output) {
     Tick tick(__FN__, input.to_string());
    int64_t m = input.m(), n = input.n();
    int64_t lm = (int64_t)misc::Log2UB(input.m());
    int64_t ln = (int64_t)misc::Log2UB(input.n());

    std::vector<Fr> rl(lm), rr(ln), sl, sr, s;
    std::vector<Fr> rl_hat(m), rr_hat(n), sl_hat, sr_hat;

    ComputeFst(seed, "argument::A6::rl", rl);
    ComputeFst(seed, "argument::A6::rr", rr);

    auto parallel_f1 = [&rl_hat, &rr_hat, rl, rr](int i){
        if(i == 0){
            misc::BuildR(rl_hat, rl);
        }else{
            misc::BuildR(rr_hat, rr);
        }
    };
    parallel::For(2, parallel_f1);
    
    G1 com_c = G1Zero();
    SumCheck::Verify(input.com_t0, input.com_t2, seed, com_c, s);

    sl = std::vector<Fr>(s.begin(), s.begin()+lm+1);
    sr = std::vector<Fr>(s.begin()+lm+1, s.end());

    sl_hat = misc::BuildE(sl); sr_hat = misc::BuildE(sr);
    std::vector<Fr> sl_chk(sl_hat.rbegin(), sl_hat.rend());
    std::vector<Fr> sr_chk(sr_hat.rbegin(), sr_hat.rend());
    std::vector<Fr> sl_hat_l(sl_hat.begin(), sl_hat.begin() + m);
    std::vector<Fr> sl_hat_r(sl_hat.begin()+m, sl_hat.begin() + 2*m);
    std::vector<Fr> sl_chk_l(sl_chk.begin(), sl_chk.begin() + m);
    std::vector<Fr> sl_chk_r(sl_chk.begin()+m, sl_chk.begin() + 2*m);

    sr_hat.resize(n);
    sr_chk.resize(n);
    sr_chk = HadamardProduct(sr_chk, rr_hat);
    sl_chk_l = HadamardProduct(sl_chk_l, rl_hat);
    sl_chk_r = HadamardProduct(sl_chk_r, rl_hat);

    output.com_c = std::move(com_c);
    output.sr_hat = std::move(sr_hat);
    output.sr_chk = std::move(sr_chk);
    output.sl_hat_l = std::move(sl_hat_l);
    output.sl_hat_r = std::move(sl_hat_r);
    output.sl_chk_l = std::move(sl_chk_l);
    output.sl_chk_r = std::move(sl_chk_r);
  }


  static void Prove(h256_t & seed, HPProveInput const& input, HPProveOutput & output) {
     Tick tick(__FN__, input.to_string());
    int64_t m = input.m(), n = input.n();
    int64_t lm = (int64_t)misc::Log2UB(input.m());
    int64_t ln = (int64_t)misc::Log2UB(input.n());

    std::vector<Fr> rl(lm), rr(ln), sl, sr;
    std::vector<Fr> rl_hat(m), rr_hat(n), sl_hat, sr_hat;

    ComputeFst(seed, "argument::A6::rl", rl);
    ComputeFst(seed, "argument::A6::rr", rr);

    auto parallel_f1 = [&rl_hat, &rr_hat, rl, rr](int i){
        if(i == 0){
            misc::BuildR(rl_hat, rl);
        }else{
            misc::BuildR(rr_hat, rr);
        }
    };
    parallel::For(2, parallel_f1);

    std::vector<Fr> d;
    OuterProduct(rl_hat, rr_hat, d);
    
    G1 gc = input.get_g(0);
    Fr & c = output.c = 0, & r_com_c = output.r_com_c = 0;

    std::vector<Fr> a(m * n * 2), b(m * n);
    auto parallel_f2 = [&input, &a, &b](size_t i){
        size_t j1 = i * input.n(), j2 = j1 + b.size();
        std::copy(input.a[i].begin(), input.a[i].end(), a.begin() + j1);
        std::copy(input.c[i].begin(), input.c[i].end(), a.begin() + j2);
        std::copy(input.b[i].begin(), input.b[i].end(), b.begin() + j1);
    };
    parallel::For(m, parallel_f2);

    HadamardProduct(b, d, b);
    d = -d;
    b.insert(b.end(), d.begin(), d.end());

    SumCheck::Prove(lm + 1, (1 << (lm + 1)) * n, output.com_t0, output.com_t2, sl, seed, a, b, c, r_com_c, gc);
    SumCheck::Prove(ln, 1 << ln, output.com_t0, output.com_t2, sr, seed, a, b, c, r_com_c, gc);

    output.r_com_a = FrRand(); output.r_com_b = FrRand();
    output.com_ab[0] = pc::ComputeCom(input.get_g(0), a[0], output.r_com_a);
    output.com_ab[1] = pc::ComputeCom(input.get_g(0), b[0], output.r_com_b);

    A1::ProveInput a1_in(a[0], b[0], c);
    A1::CommitmentSec a1_sec(output.r_com_a, output.r_com_b, r_com_c);
    A1::Prove(output.sm_proof, seed, a1_in, a1_sec);

    sl_hat = misc::BuildE(sl); sr_hat = misc::BuildE(sr);
    std::vector<Fr> sl_chk(sl_hat.rbegin(), sl_hat.rend());
    std::vector<Fr> sr_chk(sr_hat.rbegin(), sr_hat.rend());
    std::vector<Fr> sl_hat_l(sl_hat.begin(), sl_hat.begin() + m);
    std::vector<Fr> sl_hat_r(sl_hat.begin()+m, sl_hat.begin() + 2*m);
    std::vector<Fr> sl_chk_l(sl_chk.begin(), sl_chk.begin() + m);
    std::vector<Fr> sl_chk_r(sl_chk.begin()+m, sl_chk.begin() + 2*m);

    sr_hat.resize(n);
    sr_chk.resize(n);
    sr_chk = HadamardProduct(sr_chk, rr_hat);
    sl_chk_l = HadamardProduct(sl_chk_l, rl_hat);
    sl_chk_r = HadamardProduct(sl_chk_r, rl_hat);

    assert(InnerProduct(MatrixVectorMul(sl_hat_l, input.a) + MatrixVectorMul(sl_hat_r, input.c), sr_hat) == a[0]);
    assert(InnerProduct(MatrixVectorMul(sl_chk_l, input.b), sr_chk) == b[0] + Sum(sl_chk_r) * Sum(sr_chk));

    output.a = a[0]; output.b = b[0];
    output.sr_hat = std::move(sr_hat);
    output.sr_chk = std::move(sr_chk);
    output.sl_hat_l = std::move(sl_hat_l);
    output.sl_hat_r = std::move(sl_hat_r);
    output.sl_chk_l = std::move(sl_chk_l);
    output.sl_chk_r = std::move(sl_chk_r);
  }

  static void Prove(Proof& proof, h256_t seed,
                    ProveInput const& input,
                    CommitmentSec const& com_sec){
    Tick tick(__FN__, input.to_string());

    int64_t m = input.m(), n = input.n();
    int64_t lm = (int64_t)misc::Log2UB(input.m());
    int64_t ln = (int64_t)misc::Log2UB(input.n());

    std::vector<Fr> rl(lm), rr(ln);
    std::vector<Fr> r_hat(m), r_chk(n);

    ComputeFst(seed, "argument::A6::rl", rl);
    ComputeFst(seed, "argument::A6::rr", rr);

    auto parallel_f1 = [&r_hat, &r_chk, rl, rr](int i){
        if(i == 0){
            misc::BuildR(r_hat, rl);
        }else{
            misc::BuildR(r_chk, rr);
        }
    };
    parallel::For(2, parallel_f1);

    std::vector<Fr> d;
    OuterProduct(r_hat, r_chk, d);
    
    std::vector<Fr> u1(m * n * 2), u2(m * n);
    auto parallel_f2 = [&input, &u1, &u2](size_t i){
        size_t j1 = i * input.n(), j2 = j1 + (u1.size() >> 1);
        std::copy(input.a[i].begin(), input.a[i].end(), u1.begin() + j1);
        std::copy(input.c[i].begin(), input.c[i].end(), u1.begin() + j2);
        std::copy(input.b[i].begin(), input.b[i].end(), u2.begin() + j1);
    };
    parallel::For(m, parallel_f2);

    HadamardProduct(u2, d, u2);

    d = -d;
    u2.insert(u2.end(), d.begin(), d.end());

    G1 gc = input.get_g(0);
    Fr c = 0, r_com_c = 0;

    std::vector<Fr> e, s;
    std::vector<G1> com_t0, com_t2;
    SumCheck::Prove(lm + 1, (1 << (lm + 1)) * n, proof.com_t0, proof.com_t2, s, seed, u1, u2, c, r_com_c, gc);
    SumCheck::Prove(ln, 1 << ln, com_t0, com_t2, e, seed, u1, u2, c, r_com_c, gc);

    proof.com_t0.insert(proof.com_t0.end(), com_t0.begin(), com_t0.end());
    proof.com_t2.insert(proof.com_t2.end(), com_t2.begin(), com_t2.end());

    Fr r_com_u1 = FrRand(), r_com_u2 = FrRand();
    proof.com_u[0] = pc::ComputeCom(input.get_g(0), u1[0], r_com_u1);
    proof.com_u[1] = pc::ComputeCom(input.get_g(0), u2[0], r_com_u2);

    A1::ProveInput a1_in(u1[0], u2[0], c);
    A1::CommitmentSec a1_sec(r_com_u1, r_com_u2, r_com_c);
    A1::Prove(proof.sub_proof1, seed, a1_in, a1_sec);

    std::vector<Fr> s_hat = misc::BuildE(s), e_hat = misc::BuildE(e);
    std::vector<Fr> s_chk(s_hat.rbegin(), s_hat.rend());
    std::vector<Fr> e_chk(e_hat.rbegin(), e_hat.rend());
    std::vector<Fr> s_hat_l(s_hat.begin(), s_hat.begin() + m);
    std::vector<Fr> s_hat_r(s_hat.begin()+m, s_hat.begin() + 2*m);
    std::vector<Fr> s_chk_l(s_chk.begin(), s_chk.begin() + m);
    std::vector<Fr> s_chk_r(s_chk.begin()+m, s_chk.begin() + 2*m);

    e_hat.resize(n);
    e_chk.resize(n);
    e_chk = HadamardProduct(e_chk, r_chk);
    s_chk_l = HadamardProduct(s_chk_l, r_hat);
    s_chk_r = HadamardProduct(s_chk_r, r_hat);
    
    std::vector<Fr> r_com_dd(2), r_com_uu(2);
    std::vector<std::vector<Fr>> dd(2), bb(2);
    std::vector<Fr> uu(2);

    dd[0] = MatrixVectorMul(s_hat_l, input.a) + MatrixVectorMul(s_hat_r, input.c);
    dd[1] = MatrixVectorMul(s_chk_l, input.b);
                
    bb[0] = e_hat;
    bb[1] = e_chk;

    uu[0] = u1[0];
    uu[1] = u2[0] + Sum(s_chk_r) * Sum(bb[1]);

    r_com_dd[0] = InnerProduct(s_hat_l, com_sec.r_com_a) + InnerProduct(s_hat_r, com_sec.r_com_c);
    r_com_dd[1] = InnerProduct(s_chk_l, com_sec.r_com_b);

    r_com_uu[0] = r_com_u1;
    r_com_uu[1] = r_com_u2;

    A5::CommitmentSec a5_sec(r_com_dd, r_com_uu);
    A5::ProveInput a5_in(dd, bb, uu, input.get_g, input.get_g(0));
    A5::Prove(proof.sub_proof2, seed, a5_in, a5_sec);
  }


  static bool Verify(Proof const& proof, h256_t seed, VerifyInput const& input){
    Tick tick(__FN__, input.to_string());

    int64_t m = input.m(), n = input.n();
    int64_t lm = (int64_t)misc::Log2UB(input.m());
    int64_t ln = (int64_t)misc::Log2UB(input.n());

    std::vector<Fr> rl(lm), rr(ln);
    std::vector<Fr> r_hat(m), r_chk(n);

    ComputeFst(seed, "argument::A6::rl", rl);
    ComputeFst(seed, "argument::A6::rr", rr);

    auto parallel_f1 = [&r_hat, &r_chk, rl, rr](int i){
        if(i == 0){
            misc::BuildR(r_hat, rl);
        }else{
            misc::BuildR(r_chk, rr);
        }
    };
    parallel::For(2, parallel_f1);

    G1 gc = input.get_g(0);
    G1 com_c = G1Zero();

    std::vector<Fr> s, e;
    std::vector<G1> com_t0_l(proof.com_t0.begin(), proof.com_t0.begin()+lm+1);
    std::vector<G1> com_t2_l(proof.com_t2.begin(), proof.com_t2.begin()+lm+1);
    std::vector<G1> com_t0_r(proof.com_t0.begin()+lm+1, proof.com_t0.end());
    std::vector<G1> com_t2_r(proof.com_t2.begin()+lm+1, proof.com_t2.end());
    SumCheck::Verify(com_t0_l, com_t2_l, seed, com_c, s);
    SumCheck::Verify(com_t0_r, com_t2_r, seed, com_c, e);

    A1::CommitmentPub a1_pub(proof.com_u[0], proof.com_u[1], com_c);
    A1::VerifyInput a1_in(a1_pub);
    bool ret = A1::Verify(proof.sub_proof1, seed, a1_in);

    std::vector<Fr> s_hat = misc::BuildE(s), e_hat = misc::BuildE(e);
    std::vector<Fr> s_chk(s_hat.rbegin(), s_hat.rend());
    std::vector<Fr> e_chk(e_hat.rbegin(), e_hat.rend());
    std::vector<Fr> s_hat_l(s_hat.begin(), s_hat.begin() + m);
    std::vector<Fr> s_hat_r(s_hat.begin()+m, s_hat.begin() + 2*m);
    std::vector<Fr> s_chk_l(s_chk.begin(), s_chk.begin() + m);
    std::vector<Fr> s_chk_r(s_chk.begin()+m, s_chk.begin() + 2*m);

    e_hat.resize(n);
    e_chk.resize(n);
    e_chk = HadamardProduct(e_chk, r_chk);
    s_chk_l = HadamardProduct(s_chk_l, r_hat);
    s_chk_r = HadamardProduct(s_chk_r, r_hat);
    
    std::vector<G1> com_dd(2), com_uu(2);
    std::vector<std::vector<Fr>> bb(2);

    com_dd[0] = MultiExpBdlo12(input.com_pub.com_a, s_hat_l) + MultiExpBdlo12(input.com_pub.com_c, s_hat_r);
    com_dd[1] = MultiExpBdlo12(input.com_pub.com_b, s_chk_l);
                
    bb[0] = e_hat;
    bb[1] = e_chk;

    com_uu[0] = proof.com_u[0];
    com_uu[1] = proof.com_u[1] + input.get_g(0) * Sum(s_chk_r) * Sum(bb[1]);

    A5::CommitmentPub a5_pub(com_dd, com_uu);
    A5::VerifyInput a5_in(bb, a5_pub, input.get_g, input.get_g(0));
    ret &= A5::Verify(proof.sub_proof2, seed, a5_in);

    return ret;
  }

  static bool Verify(size_t n, Proof const& proof, h256_t seed, 
                     std::vector<std::vector<Fr>> const& a,
                     std::vector<std::vector<Fr>> const& b,
                     std::vector<std::vector<Fr>> const& c,
                     std::vector<G1> const& com_w,
                     GetRefG1 const& get_g){
    Tick tick(__FN__, std::to_string(a.size()) + "*" + std::to_string(n));

    int64_t m = a.size();
    int64_t lm = (int64_t)misc::Log2UB(m);
    int64_t ln = (int64_t)misc::Log2UB(n);

    std::vector<Fr> rl(lm), rr(ln);
    std::vector<Fr> r_hat(m), r_chk(n);

    ComputeFst(seed, "argument::A6::rl", rl);
    ComputeFst(seed, "argument::A6::rr", rr);

    auto parallel_f1 = [&r_hat, &r_chk, rl, rr](int i){
        if(i == 0){
            misc::BuildR(r_hat, rl);
        }else{
            misc::BuildR(r_chk, rr);
        }
    };
    parallel::For(2, parallel_f1);

    G1 com_c = G1Zero();

    std::vector<Fr> s, e;
    std::vector<G1> com_t0_l(proof.com_t0.begin(), proof.com_t0.begin()+lm+1);
    std::vector<G1> com_t2_l(proof.com_t2.begin(), proof.com_t2.begin()+lm+1);
    std::vector<G1> com_t0_r(proof.com_t0.begin()+lm+1, proof.com_t0.end());
    std::vector<G1> com_t2_r(proof.com_t2.begin()+lm+1, proof.com_t2.end());
    SumCheck::Verify(com_t0_l, com_t2_l, seed, com_c, s);
    SumCheck::Verify(com_t0_r, com_t2_r, seed, com_c, e);

    A1::CommitmentPub a1_pub(proof.com_u[0], proof.com_u[1], com_c);
    A1::VerifyInput a1_in(a1_pub);
    bool ret = A1::Verify(proof.sub_proof1, seed, a1_in);

    std::vector<Fr> s_hat = misc::BuildE(s), e_hat = misc::BuildE(e);
    std::vector<Fr> s_chk(s_hat.rbegin(), s_hat.rend());
    std::vector<Fr> e_chk(e_hat.rbegin(), e_hat.rend());
    std::vector<Fr> s_hat_l(s_hat.begin(), s_hat.begin() + m);
    std::vector<Fr> s_hat_r(s_hat.begin()+m, s_hat.begin() + 2*m);
    std::vector<Fr> s_chk_l(s_chk.begin(), s_chk.begin() + m);
    std::vector<Fr> s_chk_r(s_chk.begin()+m, s_chk.begin() + 2*m);

    e_hat.resize(n);
    e_chk.resize(n);
    e_chk = HadamardProduct(e_chk, r_chk);
    s_chk_l = HadamardProduct(s_chk_l, r_hat);
    s_chk_r = HadamardProduct(s_chk_r, r_hat);
    
    std::vector<G1> com_dd(2), com_uu(2);
    std::vector<std::vector<Fr>> bb(2);

    com_dd[0] = MultiExpBdlo12(com_w, MatrixVectorMul(s_hat_l, a) + MatrixVectorMul(s_hat_r, c));
    com_dd[1] = MultiExpBdlo12(com_w, MatrixVectorMul(s_chk_l, b));
                
    bb[0] = e_hat;
    bb[1] = e_chk;

    com_uu[0] = proof.com_u[0];
    com_uu[1] = proof.com_u[1] + get_g(0) * Sum(s_chk_r) * Sum(bb[1]);

    A5::CommitmentPub a5_pub(com_dd, com_uu);
    A5::VerifyInput a5_in(bb, a5_pub, get_g, get_g(0));
    ret &= A5::Verify(proof.sub_proof2, seed, a5_in);

    return ret;
  }


  static void ComputeCom(CommitmentPub& com_pub,
                             CommitmentSec& com_sec,
                             ProveInput const& input){
    Tick tick(__FN__, input.to_string());
    int64_t m = input.m();

    com_pub.com_a.resize(m);
    com_pub.com_b.resize(m);
    com_pub.com_c.resize(m);

    com_sec.r_com_a.resize(m);
    com_sec.r_com_b.resize(m);
    com_sec.r_com_c.resize(m);

    FrRand(com_sec.r_com_a);
    FrRand(com_sec.r_com_b);
    FrRand(com_sec.r_com_c);
    
    auto parallel_f = [&com_sec, &com_pub, &input](int64_t i) {
        com_pub.com_a[i] = pc::ComputeCom(input.a[i], com_sec.r_com_a[i]);
        com_pub.com_b[i] = pc::ComputeCom(input.b[i], com_sec.r_com_b[i]);
        com_pub.com_c[i] = pc::ComputeCom(input.c[i], com_sec.r_com_c[i]);
    };
    parallel::For(m, parallel_f);
  }

    static bool Test(uint64_t m, uint64_t n);

};

inline bool A7::Test(uint64_t m, uint64_t n) {
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
    Prove(proof, seed, prove_input, com_sec);
    

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
    std::cout << "FrSize:" << proof.FrSize() << "\t G1Size:" << proof.G1Size() << "\n";
#endif

    VerifyInput verify_input(m, n, com_pub, pc::kGetRefG1);
    bool success = Verify(proof, seed, verify_input);
    std::cout << Tick::GetIndentString() << success << "\n\n\n\n\n\n";
    return success;
}


}