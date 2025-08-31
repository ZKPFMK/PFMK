#pragma once

#include "./details.h"
#include "./a1.h"
#include "./a5.h"
#include "./sumcheck.h"

namespace argument{

// A, B, C: secret Fr, m*k, k*n, m*n
// open: com(gx, A), com(gy, B), com(gz,C)
// prove: A B = C
// proof size:
// prove cost:
// verify cost:

struct A6{
  struct ProveInput{
    std::vector<std::vector<Fr>> const& a; // m*k
    std::vector<std::vector<Fr>> const& b; // k*n
    std::vector<std::vector<Fr>> const& c; // m*n
    GetRefG1 const& get_g;

    int64_t m() const { return a.size(); }
    int64_t k() const { return a[0].size(); }
    int64_t n() const { return b[0].size(); }

    std::string to_string() const {
      return std::to_string(m()) + "*" + std::to_string(k()) + "*" + std::to_string(n());
    }

    ProveInput(std::vector<std::vector<Fr>> const& a,
               std::vector<std::vector<Fr>> const& b,
               std::vector<std::vector<Fr>> const& c,
               GetRefG1 const& get_g)
      : a(a),
        b(b),
        c(c),
        get_g(get_g){
    }
  };

  struct CommitmentPub {
    std::vector<G1> a;  // a.size = m
    std::vector<G1> b;  // b.size = k
    std::vector<G1> c;  // c.size = m

    bool row_a = true;
    bool row_c = true;

    CommitmentPub(){}
    CommitmentPub(std::vector<G1> const& a,
                  std::vector<G1> const& b,
                  std::vector<G1> const& c,
                  bool row_a = true,
                  bool row_c = true)
        :   a(a), b(b), c(c), row_a(row_a), row_c(row_c) {}
  };

  struct CommitmentSec {
    std::vector<Fr> r_com_a;  // r.size = m
    std::vector<Fr> r_com_b;  // s.size = k
    std::vector<Fr> r_com_c;  // t.size = m
    bool row_a = true;
    bool row_c = true;
    CommitmentSec(){}
    CommitmentSec(std::vector<Fr> const& r_com_a,
                  std::vector<Fr> const& r_com_b,
                  std::vector<Fr> const& r_com_c,
                  bool row_a = true,
                  bool row_c = true)
        :   r_com_a(r_com_a), r_com_b(r_com_b), r_com_c(r_com_c), row_a(row_a), row_c(row_c) {}
  };

  struct VerifyInput {
    VerifyInput(size_t const& m_, int64_t const& k_, int64_t const& n_,
                CommitmentPub const& com_pub,
                GetRefG1 const& get_g)
        :   m_(m_),
            n_(n_),
            k_(k_),
            com_pub(com_pub),
            get_g(get_g) {
        }

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
      ar& YAS_OBJECT_NVP("a6.p", ("0", com_t0), ("2", com_t2), ("u", com_u), ("p1", sub_proof1), ("p2", sub_proof2));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("a6.p", ("0", com_t0), ("2", com_t2), ("u", com_u), ("p1", sub_proof1), ("p2", sub_proof2));
    }
  };

  static void CheckInput(ProveInput const& input){
    auto const& a = input.a;
    auto const& b = input.b;
    auto const& c = input.c;
    assert(!a.empty() && !a[0].empty() && !b[0].empty());
    assert(a.size() == c.size() && a[0].size() == b.size() && b[0].size() == c[0].size());
    assert(MatrixMul(input.a, input.b) == input.c);
  }

  static void CheckWitness(ProveInput const& input, 
                           CommitmentPub const& com_pub,
                           CommitmentSec const& com_sec){
    CheckInput(input);
    if(com_pub.row_a){
      for(int64_t i=0; i<input.m(); i++){
        assert(pc::ComputeCom(input.get_g, input.a[i], com_sec.r_com_a[i]) == com_pub.a[i]);
      }
    }else{
      for(int64_t j=0; j<input.k(); j++){
        auto get_a = [&input, &j](size_t i)-> Fr const& {
          return input.a[i][j];
        };
        assert(com_pub.a[j] == pc::ComputeCom(input.m(), input.get_g, get_a, com_sec.r_com_a[j]));
      }
    }
    
    for(int64_t i=0; i<input.k(); i++){
      assert(pc::ComputeCom(input.get_g, input.b[i], com_sec.r_com_b[i]) == com_pub.b[i]);
    }

    if(com_pub.row_c){
      for(int64_t i=0; i<input.m(); i++){
        assert(pc::ComputeCom(input.get_g, input.c[i], com_sec.r_com_c[i]) == com_pub.c[i]);
      }
    }else{
      for(int64_t j=0; j<input.n(); j++){
        auto get_c = [&input, &j](size_t i)-> Fr const& {
          return input.c[i][j];
        };
        assert(com_pub.c[j] == pc::ComputeCom(input.m(), input.get_g, get_c, com_sec.r_com_c[j]));
      }
    }
  }

  static void ComputeCom(CommitmentPub& com_pub, CommitmentSec& com_sec,
                        ProveInput const& input){
    Tick tick(__FN__, input.to_string());
    auto const m = input.m(); // m*k
    auto const k = input.k(); // k*n
    auto const n = input.n(); // m*n

    if(com_pub.row_a){
      com_pub.a.resize(m);
      com_sec.r_com_a.resize(m);
    }else{
      com_pub.a.resize(k);
      com_sec.r_com_a.resize(k);
    }

    if(com_pub.row_c){
      com_pub.c.resize(m);
      com_sec.r_com_c.resize(m);
    }else{
      com_pub.c.resize(n);
      com_sec.r_com_c.resize(n);
    }
    
    com_pub.b.resize(k);
    com_sec.r_com_b.resize(k);
   
    FrRand(com_sec.r_com_a);
    FrRand(com_sec.r_com_b);
    FrRand(com_sec.r_com_c);
    
    std::array<parallel::VoidTask, 3> tasks;
    tasks[0] = [&com_pub, &input, &com_sec]() { //m*k
      if(com_pub.row_a){
        auto parallel_f = [&com_pub, &input, &com_sec](size_t i){
            com_pub.a[i] = pc::ComputeCom(input.a[i], com_sec.r_com_a[i]);
        };
        parallel::For(input.m(), parallel_f);
      }else{
        auto parallel_f = [&com_pub, &input, &com_sec](size_t j){
            auto get_a = [&input, &j](size_t i)-> Fr const& {
                return input.a[i][j];
            };
            com_pub.a[j] = pc::ComputeCom(input.m(), get_a, com_sec.r_com_a[j]);
        };
        parallel::For(input.k(), parallel_f);
      }
    };
    tasks[1] = [&com_pub, &input, &com_sec]() { //k*n
        auto parallel_f = [&com_pub, &input, &com_sec](size_t i){
            com_pub.b[i] = pc::ComputeCom(input.b[i], com_sec.r_com_b[i]);
        };
        parallel::For(input.k(), parallel_f);
        
    };
    tasks[2] = [&com_pub, &input, &com_sec]() { //m*n
      if(com_pub.row_c){
        auto parallel_f = [&com_pub, &input, &com_sec](size_t i){
          com_pub.c[i] = pc::ComputeCom(input.c[i], com_sec.r_com_c[i]);
        };
        parallel::For(input.m(), parallel_f);
      }else{
        auto parallel_f = [&com_pub, &input, &com_sec](size_t j){
          auto get_c = [&input, &j](size_t i) -> Fr const& {
            return input.c[i][j];
          };
          com_pub.c[j] = pc::ComputeCom(input.m(), get_c, com_sec.r_com_c[j]);
        };
        parallel::For(input.n(), parallel_f);
      }
    };
    parallel::Invoke(tasks);
  }

  //A为col
  static void Prove61(Proof& proof, h256_t seed,
                      ProveInput const& input,
                      CommitmentSec const& com_sec){
    Tick tick(__FN__, input.to_string());
    
    if(DEBUG_CHECK){
      CheckInput(input);
    }

    int64_t m = input.m(), n = input.n(), k = input.k();
    int64_t lm = (int64_t)misc::Log2UB(input.m());
    int64_t ln = (int64_t)misc::Log2UB(input.n());
    int64_t lk = (int64_t)misc::Log2UB(input.k());

    std::vector<Fr> r(lm), s(ln);
    std::vector<Fr> r_hat(m), s_hat(n);

    ComputeFst(seed, "libra::A61::r", r);
    ComputeFst(seed, "libra::A61::s", s);

    auto parallel_f1 = [&r_hat, &s_hat, r, s](int i){
      if(i == 0){
          misc::BuildR(r_hat, r);
      }else{
          misc::BuildR(s_hat, s);
      }
    };
    parallel::For(2, parallel_f1);

    std::vector<Fr> a = MatrixVectorMul(r_hat, input.a);
    std::vector<Fr> b = MatrixVectorMul(input.b, s_hat);
    std::vector<Fr> c = -r_hat;
    std::vector<Fr> d = MatrixVectorMul(input.c, s_hat);
    
    int64_t l = (m > k ? m : k), ll = (m > k ? lm : lk);
     
    std::vector<Fr> u1(1 << (ll+1), FrZero()), u2(1 << (ll+1), FrZero());
    std::copy(a.begin(), a.end(), u1.begin());
    std::copy(c.begin(), c.end(), u1.begin() + (1 << ll));
    std::copy(b.begin(), b.end(), u2.begin());
    std::copy(d.begin(), d.end(), u2.begin() + (1 << ll));

    SumCheck::ProveOutput out;
    SumCheck::CommitmentSec sec(0);
    SumCheck::ProveInput in(u1, u2, 0, input.get_g(0));
    SumCheck::Prove(out, proof.com_t0, proof.com_t2, seed, in, sec);

    Fr r_com_a = FrRand(), r_com_b = FrRand();
    proof.com_u[0] = pc::ComputeCom(input.get_g(0), out.a, r_com_a);
    proof.com_u[1] = pc::ComputeCom(input.get_g(0), out.b, r_com_b);

    A1::ProveInput a1_in(out.a, out.b, out.c);
    A1::CommitmentSec a1_sec(r_com_a, r_com_b, out.r_com_c);
    A1::Prove(proof.sub_proof1, seed, a1_in, a1_sec);

    auto const& e = out.e;
    std::vector<Fr> e_hat = misc::BuildE(std::vector<Fr>(e.begin()+1, e.end()));
    std::vector<Fr> e_chk(e_hat.rbegin(), e_hat.rend());
    
    std::vector<std::vector<Fr>> dd(2), bb(2);
    std::vector<Fr> r_com_dd(2), r_com_uu(2);
    std::vector<Fr> uu(2);

    dd[0] = MatrixVectorMul(
                input.a,
                std::vector<Fr>(e_hat.begin(), e_hat.begin()+k)
            );

    dd[1] = MatrixVectorMul(
                std::vector<Fr>(e_chk.begin(), e_chk.begin()+k),
                input.b
            ) * e[0] + 
            MatrixVectorMul(
                std::vector<Fr>(e_chk.begin(), e_chk.begin()+m),
                input.c
            );

    bb[0] = r_hat;
    bb[1] = s_hat;

    uu[0] = out.a - e[0] * InnerProduct(c, e_hat);
    uu[1] = out.b;

    r_com_dd[0] = InnerProduct(e_hat, com_sec.r_com_a);
    r_com_dd[1] = e[0] * InnerProduct(e_chk, com_sec.r_com_b) + InnerProduct(e_chk, com_sec.r_com_c);

    r_com_uu[0] = r_com_a;
    r_com_uu[1] = r_com_b;

    A5::CommitmentSec a5_sec(r_com_dd, r_com_uu);
    A5::ProveInput a5_in(dd, bb, uu, input.get_g, input.get_g(0));
    A5::Prove(proof.sub_proof2, seed, a5_in, a5_sec);
  };

  static bool Verify61(Proof const& proof, h256_t seed, VerifyInput const& input){
    Tick tick(__FN__, input.to_string());

    int64_t m = input.m(), n = input.n(), k = input.k();
    int64_t lm = (int64_t)misc::Log2UB(input.m());
    int64_t ln = (int64_t)misc::Log2UB(input.n());
    int64_t lk = (int64_t)misc::Log2UB(input.k());

    std::vector<Fr> r(lm), s(ln);
    std::vector<Fr> r_hat(m), s_hat(n);

    ComputeFst(seed, "libra::A61::r", r);
    ComputeFst(seed, "libra::A61::s", s);

    auto parallel_f1 = [&r_hat, &s_hat, r, s](int i){
        if(i == 0){
            misc::BuildR(r_hat, r);
        }else{
            misc::BuildR(s_hat, s);
        }
    };
    parallel::For(2, parallel_f1);

    int64_t l = (m > k ? m : k), ll = (m > k ? lm : lk);

    G1 com_c = G1Zero();
    std::vector<Fr> e;
    SumCheck::Verify(proof.com_t0, proof.com_t2, seed, com_c, e);

    A1::CommitmentPub a1_pub(proof.com_u[0], proof.com_u[1], com_c);
    A1::VerifyInput a1_in(a1_pub);
    bool ret = A1::Verify(proof.sub_proof1, seed, a1_in);

    std::vector<Fr> e_hat = misc::BuildE(std::vector<Fr>(e.begin()+1, e.end()));
    std::vector<Fr> e_chk(e_hat.rbegin(), e_hat.rend());
    
    std::vector<std::vector<Fr>> bb(2);
    std::vector<G1> com_dd(2);
    std::vector<G1> com_uu(2);
    
    com_dd[0] = MultiExpBdlo12(input.com_pub.a, e_hat);
    com_dd[1] = MultiExpBdlo12(input.com_pub.b, e_chk) * e[0] + MultiExpBdlo12(input.com_pub.c, e_chk);

    bb[0] = r_hat;
    bb[1] = s_hat;

    com_uu[0] = proof.com_u[0] + input.get_g(0) * (e[0] * InnerProduct(r_hat, e_hat));
    com_uu[1] = proof.com_u[1];

    A5::CommitmentPub a5_pub(com_dd, com_uu);
    A5::VerifyInput a5_in(bb, a5_pub, input.get_g, input.get_g(0));
    ret &= A5::Verify(proof.sub_proof2, seed, a5_in);
    
    return ret;
  }


  static void Prove62(Proof& proof, h256_t seed,
                      ProveInput const& input,
                      CommitmentSec const& com_sec){
    Tick tick(__FN__, input.to_string());
    
    if(DEBUG_CHECK){
      CheckInput(input);
    }

    int64_t m = input.m(), n = input.n(), k = input.k();
    int64_t lm = (int64_t)misc::Log2UB(input.m());
    int64_t ln = (int64_t)misc::Log2UB(input.n());
    int64_t lk = (int64_t)misc::Log2UB(input.k());

    std::vector<Fr> r(lm), s(ln);
    std::vector<Fr> r_hat(m), s_hat(n);

    ComputeFst(seed, "libra::A62::r", r);
    ComputeFst(seed, "libra::A62::s", s);

    auto parallel_f1 = [&r_hat, &s_hat, r, s](int i){
      if(i == 0){
          misc::BuildR(r_hat, r);
      }else{
          misc::BuildR(s_hat, s);
      }
    };
    parallel::For(2, parallel_f1);

    std::vector<Fr> a = MatrixVectorMul(r_hat, input.a);
    std::vector<Fr> b = MatrixVectorMul(input.b, s_hat);
    std::vector<Fr> c = MatrixVectorMul(input.c, s_hat);
    std::vector<Fr> d = -r_hat;

    int64_t l = (m > k ? m : k), ll = (m > k ? lm : lk);
    std::vector<Fr> u1(1 << (ll+1), FrZero()), u2(1 << (ll+1), FrZero());
    std::copy(a.begin(), a.end(), u1.begin());
    std::copy(c.begin(), c.end(), u1.begin() + (1 << ll));
    std::copy(b.begin(), b.end(), u2.begin());
    std::copy(d.begin(), d.end(), u2.begin() + (1 << ll));

    SumCheck::ProveOutput out;
    SumCheck::CommitmentSec sec(0);
    SumCheck::ProveInput in(u1, u2, 0, input.get_g(0));
    SumCheck::Prove(out, proof.com_t0, proof.com_t2, seed, in, sec);

    Fr r_com_a = FrRand(), r_com_b = FrRand();
    proof.com_u[0] = pc::ComputeCom(input.get_g(0), out.a, r_com_a);
    proof.com_u[1] = pc::ComputeCom(input.get_g(0), out.b, r_com_b);

    A1::ProveInput a1_in(out.a, out.b, out.c);
    A1::CommitmentSec a1_sec(r_com_a, r_com_b, out.r_com_c);
    A1::Prove(proof.sub_proof1, seed, a1_in, a1_sec);

    auto const& e = out.e;
    std::vector<Fr> e_hat = misc::BuildE(std::vector<Fr>(e.begin()+1, e.end()));
    std::vector<Fr> e_chk(e_hat.rbegin(), e_hat.rend());
    
    std::vector<Fr> r_com_dd(2), r_com_uu(2);
    std::vector<std::vector<Fr>> dd(2), bb(2);
    std::vector<Fr> uu(2);

    dd[0] = a + c * e[0];
    dd[1] = MatrixVectorMul(
                std::vector<Fr>(e_chk.begin(), e_chk.begin()+k),
                input.b
            ) * e[0];

    bb[0] = std::vector<Fr>(e_hat.begin(), e_hat.begin() + l);
    bb[1] = s_hat;

    uu[0] = out.a;
    uu[1] = out.b - InnerProduct(d, e_chk);

    r_com_dd[0] = InnerProduct(r_hat, com_sec.r_com_a) + e[0] * InnerProduct(s_hat, com_sec.r_com_c);
    r_com_dd[1] = e[0] * InnerProduct(e_chk, com_sec.r_com_b);

    r_com_uu[0] = r_com_a;
    r_com_uu[1] = r_com_b;

    A5::CommitmentSec a5_sec(r_com_dd, r_com_uu);
    A5::ProveInput a5_in(dd, bb, uu, input.get_g, input.get_g(0));
    A5::Prove(proof.sub_proof2, seed, a5_in, a5_sec);
  }

  static bool Verify62(Proof const& proof, h256_t seed, VerifyInput const& input){
    Tick tick(__FN__, input.to_string());

    int64_t m = input.m(), n = input.n(), k = input.k();
    int64_t lm = (int64_t)misc::Log2UB(input.m());
    int64_t ln = (int64_t)misc::Log2UB(input.n());
    int64_t lk = (int64_t)misc::Log2UB(input.k());

    std::vector<Fr> r(lm), s(ln);
    std::vector<Fr> r_hat(m), s_hat(n);

    ComputeFst(seed, "libra::A62::r", r);
    ComputeFst(seed, "libra::A62::s", s);

    auto parallel_f1 = [&r_hat, &s_hat, r, s](int i){
        if(i == 0){
            misc::BuildR(r_hat, r);
        }else{
            misc::BuildR(s_hat, s);
        }
    };
    parallel::For(2, parallel_f1);

    int64_t l = (m > k ? m : k), ll = (m > k ? lm : lk);

    G1 com_c = G1Zero();
    std::vector<Fr> e;
    SumCheck::Verify(proof.com_t0, proof.com_t2, seed, com_c, e);

    A1::CommitmentPub a1_pub(proof.com_u[0], proof.com_u[1], com_c);
    A1::VerifyInput a1_in(a1_pub);
    bool ret = A1::Verify(proof.sub_proof1, seed, a1_in);

    std::vector<Fr> e_hat = misc::BuildE(std::vector<Fr>(e.begin()+1, e.end()));
    std::vector<Fr> e_chk(e_hat.rbegin(), e_hat.rend());
    
    std::vector<std::vector<Fr>> bb(2);
    std::vector<G1> com_dd(2);
    std::vector<G1> com_uu(2);
    
    com_dd[0] = MultiExpBdlo12(input.com_pub.a, r_hat) + MultiExpBdlo12(input.com_pub.c, s_hat) * e[0];
    com_dd[1] = MultiExpBdlo12(input.com_pub.b, e_chk) * e[0];

    bb[0] = std::vector<Fr>(e_hat.begin(), e_hat.begin() + l);
    bb[1] = s_hat;

    com_uu[0] = proof.com_u[0];
    com_uu[1] = proof.com_u[1] + input.get_g(0) * InnerProduct(r_hat, e_chk);

    A5::CommitmentPub a5_pub(com_dd, com_uu);
    A5::VerifyInput a5_in(bb, a5_pub, input.get_g, input.get_g(0));
    ret &= A5::Verify(proof.sub_proof2, seed, a5_in);
    return ret;
  }

  static void Prove63(Proof& proof, h256_t seed,
                    ProveInput const& input,
                    CommitmentSec const& com_sec){
    Tick tick(__FN__, input.to_string());
    
    if(DEBUG_CHECK){
      CheckInput(input);
    }

    int64_t m = input.m(), n = input.n(), k = input.k();
    int64_t lm = (int64_t)misc::Log2UB(input.m());
    int64_t ln = (int64_t)misc::Log2UB(input.n());
    int64_t lk = (int64_t)misc::Log2UB(input.k());

    std::vector<Fr> r(lm), s(ln);
    std::vector<Fr> r_hat(m), s_hat(n);

    ComputeFst(seed, "libra::A63::r", r);
    ComputeFst(seed, "libra::A63::s", s);

    auto parallel_f1 = [&r_hat, &s_hat, r, s](int i){
      if(i == 0){
          misc::BuildR(r_hat, r);
      }else{
          misc::BuildR(s_hat, s);
      }
    };
    parallel::For(2, parallel_f1);

    std::vector<Fr> a = MatrixVectorMul(r_hat, input.a);
    std::vector<Fr> b = MatrixVectorMul(input.b, s_hat);
    std::vector<Fr> c = MatrixVectorMul(r_hat, input.c);
    std::vector<Fr> d = -s_hat;
    
    int64_t l = (n > k ? n : k), ll = (n > k ? ln : lk);
     
    std::vector<Fr> u1(1 << (ll+1), FrZero()), u2(1 << (ll+1), FrZero());
    std::copy(a.begin(), a.end(), u1.begin());
    std::copy(c.begin(), c.end(), u1.begin() + (1 << ll));
    std::copy(b.begin(), b.end(), u2.begin());
    std::copy(d.begin(), d.end(), u2.begin() + (1 << ll));

    SumCheck::ProveOutput out;
    SumCheck::CommitmentSec sec(0);
    SumCheck::ProveInput in(u1, u2, 0, input.get_g(0));
    SumCheck::Prove(out, proof.com_t0, proof.com_t2, seed, in, sec);

    Fr r_com_a = FrRand(), r_com_b = FrRand();
    proof.com_u[0] = pc::ComputeCom(input.get_g(0), out.a, r_com_a);
    proof.com_u[1] = pc::ComputeCom(input.get_g(0), out.b, r_com_b);

    A1::ProveInput a1_in(out.a, out.b, out.c);
    A1::CommitmentSec a1_sec(r_com_a, r_com_b, out.r_com_c);
    A1::Prove(proof.sub_proof1, seed, a1_in, a1_sec);

    auto const& e = out.e;
    std::vector<Fr> e_hat = misc::BuildE(std::vector<Fr>(e.begin()+1, e.end()));
    std::vector<Fr> e_chk(e_hat.rbegin(), e_hat.rend());
    
    std::vector<Fr> r_com_dd(2), r_com_uu(2);
    std::vector<std::vector<Fr>> dd(2), bb(2);
    std::vector<Fr> uu(2);

    dd[0] = a + c * e[0];
    dd[1] = MatrixVectorMul(
                std::vector<Fr>(e_chk.begin(), e_chk.begin()+k),
                input.b
            ) * e[0];

    bb[0] = std::vector<Fr>(e_hat.begin(), e_hat.begin() + l);
    bb[1] = s_hat;

    uu[0] = out.a;
    uu[1] = out.b - InnerProduct(d, e_chk);

    r_com_dd[0] = InnerProduct(r_hat, com_sec.r_com_a) + e[0] * InnerProduct(r_hat, com_sec.r_com_c);
    r_com_dd[1] = e[0] * InnerProduct(e_chk, com_sec.r_com_b);

    r_com_uu[0] = r_com_a;
    r_com_uu[1] = r_com_b;

    A5::CommitmentSec a5_sec(r_com_dd, r_com_uu);
    A5::ProveInput a5_in(dd, bb, uu, input.get_g, input.get_g(0));
    A5::Prove(proof.sub_proof2, seed, a5_in, a5_sec);
  }

  static bool Verify63(Proof const& proof, h256_t seed, VerifyInput const& input){
    Tick tick(__FN__, input.to_string());

    int64_t m = input.m(), n = input.n(), k = input.k();
    int64_t lm = (int64_t)misc::Log2UB(input.m());
    int64_t ln = (int64_t)misc::Log2UB(input.n());
    int64_t lk = (int64_t)misc::Log2UB(input.k());

    std::vector<Fr> r(lm), s(ln);
    std::vector<Fr> r_hat(m), s_hat(n);

    ComputeFst(seed, "libra::A63::r", r);
    ComputeFst(seed, "libra::A63::s", s);

    auto parallel_f1 = [&r_hat, &s_hat, r, s](int i){
        if(i == 0){
            misc::BuildR(r_hat, r);
        }else{
            misc::BuildR(s_hat, s);
        }
    };
    parallel::For(2, parallel_f1);

    int64_t l = (n > k ? n : k), ll = (n > k ? ln : lk);

    G1 com_c = G1Zero();
    std::vector<Fr> e;
    SumCheck::Verify(proof.com_t0, proof.com_t2, seed, com_c, e);

    A1::CommitmentPub a1_pub(proof.com_u[0], proof.com_u[1], com_c);
    A1::VerifyInput a1_in(a1_pub);
    bool ret = A1::Verify(proof.sub_proof1, seed, a1_in);

    std::vector<Fr> e_hat = misc::BuildE(std::vector<Fr>(e.begin()+1, e.end()));
    std::vector<Fr> e_chk(e_hat.rbegin(), e_hat.rend());
    
    std::vector<std::vector<Fr>> bb(2);
    std::vector<G1> com_dd(2);
    std::vector<G1> com_uu(2);
    
    com_dd[0] = MultiExpBdlo12(input.com_pub.a, r_hat) + MultiExpBdlo12(input.com_pub.c, r_hat) * e[0];
    com_dd[1] = MultiExpBdlo12(input.com_pub.b, e_chk) * e[0];

    bb[0] = std::vector<Fr>(e_hat.begin(), e_hat.begin() + (k > n ? k : n));
    bb[1] = s_hat;

    com_uu[0] = proof.com_u[0];
    com_uu[1] = proof.com_u[1] + input.get_g(0) * InnerProduct(s_hat, e_chk);

    A5::CommitmentPub a5_pub(com_dd, com_uu);
    A5::VerifyInput a5_in(bb, a5_pub, input.get_g, input.get_g(0));
    ret &= A5::Verify(proof.sub_proof2, seed, a5_in);
    return ret;
  }

  static void Prove(Proof& proof, h256_t seed,
                    ProveInput const& input,
                    CommitmentSec const& com_sec){
    Tick tick(__FN__, input.to_string());
    if(!com_sec.row_a){
      Prove61(proof, seed, input, com_sec);
    }else if(!com_sec.row_c){
      Prove62(proof, seed, input, com_sec);
    }else{
      Prove63(proof, seed, input, com_sec);
    }
  }


  static bool Verify(Proof const& proof, h256_t seed, VerifyInput const& input){
    Tick tick(__FN__, input.to_string());
    if(!input.com_pub.row_a){
      return Verify61(proof, seed, input);
    }else if(!input.com_pub.row_c){
      return Verify62(proof, seed, input);
    }else{
      return Verify63(proof, seed, input);
    }
  }

  static bool Test(int64_t m, int64_t k, int64_t n, bool row_a, bool row_c); //矩阵乘
};

inline bool A6::Test(int64_t m, int64_t k, int64_t n, bool row_a, bool row_c) {

    Tick tick(__FN__, std::to_string(m) + " " +
                      std::to_string(k) + " " +
                      std::to_string(n) + "");

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

    ProveInput prove_input(a, b, c, pc::kGetRefG1);
    CommitmentPub com_pub;
    CommitmentSec com_sec;
    com_pub.row_a = row_a;
    com_pub.row_c = row_c;
    com_sec.row_a = row_a;
    com_sec.row_c = row_c;
    ComputeCom(com_pub, com_sec, prove_input);

    CheckWitness(prove_input, com_pub, com_sec);

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

    VerifyInput verify_input(m, k, n, com_pub, pc::kGetRefG1);
    bool success = Verify(proof, seed, verify_input);
    std::cout << Tick::GetIndentString() << success << "\n\n\n\n\n\n";
    return success;

    return true;
}
}