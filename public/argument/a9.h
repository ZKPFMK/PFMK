#pragma once

#include "./details.h"
#include "./a8.h"

// a_i: public vector<Fr>, i\in[0,m-1], a_i.size() maybe neq a_j.size()
// b_i: secret vector<Fr>, i\in[0,m-1], x_i.size() maybe neq x_j.size()
// a_i.size() must eq x_i.size()
// c: secret Fr
// open: com(g,a), com(g,b), com(gz,c)
// prove: c = \sum_{i=0}^{m}<x_i,a_i>
// proof size:


//需要处理长度不一致的情况
namespace argument {
struct A9 {
  struct CommitmentPub {
    std::vector<G1> com_a;
    std::vector<G1> com_b;
    G1 com_c;
    CommitmentPub(){}
    CommitmentPub(std::vector<G1> const& com_a, std::vector<G1> const& com_b, G1 const& com_c)
        : com_a(com_a),
          com_b(com_b),
          com_c(com_c){}
    bool operator==(CommitmentPub const& right) const {
      return com_a == right.com_a && com_b == right.com_b && com_c == right.com_c;
    }

    bool operator!=(CommitmentPub const& right) const {
      return !(*this == right);
    }
  };

  struct CommitmentSec {
    std::vector<Fr> r_com_a;  // r.size = m
    std::vector<Fr> r_com_b;  // r.size = m
    Fr r_com_c;
    CommitmentSec(){

    }
    CommitmentSec(std::vector<Fr> const& r_com_a, std::vector<Fr> const& r_com_b, Fr const& r_com_c)
        : r_com_a(r_com_a),
          r_com_b(r_com_b),
          r_com_c(r_com_c){}
  };

  struct VerifyInput {
    VerifyInput(size_t _n,
                CommitmentPub const& com_pub,
                GetRefG1 const& get_g,
                G1 const& gc)
        : _n(_n),
          com_pub(com_pub),
          get_g(get_g),
          gc(gc) {
    }
    size_t _n = 0;
    CommitmentPub const com_pub;
    GetRefG1 const& get_g;
    G1 const& gc;

    int64_t m() const { return com_pub.com_a.size(); }
    int64_t n() const { return _n; }
    std::string to_string() const {
      return std::to_string(m()) + " " + std::to_string(n());
    }
  };

  struct ProveInput {
    std::vector<std::vector<Fr>> const a;
    std::vector<std::vector<Fr>> const b;
    Fr const c;
    GetRefG1 const& get_g;
    G1 const& gc;
    size_t _n = 0;

    int64_t m() const { return (int64_t)a.size(); }
    int64_t n() const { return (int64_t)_n; }
    std::string to_string() const {
      return std::to_string(m()) + "*" + std::to_string(n());
    }
    ProveInput(std::vector<std::vector<Fr>> const& a,
               std::vector<std::vector<Fr>> const& b, 
               Fr const& c, GetRefG1 const& get_g, G1 const& gc)
        : a(a),
          b(b),
          c(c),
          get_g(get_g),
          gc(gc) {
      for(size_t i=0; i<b.size(); i++) {
        _n = _n > b[i].size() ? _n : b[i].size();
      }
    }
  };

  struct Proof {
    std::vector<G1> com_t0; 
    std::vector<G1> com_t2; 
    A8::Proof sub_proof;

    size_t FrSize(){
      return sub_proof.FrSize();
    }

    size_t G1Size(){
      return (com_t0.size() << 1) + sub_proof.G1Size();
    }

    bool operator==(Proof const& right) const {
      return com_t0 == right.com_t0 && com_t2 == right.com_t2 && sub_proof == right.sub_proof;
    }
    bool operator!=(Proof const& right) const { return !(*this == right); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("A9.p", ("0", com_t0), ("2", com_t2), ("p", sub_proof));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("A9.p", ("0", com_t0), ("2", com_t2), ("p", sub_proof));
    }
  };

  static void ComputeCom(ProveInput const& input,
                         CommitmentPub & com_pub,
                         CommitmentSec & com_sec) {
    Tick tick(__FN__);
    auto m = input.m();

    com_pub.com_a.resize(m);
    com_pub.com_b.resize(m);
    com_sec.r_com_a.resize(m);
    com_sec.r_com_b.resize(m);

    FrRand(com_sec.r_com_a);
    FrRand(com_sec.r_com_b);
    com_sec.r_com_c = FrRand();
    
    com_pub.com_c = pc::ComputeCom(input.gc, input.c, com_sec.r_com_c);
    auto parallel_f = [&input, &com_pub, &com_sec](int64_t i){
      com_pub.com_a[i] = pc::ComputeCom(input.get_g, input.a[i], com_sec.r_com_a[i]);
      com_pub.com_b[i] = pc::ComputeCom(input.get_g, input.b[i], com_sec.r_com_b[i]);
    };
    parallel::For(m, parallel_f);
  }

  static void CheckInput(ProveInput const& input){
    assert(input.a.size() == input.b.size() && !input.b.empty());
    Fr c = FrZero();
    for(size_t i=0; i<input.m(); i++){
      assert(input.a[i].size() == input.b[i].size());
      c += InnerProduct(input.a[i], input.b[i]);
    }
    assert(input.c == c);
  }

  static void CheckWitness(ProveInput const& input, 
                           CommitmentPub const& com_pub,
                           CommitmentSec const& com_sec){
    CheckInput(input);
    assert(pc::ComputeCom(input.gc, input.c, com_sec.r_com_c) == com_pub.com_c);
    for(size_t i=0; i<input.m(); i++){
      CHECK(pc::ComputeCom(input.get_g, input.a[i], com_sec.r_com_a[i]) == com_pub.com_a[i], std::to_string(i));
      CHECK(pc::ComputeCom(input.get_g, input.b[i], com_sec.r_com_b[i]) == com_pub.com_b[i], std::to_string(i));
    }
  }
  

  static void Prove(Proof& proof, h256_t seed,
                    ProveInput const& input,
                    CommitmentSec const& com_sec) {
    Tick tick(__FN__, input.to_string());
    int64_t n = input.n();
    int64_t m = input.m();
    int64_t round = (int64_t)misc::Log2UB(m);

    if(DEBUG_CHECK){
      CheckInput(input);
    }

    auto c = input.c;
    auto r_com_c = com_sec.r_com_c;
    auto const& r_com_a = com_sec.r_com_a;
    auto const& r_com_b = com_sec.r_com_b;

    std::vector<Fr> a(m*n, FrZero()), b(m*n, FrZero());
    auto parallel_f = [&input, &a, &b](size_t i){
      size_t j = i * input.n();
      std::copy(input.a[i].begin(), input.a[i].end(), a.begin()+j);
      std::copy(input.b[i].begin(), input.b[i].end(), b.begin()+j);
    };
    parallel::For(m, parallel_f);

    std::vector<Fr> e; //随机数
    SumCheck::Prove(round, (1 << round) * n, proof.com_t0, proof.com_t2, e, seed, a, b, c, r_com_c, input.gc);

    assert(a.size() == n);
    assert(b.size() == n);
    assert(InnerProduct(a, b) == c);

    std::vector<Fr> e_hat = misc::BuildE(e);;
    std::vector<Fr> e_chk(e_hat.rbegin(), e_hat.rend());
    e_hat.resize(m);
    e_chk.resize(m);

    Fr r_com_u = InnerProduct(e_hat, r_com_a);
    Fr r_com_v = InnerProduct(e_chk, r_com_b);
    A8::ProveInput a8_in(a, b, c, input.get_g, input.gc);
    A8::CommitmentSec a8_sec(r_com_u, r_com_v, r_com_c);
    A8::Prove(proof.sub_proof, seed, a8_in, a8_sec);
  }

  static bool Verify(Proof const& proof, h256_t seed, VerifyInput const& input) {
    Tick tick(__FN__, input.to_string());
    
    int64_t n = input.n();
    int64_t m = input.m();
    int64_t round = (int64_t)misc::Log2UB(m);

    auto com_c = input.com_pub.com_c;
    auto const& com_a = input.com_pub.com_a;
    auto const& com_b = input.com_pub.com_b;

    std::vector<Fr> e(round); //随机数
    SumCheck::Verify(proof.com_t0, proof.com_t2, seed, com_c, e);

    std::vector<Fr> e_hat = misc::BuildE(e);
    std::vector<Fr> e_chk(e_hat.rbegin(), e_hat.rend());
    e_hat.resize(m);
    e_chk.resize(m);

    G1 com_u = MultiExpBdlo12(com_a, e_hat);
    G1 com_v = MultiExpBdlo12(com_b, e_chk);
    A8::CommitmentPub a8_pub(com_u, com_v, com_c);
    A8::VerifyInput a8_in(input.n(), a8_pub, input.get_g, input.gc);
    return A8::Verify(proof.sub_proof, seed, a8_in);
  }

 public:
  static bool Test(int64_t m, int64_t n) {
    Tick tick(__FN__, std::to_string(m) + " " + std::to_string(n));

    std::vector<std::vector<Fr>> a(m, std::vector<Fr>(n, 0));
    std::vector<std::vector<Fr>> b(m, std::vector<Fr>(n, 0));

    for (int i=0; i<m; i++) {
      FrRand(a[i]);
      FrRand(b[i]);
      if(i > 0){
        size_t len =  std::rand() % (n + 1);
        a[i].resize(len);
        b[i].resize(len);
      }
    }

    Fr c = FrZero();
    for (int64_t i = 0; i < m; ++i) {
      c += InnerProduct(a[i], b[i]);
    }

    h256_t seed = misc::RandH256();
    G1 gc = pc::kGetRefG1(0);
    GetRefG1 get_g = pc::kGetRefG1;

    ProveInput prove_input(a, b, c, get_g, gc);
    CommitmentPub com_pub;
    CommitmentSec com_sec;
    ComputeCom(prove_input, com_pub, com_sec);

    if(DEBUG_CHECK){
      CheckWitness(prove_input, com_pub, com_sec);
    }

    Proof proof;
    Prove(proof, seed, prove_input, com_sec);
#ifndef DISABLE_SERIALIZE_CHECK
    // serialize to buffer
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
    VerifyInput verify_input(n, com_pub, get_g, gc);
    bool success = Verify(proof, seed, verify_input);
    std::cout << __FILE__ << " " << __FN__ << ": " << success << "\n\n\n\n\n\n";
    return success;
  }
};
}  // namespace argument
