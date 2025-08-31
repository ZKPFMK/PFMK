#pragma once

#include "./details.h"
#include "./a3.h"
#include "./sumcheck.h"

// a_i: secret vector<Fr>, i\in[0,m-1], a_i.size() maybe neq a_j.size()
// b_i: public vector<Fr>, i\in[0,m-1], x_i.size() maybe neq x_j.size()
// a_i.size() must eq x_i.size()
// c: secret Fr
// open: com(gx,a), com(gz,c)
// prove: c = \sum_{i=0}^{m}<a_i,b_i>
// proof size: 2logm+2logn+2 G1 and 4 Fr


//需要处理长度不一致的情况
namespace argument {
struct A4 {
  struct CommitmentPub {
    std::vector<G1> com_a;
    G1 com_c;
    CommitmentPub(){}
    CommitmentPub(std::vector<G1> const& com_a, G1 const& com_c)
        : com_a(com_a),
          com_c(com_c){}
    bool operator==(CommitmentPub const& right) const {
      return com_a == right.com_a && com_c == right.com_c;
    }

    bool operator!=(CommitmentPub const& right) const {
      return !(*this == right);
    }
  };

  struct CommitmentSec {
    std::vector<Fr> r_com_a;  // r.size = m
    Fr r_com_c;
    CommitmentSec(){

    }
    CommitmentSec(std::vector<Fr> const& r_com_a, Fr const& r_com_c)
        : r_com_a(r_com_a),
          r_com_c(r_com_c){}
  };

  struct VerifyInput {
    VerifyInput(std::vector<std::vector<Fr>> const& b,
                CommitmentPub const& com_pub,
                GetRefG1 const& get_ga,
                G1 const& gc)
        : b(b),
          com_pub(com_pub),
          get_ga(get_ga),
          gc(gc) {
      for(size_t i=0; i<b.size(); i++) {
        _n = _n > b[i].size() ? _n : b[i].size();
      }
    }
    size_t _n = 0;
    CommitmentPub const com_pub;
    std::vector<std::vector<Fr>> const b;
    GetRefG1 const& get_ga;
    G1 const& gc;

    int64_t m() const { return b.size(); }
    int64_t n() const { return _n; }
    std::string to_string() const {
      return std::to_string(m()) + " " + std::to_string(n());
    }
  };

  struct ProveInput {
    std::vector<std::vector<Fr>> const a;
    std::vector<std::vector<Fr>> const b;
    Fr const c;
    GetRefG1 const& get_ga;
    G1 const& gc;
    size_t _n = 0;

    int64_t m() const { return (int64_t)a.size(); }
    int64_t n() const { return (int64_t)_n; }
    std::string to_string() const {
      return std::to_string(m()) + "*" + std::to_string(n());
    }
    ProveInput(std::vector<std::vector<Fr>> const& a,
               std::vector<std::vector<Fr>> const& b, 
               Fr const& c, GetRefG1 const& get_ga, G1 const& gc)
        : a(a),
          b(b),
          c(c),
          get_ga(get_ga),
          gc(gc) {
      for(size_t i=0; i<b.size(); i++) {
        _n = _n > b[i].size() ? _n : b[i].size();
      }
    }
  };

  struct Proof {
    std::vector<G1> com_t0; 
    std::vector<G1> com_t2; 
    A3::Proof sub_proof;

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
      ar& YAS_OBJECT_NVP("a4.p", ("0", com_t0), ("2", com_t2), ("p", sub_proof));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("a4.p", ("0", com_t0), ("2", com_t2), ("p", sub_proof));
    }
  };

  static void ComputeCom(ProveInput const& input,
                         CommitmentPub & com_pub,
                         CommitmentSec & com_sec) {
    Tick tick(__FN__);
    auto m = input.m();

    com_pub.com_a.resize(m);
    com_sec.r_com_a.resize(m);

    com_sec.r_com_c = FrRand();
    FrRand(com_sec.r_com_a);
    com_pub.com_c = pc::ComputeCom(input.gc, input.c, com_sec.r_com_c);

    auto parallel_f = [&input, &com_pub, &com_sec](int64_t i){
      com_pub.com_a[i] = pc::ComputeCom(input.get_ga, input.a[i], com_sec.r_com_a[i]);
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
      CHECK(pc::ComputeCom(input.get_ga, input.a[i], com_sec.r_com_a[i]) == com_pub.com_a[i], std::to_string(i));
    }
  }

  static void UpdateWitness(std::vector<Fr> & a, std::vector<Fr> & b, Fr const& e, size_t half){
    auto parallel_f = [&a, &b, &e, &half](int64_t i){
      size_t j = i + half;
      if(j >= a.size()) {
        b[i] = b[i] * e;
      }else{
        a[i] = a[i] + a[j] * e;
        b[i] = b[i] * e + b[j];
      }
    };
    parallel::For(half, parallel_f);
    a.resize(half);
    b.resize(half);
  }

  static void UpdateWitness(std::vector<Fr> & b, Fr const& e, size_t half){
    auto parallel_f = [&b, &e, &half](int64_t i){
      size_t j = i + half;
      if(j >= b.size()) {
        b[i] = b[i] * e;
      }else{
        b[i] = b[i] * e + b[j];
      }
    };
    parallel::For(half, parallel_f);
    b.resize(half);
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
    auto const& gc = input.gc;
    auto & com_t0 = proof.com_t0;
    auto & com_t2 = proof.com_t2;

    std::vector<Fr> a(m*n, FrZero()), b(m*n, FrZero());

    auto parallel_f = [&input, &a, &b](size_t i){
      size_t j = i * input.n();
      std::copy(input.a[i].begin(), input.a[i].end(), a.begin()+j);
      std::copy(input.b[i].begin(), input.b[i].end(), b.begin()+j);
    };
    parallel::For(m, parallel_f);

    std::vector<Fr> e; //随机数
    SumCheck::Prove(round, (1 << round) * n, proof.com_t0, proof.com_t2, e, seed, a, b, c, r_com_c, gc);

    assert(a.size() == n);
    assert(b.size() == n);
    assert(InnerProduct(a, b) == c);

    std::vector<Fr> e_hat(m);
    misc::BuildE(e_hat, e);

    A3::CommitmentSec sec;
    sec.r_com_a = InnerProduct(r_com_a, e_hat);
    sec.r_com_c = r_com_c;

    A3::ProveInput in(a, b, c, input.get_ga, gc);
    A3::Prove(proof.sub_proof, seed, in, sec);
  }

  static bool Verify(Proof const& proof, h256_t seed, VerifyInput const& input) {
    Tick tick(__FN__, input.to_string());
    
    int64_t n = input.n();
    int64_t m = input.m();
    int64_t round = (int64_t)misc::Log2UB(m);

    auto const& gc = input.gc;
    auto com_c = input.com_pub.com_c;
    auto const& com_a = input.com_pub.com_a;
    auto const& com_t0 = proof.com_t0;
    auto const& com_t2 = proof.com_t2;

    std::vector<Fr> b(m*n, FrZero());

    auto parallel_f = [&input, &b](size_t i){
      size_t j = i * input.n();
      std::copy(input.b[i].begin(), input.b[i].end(), b.begin()+j);
    };
    parallel::For(m, parallel_f);

    std::vector<Fr> e(round); //随机数
    for (int64_t loop = 0, half=(1 << (round-1))*n; loop < round; ++loop, half>>=1) {
      UpdateSeed(seed, com_t0[loop], com_t2[loop]);
      e[loop] = H256ToFr(seed);

      UpdateWitness(b, e[loop], half);

      Fr ee = e[loop] * e[loop];
      com_c = com_t0[loop] + com_c * e[loop] + com_t2[loop] * ee;
    }
    assert(b.size() == n);

    std::vector<Fr> e_hat(m);
    misc::BuildE(e_hat, e);

    A3::CommitmentPub pub;
    pub.com_a = MultiExpBdlo12(com_a, e_hat);
    pub.com_c = com_c;
    A3::VerifyInput in(b, pub, input.get_ga, gc);
    return A3::Verify(proof.sub_proof, seed, in);
  }

 public:
  static bool Test(int64_t m, int64_t n) {
    Tick tick(__FN__, std::to_string(m) + " " + std::to_string(n));

    std::vector<std::vector<Fr>> a(m, std::vector<Fr>(n, 0));
    std::vector<std::vector<Fr>> b(m, std::vector<Fr>(n, 0));

    for (int i=0; i<m; i++) {
      FrRand(a[i]);
      FrRand(b[i]);
      size_t len =  std::rand() % (n + 1);
      a[i].resize(len);
      b[i].resize(len);
    }

    Fr c = FrZero();
    for (int64_t i = 0; i < m; ++i) {
      c += InnerProduct(a[i], b[i]);
    }

    h256_t seed = misc::RandH256();

    G1 gc = pc::kGetRefG1(0);
    GetRefG1 get_ga = pc::kGetRefG1;

    ProveInput prove_input(a, b, c, get_ga, gc);
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
    VerifyInput verify_input(b, com_pub, get_ga, gc);
    bool success = Verify(proof, seed, verify_input);
    std::cout << __FILE__ << " " << __FN__ << ": " << success << "\n\n\n\n\n\n";
    return success;
  }
};
}  // namespace argument
