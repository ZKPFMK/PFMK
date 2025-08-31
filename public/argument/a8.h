#pragma once

#include "./details.h"
#include "./a1.h"
#include "./a3.h"
#include "./a5.h"
#include "./sumcheck.h"

// b: public vector<Fr>, size = n
// a: secret vector<Fr>, size = n
// c: secret Fr,c = <a,b>
// open: com(g,a), com(g, b),  com(gc,c)
// prove: c=<a,b>
// proof size: 
// prove cost:
// verify cost:
namespace argument {
struct A8 {
  struct ProveInput {
    ProveInput(std::vector<Fr> const& a, std::vector<Fr> const& b, 
               Fr const& c, GetRefG1 const& get_g, G1 const& gc)
        : a(a), b(b), c(c), get_g(get_g), gc(gc) {
    }
    int64_t n() const { return (int64_t)a.size(); }
    std::string to_string() const { return std::to_string(n()); }

    std::vector<Fr> const& a;
    std::vector<Fr> const& b; 
    Fr const& c;              
    GetRefG1 const& get_g;
    G1 const& gc;
  };

  struct CommitmentPub {
    CommitmentPub() {}
    CommitmentPub(G1 const& com_a, G1 const& com_b, G1 const& com_c) 
        : com_a(com_a), 
          com_b(com_b),
          com_c(com_c) {}
    G1 com_a;
    G1 com_b;   
    G1 com_c;  
    bool operator==(CommitmentPub const& right) const {
      return com_a == right.com_a && com_b == right.com_b && com_c == right.com_c;
    }

    bool operator!=(CommitmentPub const& right) const {
      return !(*this == right);
    }
  };

  struct CommitmentSec {
    CommitmentSec() {}
    CommitmentSec(Fr const& r_com_a, Fr const& r_com_b, Fr const& r_com_c) 
        : r_com_a(r_com_a), r_com_b(r_com_b), r_com_c(r_com_c) {}
    Fr r_com_a;
    Fr r_com_b;
    Fr r_com_c;
  };

  struct Proof {
    std::vector<G1> com_t0;
    std::vector<G1> com_t2;
    G1 com_a, com_b;
    A5::Proof sub_proof;
    A1::Proof mul_proof;

    size_t FrSize(){
      return 3 + sub_proof.FrSize();
    }

    size_t G1Size(){
      return 2 + sub_proof.G1Size();
    }

    bool operator==(Proof const& right) const {
      return com_t0 == right.com_t0 && com_t2 == right.com_t2 &&
             com_a == right.com_a && com_b == right.com_b  && 
             mul_proof == right.mul_proof && sub_proof == right.sub_proof;
    }
    bool operator!=(Proof const& right) const { return !(*this == right); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("A8.p", ("0", com_t0), ("2", com_t2), ("a", com_a),
                                 ("b", com_b), ("mp", mul_proof), ("sp", sub_proof));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("A8.p", ("0", com_t0), ("2", com_t2), ("a", com_a),
                                 ("b", com_b), ("mp", mul_proof), ("sp", sub_proof));
    }
  };

  struct VerifyInput {
    VerifyInput(size_t _n,
                CommitmentPub const& com_pub,
                GetRefG1 const& get_g,
                G1 const& gc)
        : _n(_n), com_pub(com_pub), get_g(get_g), gc(gc) {}
    CommitmentPub const& com_pub;
    GetRefG1 const get_g;
    G1 const gc;
    size_t _n;
    int64_t n() const { return _n; }
    std::string to_string() const { return std::to_string(_n); }
  };


  static void ComputeCom(CommitmentPub& com_pub, CommitmentSec& com_sec,
                         ProveInput const& input) {
    Tick tick(__FN__, input.to_string());
    com_sec.r_com_a = FrRand();
    com_sec.r_com_b = FrRand();
    com_sec.r_com_c = FrRand();
    com_pub.com_a = pc::ComputeCom(input.get_g, input.a, com_sec.r_com_a);
    com_pub.com_b = pc::ComputeCom(input.get_g, input.b, com_sec.r_com_b);
    com_pub.com_c = pc::ComputeCom(input.gc, input.c, com_sec.r_com_c);
  }


  static void CheckInput(ProveInput const& input){
    assert(input.a.size() == input.b.size() && !input.a.empty());
    assert(input.c == InnerProduct(input.a, input.b));
  }

  static void CheckCom(ProveInput const& input, 
                      CommitmentPub const& com_pub,
                      CommitmentSec const& com_sec){
    assert(pc::ComputeCom(input.gc, input.c, com_sec.r_com_c) == com_pub.com_c);
    assert(pc::ComputeCom(input.get_g, input.a, com_sec.r_com_a) == com_pub.com_a);
    assert(pc::ComputeCom(input.get_g, input.b, com_sec.r_com_b) == com_pub.com_b);
  }

  static void CheckWitness(ProveInput const& input, 
                            CommitmentPub const& com_pub,
                            CommitmentSec const& com_sec){
    CheckInput(input);
    CheckCom(input, com_pub, com_sec);
  }

  static void Prove(Proof& proof, h256_t seed, 
                    ProveInput const& input,
                    CommitmentSec const& com_sec) {
    Tick tick(__FN__, input.to_string());
    
    if(DEBUG_CHECK){
      CheckInput(input);
    }
    auto n = input.n();
    size_t round = misc::Log2UB(n);

    auto a = input.a; //需要对b更改
    auto b = input.b;
    auto c = input.c;

    auto r_com_c = com_sec.r_com_c;
    auto const& r_com_a = com_sec.r_com_a;
    auto const& r_com_b = com_sec.r_com_b;
    
    std::vector<Fr> e; //随机数
    SumCheck::Prove(round, 1 << round, proof.com_t0, proof.com_t2, e, seed, a, b, c, r_com_c, input.gc);
    
    Fr ca = a[0], cb = b[0], r_com_ca = FrRand(), r_com_cb = FrRand();
    proof.com_a = pc::ComputeCom(input.gc, ca, r_com_ca);
    proof.com_b = pc::ComputeCom(input.gc, cb, r_com_cb);

    //乘积证明
    A1::ProveInput a1_in(ca, cb, c);
    A1::CommitmentSec a1_sec(r_com_ca, r_com_cb, r_com_c);
    A1::Prove(proof.mul_proof, seed, a1_in, a1_sec);

    std::vector<Fr> e_hat = misc::BuildE(e);
    std::vector<Fr> e_chk(e_hat.rbegin(), e_hat.rend());

    e_hat.resize(n);
    e_chk.resize(n);
    std::vector<std::vector<Fr>> u = {input.a, input.b};
    std::vector<std::vector<Fr>> v = {e_hat, e_chk};
    std::vector<Fr> w = {ca, cb};

    std::vector<Fr> r_com_u = {r_com_a, r_com_b};
    std::vector<Fr> r_com_w = {r_com_ca, r_com_cb};

    A5::ProveInput a5_in(u, v, w, input.get_g, input.gc);
    A5::CommitmentSec a5_sec(r_com_u, r_com_w);
    A5::Prove(proof.sub_proof, seed, a5_in, a5_sec);
  }

  static bool Verify(Proof const& proof, h256_t seed, VerifyInput const& input) {
    Tick tick(__FN__, input.to_string());
    auto n = input.n();
    size_t round = misc::Log2UB(n);

    auto const& com_a = input.com_pub.com_a;
    auto const& com_b = input.com_pub.com_b;
    auto com_c = input.com_pub.com_c;

    std::vector<Fr> e; //随机数
    SumCheck::Verify(proof.com_t0, proof.com_t2, seed, com_c, e);
    
    bool ret = true;
    A1::CommitmentPub a1_pub(proof.com_a, proof.com_b, com_c);
    A1::VerifyInput a1_in(a1_pub);
    ret &= A1::Verify(proof.mul_proof, seed, a1_in);

    std::vector<Fr> e_hat = misc::BuildE(e);
    std::vector<Fr> e_chk(e_hat.rbegin(), e_hat.rend());
    e_hat.resize(n);
    e_chk.resize(n);

    std::vector<std::vector<Fr>> v = {e_hat, e_chk};
    std::vector<G1> com_u = {com_a, com_b};
    std::vector<G1> com_w = {proof.com_a, proof.com_b};

    A5::CommitmentPub a5_pub(com_u, com_w);
    A5::VerifyInput a5_in(v, a5_pub, input.get_g, input.gc);
    ret &= A5::Verify(proof.sub_proof, seed, a5_in);
    return ret;
  }

  static bool Test(int64_t n);
};

bool A8::Test(int64_t n) { // z = x * a
  Tick tick(__FN__, std::to_string(n));

  std::vector<Fr> a(n);
  std::vector<Fr> b(n);

  FrRand(a);
  FrRand(b);
  Fr c = InnerProduct(a, b);

  h256_t seed = misc::RandH256();
  GetRefG1 get_g = pc::kGetRefG1;
  
  CommitmentPub com_pub;
  CommitmentSec com_sec;
  ProveInput prove_input(a, b, c, get_g, get_g(0));
  ComputeCom(com_pub, com_sec, prove_input);

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

  VerifyInput verify_input(n, com_pub, get_g, get_g(0));
  bool success = Verify(proof, seed, verify_input);
  std::cout << __FILE__ << " " << __FN__ << ": " << success << "\n\n\n\n\n\n";
  return success;
}
}  // namespace argument
