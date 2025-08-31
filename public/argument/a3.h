#pragma once

#include "./details.h"
#include "./a2.h"

// b: public vector<Fr>, size = n
// a: secret vector<Fr>, size = n
// c: secret Fr,c = <a,b>
// open: com(ga,a), com(gc,c)
// prove: c=<a,b>
// proof size: 2logn+2 G1 and 4 Fr
// prove cost: mulexp(n)
// verify cost: mulexp(n)
namespace argument {
struct A3 {
  struct ProveInput {
    ProveInput(std::vector<Fr> const& a, std::vector<Fr> const& b, 
               Fr const& c, GetRefG1 const& get_ga, G1 const& gc)
        : a(a), b(b), c(c), get_ga(get_ga), gc(gc) {
    }
    int64_t n() const { return (int64_t)a.size(); }
    std::string to_string() const { return std::to_string(n()); }

    std::vector<Fr> const& a;
    std::vector<Fr> const& b; 
    Fr const& c;              
    GetRefG1 const& get_ga;
    G1 const& gc;
  };

  struct CommitmentPub {
    CommitmentPub() {}
    CommitmentPub(G1 const& com_a, G1 const& com_c) : com_a(com_a), com_c(com_c) {}
    G1 com_a;     
    G1 com_c;  
    bool operator==(CommitmentPub const& right) const {
      return com_a == right.com_a && com_c == right.com_c;
    }

    bool operator!=(CommitmentPub const& right) const {
      return !(*this == right);
    }
  };

  struct CommitmentSec {
    CommitmentSec() {}
    CommitmentSec(Fr const& r_com_a, Fr const& r_com_c) : r_com_a(r_com_a), r_com_c(r_com_c) {}
    Fr r_com_a;
    Fr r_com_c;
  };

  struct Proof {
    std::array<G1, 2> com; 
    std::array<Fr, 3> r_com;
    A2::Proof sub_proof;

    size_t FrSize(){
      return 3 + sub_proof.FrSize();
    }

    size_t G1Size(){
      return 2 + sub_proof.G1Size();
    }

    bool operator==(Proof const& right) const {
      return com == right.com && r_com == right.r_com && sub_proof == right.sub_proof;
    }
    bool operator!=(Proof const& right) const { return !(*this == right); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("A3.p", ("c", com), ("r", r_com), ("p", sub_proof));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("A3.p", ("c", com), ("r", r_com), ("p", sub_proof));
    }
  };

  struct VerifyInput {
    VerifyInput(std::vector<Fr> const& b,
                CommitmentPub const& com_pub,
                GetRefG1 const& get_ga,
                G1 const& gc)
        : b(b), com_pub(com_pub), get_ga(get_ga), gc(gc) {}
    std::vector<Fr> const& b;  // a.size = n
    CommitmentPub const& com_pub;
    GetRefG1 const get_ga;
    G1 const gc;
    int64_t n() const { return (int64_t)b.size(); }
    std::string to_string() const { return std::to_string(n()); }
  };


  static void ComputeCom(CommitmentPub& com_pub, CommitmentSec& com_sec,
                         ProveInput const& input) {
    Tick tick(__FN__, input.to_string());
    com_sec.r_com_a = FrRand();
    com_sec.r_com_c = FrRand();
    com_pub.com_a = pc::ComputeCom(input.get_ga, input.a, com_sec.r_com_a);
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
    assert(pc::ComputeCom(input.get_ga, input.a, com_sec.r_com_a) == com_pub.com_a);
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

    auto const& a = input.a; //需要对b更改
    auto const& b = input.b;
    auto const& c = input.c;

    auto const& r_com_a = com_sec.r_com_a;
    auto const& r_com_c = com_sec.r_com_c;

    auto & z = proof.r_com[0], & zeta = proof.r_com[1], & gamma = proof.r_com[2];
    auto & com_d = proof.com[0];
    auto & com_t = proof.com[1];

    std::vector<Fr> d(n);
    Fr r_com_d = FrRand();
    Fr r_com_t = FrRand();

    FrRand(d);
    Fr t = InnerProduct(d, b);
    com_d = pc::ComputeCom(input.get_ga, d, r_com_d);
    com_t = pc::ComputeCom(input.gc, t, r_com_t);

    UpdateSeed(seed, proof.com);
    Fr e = H256ToFr(seed);

    z = t + c * e;
    zeta = r_com_t + r_com_c * e;
    gamma = r_com_d + r_com_a * e;

    std::vector<Fr> a_hat = d + a * e;

    A2::ProveInput in(a_hat, b, z, input.get_ga);
    A2::Prove(proof.sub_proof, seed, in);
  }

  static bool Verify(Proof const& proof, h256_t seed, VerifyInput const& input) {
    Tick tick(__FN__, input.to_string());
    auto n = input.n();

    auto const& b = input.b;
    auto const& z = proof.r_com[0], & zeta = proof.r_com[1], gamma = proof.r_com[2];
    auto const& com_a = input.com_pub.com_a;
    auto const& com_c = input.com_pub.com_c;
    auto const& com_d = proof.com[0];
    auto const& com_t = proof.com[1];

    UpdateSeed(seed, proof.com);
    Fr e = H256ToFr(seed);

    bool ret = (com_t + com_c * e == pc::ComputeCom(input.gc, z, zeta));

    A2::CommitmentPub pub;
    auto & com_a_hat = pub.com_a;
    com_a_hat = com_d + com_a * e - pc::PcH() * gamma;

    A2::VerifyInput in(b, z, com_a_hat, input.get_ga);
    ret = ret && A2::Verify(proof.sub_proof, seed, in);

    return ret;
  }

  static bool Test(int64_t n);
};

bool A3::Test(int64_t n) { // z = x * a
  Tick tick(__FN__, std::to_string(n));

  std::vector<Fr> a(n);
  std::vector<Fr> b(n);

  FrRand(a);
  FrRand(b);
  Fr c = InnerProduct(a, b);

  h256_t seed = misc::RandH256();
  GetRefG1 get_ga = pc::kGetRefG1;
  
  ProveInput prove_input(a, b, c, get_ga, get_ga(0));

  prove_input.to_string();

  CommitmentPub com_pub;
  CommitmentSec com_sec;

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

  VerifyInput verify_input(b, com_pub, get_ga, get_ga(0));
  bool success = Verify(proof, seed, verify_input);
  std::cout << __FILE__ << " " << __FN__ << ": " << success << "\n\n\n\n\n\n";
  return success;
}
}  // namespace argument
