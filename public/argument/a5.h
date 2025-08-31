#pragma once

#include "./details.h"
#include "./a4.h"

// a_i: public vector<Fr>, i\in[0,m-1], a_i.size() maybe neq a_j.size()
// b_i: secret vector<Fr>, i\in[0,m-1], x_i.size() maybe neq x_j.size()
// c_i: secret Fr
// open: com(gx,a), com(gz,c)
// prove: ci = <a_i,b_i>
// proof size: 2logm+2logn+2 G1 and 4 F


//需要处理长度不一致的情况
namespace argument {
struct A5 {
  struct CommitmentPub {
    std::vector<G1> com_a, com_c;
    CommitmentPub(){}
    CommitmentPub(std::vector<G1> const& com_a, std::vector<G1> const& com_c)
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
    std::vector<Fr> r_com_a;
    std::vector<Fr> r_com_c;  // r.size = m
    CommitmentSec(){

    }
    CommitmentSec(std::vector<Fr> const& r_com_a, std::vector<Fr> const& r_com_c)
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
    CommitmentPub const& com_pub;
    std::vector<std::vector<Fr>> const& b;
    GetRefG1 const& get_ga;
    G1 const& gc;

    int64_t m() const { return b.size(); }
    int64_t n() const { return _n; }
    std::string to_string() const {
      return std::to_string(m()) + " " + std::to_string(n());
    }
  };

  struct ProveInput {
    std::vector<std::vector<Fr>> const& a;
    std::vector<std::vector<Fr>> const& b;
    std::vector<Fr> const& c;
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
               std::vector<Fr> const& c,
               GetRefG1 const& get_ga, G1 const& gc)
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
    A4::Proof sub_proof; 

    size_t FrSize(){
      return sub_proof.FrSize();
    }

    size_t G1Size(){
      return sub_proof.G1Size();
    }   

    bool operator==(Proof const& right) const {
      return sub_proof == right.sub_proof;
    }
    bool operator!=(Proof const& right) const { return !(*this == right); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("A4.p", ("p", sub_proof));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("A4.p", ("p", sub_proof));
    }
  };

  static void ComputeCom(ProveInput const& input,
                         CommitmentPub & com_pub,
                         CommitmentSec & com_sec) {
    Tick tick(__FN__);
    auto m = input.m();

    com_pub.com_a.resize(m);
    com_pub.com_c.resize(m);

    com_sec.r_com_a.resize(m);
    com_sec.r_com_c.resize(m);
  
    FrRand(com_sec.r_com_a);
    FrRand(com_sec.r_com_c);

    auto parallel_f = [&input, &com_pub, &com_sec](int64_t i){
      com_pub.com_a[i] = pc::ComputeCom(input.get_ga, input.a[i], com_sec.r_com_a[i]);
      com_pub.com_c[i] = pc::ComputeCom(input.gc, input.c[i], com_sec.r_com_c[i]);

    };
    parallel::For(m, parallel_f);
  }

  static void CheckInput(ProveInput const& input){
    assert(input.a.size() == input.b.size() && !input.b.empty());
    for(size_t i=0; i<input.m(); i++){
      assert(input.a[i].size() == input.b[i].size());
      assert(InnerProduct(input.a[i], input.b[i]) == input.c[i]);
    }
  }

  static void CheckWitness(ProveInput const& input, 
                           CommitmentPub const& com_pub,
                           CommitmentSec const& com_sec){
    CheckInput(input);
    for(size_t i=0; i<input.m(); i++){
      assert(pc::ComputeCom(input.get_ga, input.a[i], com_sec.r_com_a[i]) == com_pub.com_a[i]);
      assert(pc::ComputeCom(input.gc, input.c[i], com_sec.r_com_c[i]) == com_pub.com_c[i]);
    }
  }
  

  static void Prove(Proof& proof, h256_t seed,
                    ProveInput const& input,
                    CommitmentSec const& com_sec) {
    Tick tick(__FN__, input.to_string());

    if(DEBUG_CHECK){
      CheckInput(input);
    }

    int64_t n = input.n();
    int64_t m = input.m();
    int64_t lm = (int64_t)misc::Log2UB(m);

    auto const& gc = input.gc;

    std::vector<Fr> r(m);
    ComputeFst(seed, "argument::A5::r", r);

    Fr c = InnerProduct(input.c, r);
    Fr r_com_c = InnerProduct(com_sec.r_com_c, r);

    std::vector<std::vector<Fr>> b(m);
    auto parallel_f = [&b, &r, &input](size_t i){
      b[i] = input.b[i] * r[i];
    };
    parallel::For(m, parallel_f);

    A4::CommitmentSec sec(com_sec.r_com_a, r_com_c);
    A4::ProveInput in(input.a, b, c, input.get_ga, input.gc);
    A4::Prove(proof.sub_proof, seed, in, sec);
  }

  static bool Verify(Proof const& proof, h256_t seed, VerifyInput const& input) {
    Tick tick(__FN__, input.to_string());
    int64_t n = input.n();
    int64_t m = input.m();
    int64_t lm = (int64_t)misc::Log2UB(m);

    auto const& gc = input.gc;

    std::vector<Fr> r(m);
    ComputeFst(seed, "argument::A5::r", r);

    G1 com_c = MultiExpBdlo12(input.com_pub.com_c, r);

    std::vector<std::vector<Fr>> b(m);
    auto parallel_f = [&b, &r, &input](size_t i){
      b[i] = input.b[i] * r[i];
    };
    parallel::For(m, parallel_f);

    A4::CommitmentPub pub(input.com_pub.com_a, com_c);
    A4::VerifyInput in(b, pub, input.get_ga, input.gc);
    return A4::Verify(proof.sub_proof, seed, in);
  }

 public:
  static bool Test(int64_t m, int64_t n) {
    Tick tick(__FN__, std::to_string(m) + " " + std::to_string(n));

    std::vector<std::vector<Fr>> a(m, std::vector<Fr>(n, 0));
    std::vector<std::vector<Fr>> b(m, std::vector<Fr>(n, 0));
    std::vector<Fr> c(m);

    for (int i=0; i<m; i++) {
      FrRand(a[i]);
      FrRand(b[i]);
      size_t len =  std::rand() % (n + 1);
      a[i].resize(len);
      b[i].resize(len);
      c[i] = InnerProduct(a[i], b[i]);
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
