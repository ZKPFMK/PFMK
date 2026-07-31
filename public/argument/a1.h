#pragma once

#include "./details.h"
// R_{sm}
// x, y, z: secret Fr
// open: com(gx,x), com(gy,y), com(gx,z), gx can equal gy
// prove: z = x*y
// proof size: 3 G1 and 5 Fr
// prove cost: 6 G1 + 6 F
// verify cost:9 G
namespace argument {
struct A1 {
  struct ProveInput {
    ProveInput(Fr const& a, Fr const& b, Fr const& c)
        : a(a), b(b), c(c) {
      assert(c == a * b);
    }
    Fr const a;
    Fr const b;
    Fr const c;
  };

  struct CommitmentPub {
    CommitmentPub() {}
    CommitmentPub(G1 const& com_a, G1 const& com_b, G1 const& com_c) 
        : com_a(com_a), com_b(com_b), com_c(com_c) {}
    G1 com_a; 
    G1 com_b; 
    G1 com_c; 
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
    std::array<G1, 3> com_d;   //da, db, dc
    std::array<Fr, 5> r_com_d; //za, zb, zeta_a, zeta_b, zeta_c

    size_t FrSize(){
      return 5;
    }

    size_t G1Size(){
      return 3;
    }

    bool operator==(Proof const& right) const {
      return com_d == right.com_d && r_com_d == right.r_com_d;
    }

    bool operator!=(Proof const& right) const { return !(*this == right); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("a1.p", ("d", com_d), ("r", r_com_d));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("a1.p", ("d", com_d), ("r", r_com_d));
    }
  };

  struct VerifyInput {
    VerifyInput(CommitmentPub const& com_pub)
        : com_pub(com_pub) {}
    CommitmentPub const& com_pub;
  };


  static void CheckInput(ProveInput const& input){
    assert(input.a * input.b == input.c);
  }

  static void CheckCom(ProveInput const& input, 
                       CommitmentPub const& com_pub,
                       CommitmentSec const& com_sec){
    assert(pc::ComputeCom(input.a, com_sec.r_com_a) == com_pub.com_a);
    assert(pc::ComputeCom(input.b, com_sec.r_com_b) == com_pub.com_b);
    assert(pc::ComputeCom(input.c, com_sec.r_com_c) == com_pub.com_c);
  }

  static void CheckWitness(ProveInput const& input, 
                           CommitmentPub const& com_pub,
                           CommitmentSec const& com_sec){
    Tick tick(__FN__);
    CheckInput(input);
    CheckCom(input, com_pub, com_sec);
  }

  static void ComputeCom(CommitmentPub& com_pub, CommitmentSec& com_sec,
                         ProveInput const& input) {
                      
    std::array<parallel::VoidTask, 3> tasks;
    tasks[0] = [&com_pub, &input, &com_sec]() {
      com_sec.r_com_a = FrRand();
      com_pub.com_a = pc::ComputeCom(input.a, com_sec.r_com_a);
    };
    tasks[1] = [&com_pub, &input, &com_sec]() {
      com_sec.r_com_b = FrRand();
      com_pub.com_b = pc::ComputeCom(input.b, com_sec.r_com_b);
    };
    tasks[2] = [&com_pub, &input, &com_sec]() {
      com_sec.r_com_c = FrRand();
      com_pub.com_c = pc::ComputeCom(input.c, com_sec.r_com_c);
    };
    parallel::Invoke(tasks);
  }


  static void Prove(Proof& proof, h256_t seed, 
                    ProveInput const& input,
                    CommitmentSec const& com_sec) {
    Tick tick(__FN__);
    if(DEBUG_CHECK){
      CheckInput(input);
    }
    auto &a = input.a, &b = input.b, &c = input.c;
    auto &r_com_a = com_sec.r_com_a, &r_com_b = com_sec.r_com_b, &r_com_c = com_sec.r_com_c;

    auto &com_da = proof.com_d[0], &com_db = proof.com_d[1], &com_dc = proof.com_d[2];
    auto &za = proof.r_com_d[0], &zeta_a = proof.r_com_d[1], &zb = proof.r_com_d[2], &zeta_b = proof.r_com_d[3], & zeta_c = proof.r_com_d[4];

    Fr da = FrRand(), db = FrRand(), dc = db * a;
    Fr r_com_da, r_com_db, r_com_dc;

    std::array<parallel::VoidTask, 3> tasks;
    tasks[0] = [&da, &r_com_da, &com_da]() {
        r_com_da = FrRand();
        com_da = pc::ComputeCom(da, r_com_da);
    };
    tasks[1] = [&db, &r_com_db, &com_db]() {
        r_com_db = FrRand();
        com_db = pc::ComputeCom(db, r_com_db);
    };
    tasks[2] = [&dc, &r_com_dc, &com_dc]() {
        r_com_dc = FrRand();
        com_dc = pc::ComputeCom(dc, r_com_dc);
    };
    parallel::Invoke(tasks);

    UpdateSeed(seed, proof.com_d);
    Fr e = H256ToFr(seed);

    za = da + e * a;
    zb = db + e * b;
    zeta_a = r_com_da + e * r_com_a;
    zeta_b = r_com_db + e * r_com_b;
    zeta_c = zb * r_com_a - r_com_dc - e * r_com_c;
  }

  static bool Verify(Proof const& proof, h256_t seed,
                     VerifyInput const& input) {
    Tick tick(__FN__);
    UpdateSeed(seed, proof.com_d);;
    Fr e = H256ToFr(seed);
    bool ret = true;

    auto & com_da = proof.com_d[0], &com_db = proof.com_d[1], &com_dc = proof.com_d[2];
    auto & com_a = input.com_pub.com_a, & com_b = input.com_pub.com_b, & com_c = input.com_pub.com_c;
    auto & za = proof.r_com_d[0], &zeta_a = proof.r_com_d[1], & zb = proof.r_com_d[2], &zeta_b = proof.r_com_d[3], & zeta_c = proof.r_com_d[4];

    ret &= pc::ComputeCom(za, zeta_a) == com_da + com_a * e;
    ret &= pc::ComputeCom(zb, zeta_b) == com_db + com_b * e;
    ret &= com_a * zb - pc::PcH() * zeta_c == com_dc + com_c * e;
    return ret;
  }

  static bool Test();
};

inline bool A1::Test() {
  Tick tick(__FN__);
  h256_t seed = misc::RandH256();


  Fr a = FrRand();
  Fr b = FrRand();
  Fr c = a * b;
  ProveInput prove_input(a, b, c);

  CommitmentPub com_pub;
  CommitmentSec com_sec;
  ComputeCom(com_pub, com_sec, prove_input);

  CheckWitness(prove_input, com_pub, com_sec);

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
#endif
  
  VerifyInput verify_input(com_pub);
  bool success = Verify(proof, seed, verify_input);
  std::cout << __FILE__ << " " << __FN__ << ": " << success << "\n\n\n\n\n\n";
  return success;
}
}  // namespace hyrax
