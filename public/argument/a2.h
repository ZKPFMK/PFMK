#pragma once

#include "./details.h"
// R_{ip}
// recursive version of a2
// b: public vector<Fr>, size = n
// a: secret vector<Fr>, size = n
// c: public Fr,c = <a,b>
// A: commitment, A = g^a
// proof size: (2log(n))G1 + 1Fr
namespace argument {
struct A2 {
  struct ProveInput {
    ProveInput(std::vector<Fr> const& a,
               std::vector<Fr> const& b, Fr const& c, 
               GetRefG1 const& get_ga)
        : a(a), b(b), c(c), get_ga(get_ga){
      }
    int64_t n() const { return (int64_t)a.size(); }
    std::string to_string() const { return std::to_string(n()); }
    std::vector<Fr> const& a;
    std::vector<Fr> const& b;
    Fr const& c;             
    GetRefG1 const& get_ga;
  };

  struct CommitmentPub {
    CommitmentPub() {}
    CommitmentPub(G1 const& com_a) : com_a(com_a) {}
    G1 com_a;
  };


  struct Proof {
    std::vector<G1> com_t0;
    std::vector<G1> com_t2;
    Fr a;

    size_t FrSize(){
      return 1;
    }

    size_t G1Size(){
      return com_t0.size() << 1;
    }

    bool operator==(Proof const& right) const {
      return com_t0 == right.com_t0 && com_t2 == right.com_t2 && a == right.a;
    }

    bool operator!=(Proof const& right) const { return !(*this == right); }

    // save to bin
    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("A2.p", ("0", com_t0), ("2", com_t2), ("a", a));
    }

    // load from bin
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("A2.p", ("0", com_t0), ("2", com_t2), ("a", a));
    }
  };

  struct VerifyInput {
    VerifyInput(std::vector<Fr> const& b, Fr const& c,
                CommitmentPub const& com_pub, GetRefG1 const& get_ga)
        : b(b), c(c), com_pub(com_pub), get_ga(get_ga){
    }
    std::vector<Fr> const& b;
    CommitmentPub const& com_pub;
    GetRefG1 const& get_ga;
    Fr const& c; 

    int64_t n() const { return (int64_t)b.size(); }
    std::string to_string() const { return std::to_string(n()); }
  };

  static void UpdateWitness(std::vector<Fr> & a, std::vector<Fr> & b, std::vector<G1> & g, Fr const& e){
    size_t n = a.size();
    size_t half = misc::Pow2UB(n) >> 1;
    if (half == n / 2 && n == half * 2) {
      auto parallel_f = [&a, &b, &g, &e, &half](int64_t i){
        size_t j = i + half;
        a[i] = a[i] + a[j] * e;
        b[i] = b[i] * e + b[j];
        g[i] = g[i] * e + g[j];
      };
      parallel::For(half, parallel_f);
    } else {
      auto parallel_f = [&a, &b, &g, &e, &half, &n](int64_t i){
        size_t j = i + half;
        if(j >= n) {
          b[i] = b[i] * e;
          g[i] = g[i] * e;
        }else{
          a[i] = a[i] + a[j] * e;
          b[i] = b[i] * e + b[j];
          g[i] = g[i] * e + g[j];
        }
      };
      parallel::For(half, parallel_f);
    }
    a.resize(half);
    b.resize(half);
    g.resize(half);
  }

  static void UpdateStatement(std::vector<Fr> & b, Fr const& e){
    size_t n = b.size();
    size_t half = misc::Pow2UB(n) >> 1;
    if (half == n / 2 && n == half * 2) {
      auto parallel_f = [&b, &e, &half](int64_t i){
        size_t j = i + half;
        b[i] = b[i] * e + b[j];
      };
      parallel::For(half, parallel_f);
    } else {
      auto parallel_f = [&b, &e, &half, &n](int64_t i){
        size_t j = i + half;
        if(j >= n) {
          b[i] = b[i] * e;
        }else{
          b[i] = b[i] * e + b[j];
        }
      };
      parallel::For(half, parallel_f);
    }
    b.resize(half);
  }

  static void CheckInput(ProveInput const& input){
    assert(input.a.size() == input.b.size() && !input.a.empty());
    assert(input.c == InnerProduct(input.a, input.b));
  }

  static void CheckWitness(ProveInput const& input, CommitmentPub const& com_pub){
    CheckInput(input);
    assert(MultiExpBdlo12<G1>(input.get_ga, input.a, input.n()) == com_pub.com_a);
  }

  static void Prove(Proof& proof, h256_t seed, ProveInput const& input) {
    Tick tick(__FN__, input.to_string());

    int64_t n = input.n();
    int64_t round = (int64_t)misc::Log2UB(n);

    auto a = input.a; //向量
    auto b = input.b; //向量
    auto c = input.c; //y = <x, a>
    
    auto h = pc::PcU();
    auto g = pc::CopyG(input.get_ga, n);

    Fr r = H256ToFr(seed); //随机数
    h = h * r;

    auto &com_t0 = proof.com_t0;
    auto &com_t2 = proof.com_t2;
    com_t0.resize(round);
    com_t2.resize(round);

    for (int64_t loop = 0, mid = 1 << (round-1); loop < round; ++loop, mid >>= 1) {
      std::vector<std::function<void()>> tasks = {
        [&a, &b, &g, &h, &com_t0, &loop, &mid](){
          Fr t0 = InnerProduct(a.data(), b.data() + mid, b.size() - mid);
          com_t0[loop] = MultiExpBdlo12(g.data() + mid, a.data(), a.size() - mid) + h * t0;
        },
        [&a, &b, &g, &h, &com_t2, &loop, &mid](){
          Fr t2 = InnerProduct(a.data() + mid, b.data(), b.size() - mid);
          com_t2[loop] = MultiExpBdlo12(g.data(), a.data() + mid, a.size() - mid) + h * t2;
        }
      };
      parallel::Invoke(tasks);

      UpdateSeed(seed, com_t0[loop], com_t2[loop]);
      UpdateWitness(a, b, g, H256ToFr(seed));
    }

    assert(a.size() == 1);
    assert(b.size() == 1);
    assert(g.size() == 1);
    proof.a = a[0];
  }

  static bool Verify(Proof const& proof, h256_t seed,
                     VerifyInput const& input) {
    Tick tick(__FN__, input.to_string());

    size_t n = input.n();
    size_t round = (int64_t)misc::Log2UB(n);
    
    auto b = input.b;
    auto c = input.c;
    auto h = pc::PcU();
    auto com_a = input.com_pub.com_a;

    auto const& a = proof.a;
    auto const& com_t0 = proof.com_t0;
    auto const& com_t2 = proof.com_t2;

    Fr r = H256ToFr(seed);
    
    h = h * r;
    com_a = com_a + h * c;

    std::vector<Fr> e(round);
    for (int64_t loop = 0; loop < round; ++loop) {
      UpdateSeed(seed, com_t0[loop], com_t2[loop]);
      e[loop] = H256ToFr(seed);

      Fr e_sq = e[loop] * e[loop];
      com_a = com_t0[loop] + com_a * e[loop] + com_t2[loop] * e_sq;
      UpdateStatement(b, e[loop]);
    }

    std::vector<Fr> e_hat(n, FrOne());
    misc::BuildE(e_hat, e, true);
    G1 g_hat = MultiExpBdlo12<G1>(input.get_ga, e_hat, n);
    G1 expected = g_hat * a + h * (a * b[0]);
    return com_a == expected;
  }

  static bool Test(int64_t n);
};

bool A2::Test(int64_t n) {
  Tick tick(__FN__, std::to_string(n));

  std::vector<Fr> a(n);
  std::vector<Fr> b(n);
  FrRand(a);
  FrRand(b);

  h256_t seed = misc::RandH256();

  Fr c = InnerProduct(a, b);
  ProveInput prove_input(a, b, c, pc::kGetRefG1); //z = x * a

  CommitmentPub com_pub;
  com_pub.com_a = pc::ComputeCom(a, FrZero());

  if(DEBUG_CHECK){
    CheckWitness(prove_input, com_pub);
  }

  Proof proof;
  Prove(proof, seed, prove_input);

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
  VerifyInput verify_input(b, c, com_pub, pc::kGetRefG1);
  bool success = Verify(proof, seed, verify_input);
  std::cout << __FILE__ << " " << __FN__ << ": " << success << "\n\n\n\n\n\n";
  return success;
}
}  // namespace argument
