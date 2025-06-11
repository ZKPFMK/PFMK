#pragma once

#include "./details.h"

// recursive version of a2
// a: public vector<Fr>, size = n
// x: secret vector<Fr>, size = n
// y: public Fr,y = <x,a>
// A: commitment, A = g^a
// open: com(gx,x)
// prove: y=<x,a>
// proof size: (2log(n))G1 + 1Fr
namespace hyrax {
struct A5 {
  struct ProveInput {
    ProveInput(std::string const& tag, std::vector<Fr> const& x,
               std::vector<Fr> const& a, Fr const& y, GetRefG1 const& get_gx,
               G1 const& gy)
        : tag(tag), x(x), a(a), y(y), get_gx(get_gx), gy(gy) {
      assert(x.size() == a.size() && !a.empty());
      assert(y == InnerProduct(x, a));
    }
    int64_t n() const { return (int64_t)x.size(); }
    std::string to_string() const { return tag + ": " + std::to_string(n()); }

    std::string tag;
    std::vector<Fr> const& x;  // x.size = n // TODO: change to move
    std::vector<Fr> const& a;  // a.size = n
    Fr const y;                // y = <x, a>
    GetRefG1 const get_gx;
    G1 const gy;
  };

  struct CommitmentPub {
    CommitmentPub() {}
    CommitmentPub(G1 const& xi) : xi(xi) {}
    G1 xi;   // com(x,r_xi)
    bool operator==(CommitmentPub const& right) const {
      return xi == right.xi;
    }

    bool operator!=(CommitmentPub const& right) const {
      return !(*this == right);
    }
  };

  struct CommitmentExtPub {
    CommitmentExtPub() {}

    // recursive rounds
    std::vector<G1> gamma_neg_1;  // size=log(n)
    std::vector<G1> gamma_pos_1;
    bool operator==(CommitmentExtPub const& right) const {
      return gamma_neg_1 == right.gamma_neg_1 &&
             gamma_pos_1 == right.gamma_pos_1;
    }

    bool operator!=(CommitmentExtPub const& right) const {
      return !(*this == right);
    }
  };

  struct SubProof {
    Fr z;
    bool operator==(SubProof const& right) const {
      return z == right.z;
    }

    bool operator!=(SubProof const& right) const { return !(*this == right); }
  };

  struct Proof {
    CommitmentExtPub com_ext_pub;
    SubProof sub_proof;
    int64_t aligned_n() const { return 1LL << com_ext_pub.gamma_neg_1.size(); }
    bool operator==(Proof const& right) const {
      return com_ext_pub == right.com_ext_pub && sub_proof == right.sub_proof;
    }

    bool operator!=(Proof const& right) const { return !(*this == right); }
    bool CheckFormat() const { return true; }
  };

  struct VerifyInput {
    VerifyInput(std::string const& tag, std::vector<Fr> const& a, Fr const& y,
                CommitmentPub const& com_pub, GetRefG1 const& get_gx,
                G1 const& gy)
        : tag(tag), a(a), y(y), com_pub(com_pub), get_gx(get_gx), gy(gy) {
      assert(!a.empty());
    }
    std::string tag;
    std::vector<Fr> const& a;  // a.size = n
    CommitmentPub const& com_pub;
    GetRefG1 const get_gx;
    G1 const gy;
    Fr const y; 
    int64_t n() const { return (int64_t)a.size(); }
    std::string to_string() const { return tag + ": " + std::to_string(n()); }
  };

  static void UpdateSeed(h256_t& seed, std::vector<Fr> const& a,
                         CommitmentPub const& com_pub) {
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    HashUpdate(hash, a);
    HashUpdate(hash, com_pub.xi);
    hash.Final(seed.data());
  }

  static void UpdateSeed(h256_t& seed, G1 const& a, G1 const& b) {
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    HashUpdate(hash, a);
    HashUpdate(hash, b);
    hash.Final(seed.data());
  }

  template <typename T>
  static void Divide(std::vector<T> const& t, std::vector<T>& t1,
                     std::vector<T>& t2, T const& t0) { //将t分为左右两半存储到t1, t2, 如果 |t| != 2^k, 则补0
    auto n = t.size();
    auto half = misc::Pow2UB(n) >> 1;
    t1.resize(half); //x的前半部分
    t2.resize(n - half);
    std::copy(t.begin(), t.begin() + half, t1.begin());
    std::copy(t.begin() + half, t.end(), t2.begin());
  }

  static void ComputeCom(CommitmentPub& com_pub, ProveInput const& input) {
    Tick tick(__FN__);
    com_pub.xi = MultiExpBdlo12<G1>(input.get_gx, input.x, input.x.size());
  }

  // TODO: change to move
  static void Prove(Proof& proof, h256_t seed, ProveInput const& input,
                    CommitmentPub const& com_pub) {
    Tick tick(__FN__, input.to_string());
    
    assert(MultiExpBdlo12<G1>(input.get_gx, input.x, input.n()) == com_pub.xi);

    UpdateSeed(seed, input.a, com_pub);
    Fr rr = H256ToFr(seed); //随机数

    auto a = input.x;
    auto b = input.a;
    auto t = input.y; //y = <x, a>
    auto const& gt = input.gy;
    

    int64_t n = a.size();
    int64_t round = (int64_t)misc::Log2UB(n);
    auto ga = pc::CopyG(input.get_gx, n);
    
    proof.com_ext_pub.gamma_neg_1.resize(round);
    proof.com_ext_pub.gamma_pos_1.resize(round);
    CommitmentExtPub& com_ext_pub = proof.com_ext_pub;
    

    G1 h = gt * rr;
    G1 p = com_pub.xi + h * t;
    int64_t mid = 1 << round;

    // recursive round
    for (int64_t loop = 0; loop < round; ++loop) {
      mid = mid >> 1;
      //a1, a2分别为a的左右两部分; b1, b2分别为b的左右两部分; g1, g2分别为g的左右两部分
      std::vector<Fr> a1(a.begin(), a.begin() + mid), a2(a.begin()+mid, a.end());
      std::vector<Fr> b1(b.begin(), b.begin() + mid), b2(b.begin()+mid, b.end());
      std::vector<G1> g1(ga.begin(), ga.begin() + mid), g2(ga.begin()+mid, ga.end());
      a2.resize(mid, FrZero());
      b2.resize(mid ,FrZero());
      g2.resize(mid, G1Zero());

      auto& l = com_ext_pub.gamma_neg_1[loop];
      auto& r = com_ext_pub.gamma_pos_1[loop];
    
      Fr a1_b2, a2_b1;

      std::array<parallel::VoidTask, 2> tasks;
      tasks[0] = [&a1, &b2, &h, &g2, &l, &a1_b2]() {
        a1_b2 = InnerProduct(a1, b2);
        l = h * a1_b2;
        l += MultiExpBdlo12(g2, a1);
      };
      tasks[1] = [&a2, &b1, &h, &g1, &r, &a2_b1]() {
        a2_b1 = InnerProduct(a2, b1);
        r = h * a2_b1;
        r += MultiExpBdlo12(g1, a2);
      };
      parallel::Invoke(tasks);

      UpdateSeed(seed, l, r);
      Fr e = H256ToFr(seed);
      Fr ee = e * e;

      p = l + p * e + r * ee;  
      ga = g1 * e + g2;
      a = a1 + a2 * e;
      b = b1 * e + b2;
    }

    assert(ga.size() == 1);
    assert(a.size() == 1);
    assert(b.size() == 1);
    proof.sub_proof.z = a[0];
  }


  static void BuildS(std::vector<Fr>& s, std::vector<Fr> const& c) {
    Tick tick(__FN__);
    auto round = c.size();
    s[0] = 1;
    for (size_t i = 0; i < round; ++i) {
        size_t bound = 1 << i;
        for(size_t j=bound; j>=1; j--){
            int l = (j << 1) - 1, r = l-1;
            if(r >= s.size()) continue;
            else {
                if(l < s.size()){
                    s[l] = s[j-1];
                }
                s[r] = s[j-1] * c[i];
            }
        }
    }
  };

  static bool Verify(Proof const& proof, h256_t seed,
                     VerifyInput const& input) {
    Tick tick(__FN__, input.to_string());
    auto n = input.n();
    if ((int64_t)misc::Pow2UB(n) != proof.aligned_n()) {
      std::cout << "len not equal!\n";
      return false;
    }

    CommitmentPub const& com_pub = input.com_pub;
    CommitmentExtPub const& com_ext_pub = proof.com_ext_pub;
    int64_t round = (int64_t)misc::Log2UB(n);

    UpdateSeed(seed, input.a, com_pub);
    Fr rr = H256ToFr(seed);

    std::vector<Fr> vec_e(round);
    std::vector<Fr> vec_ee(round);

    // recursive round
    for (int64_t loop = 0; loop < round; ++loop) {
      auto const& l = com_ext_pub.gamma_neg_1[loop];
      auto const& r = com_ext_pub.gamma_pos_1[loop];
      UpdateSeed(seed, l, r);
      vec_e[loop] = H256ToFr(seed);
      vec_ee[loop] = vec_e[loop] * vec_e[loop];
    }
  
    std::vector<Fr> s(n);
    BuildS(s, vec_e);

    G1 ga = MultiExpBdlo12<G1>(input.get_gx, s, s.size());
    Fr b = InnerProduct(input.a, s);

    G1 h = input.gy * rr;
    G1 p = com_pub.xi + h * input.y;
    for (int64_t loop = 0; loop < round; ++loop) {
      auto const& l = com_ext_pub.gamma_neg_1[loop];
      auto const& r = com_ext_pub.gamma_pos_1[loop];
      p = l  + p * vec_e[loop] + r * vec_ee[loop];
    }
    
    auto const& sub_proof = proof.sub_proof;
    G1 left = p;
    G1 right = ga * sub_proof.z + h * (sub_proof.z * b);
    return left == right;
  }

  static bool Test(int64_t n);
};

// save to bin
template <typename Ar>
void serialize(Ar& ar, A5::CommitmentPub const& t) {
  ar& YAS_OBJECT_NVP("a3.cp", ("xi", t.xi));
}

// load from bin
template <typename Ar>
void serialize(Ar& ar, A5::CommitmentPub& t) {
  ar& YAS_OBJECT_NVP("a3.cp", ("xi", t.xi));
}

// save to bin
template <typename Ar>
void serialize(Ar& ar, A5::CommitmentExtPub const& t) {
  ar& YAS_OBJECT_NVP("a3.cep", ("gn1", t.gamma_neg_1), ("gp1", t.gamma_pos_1));
}

// load from bin
template <typename Ar>
void serialize(Ar& ar, A5::CommitmentExtPub& t) {
  ar& YAS_OBJECT_NVP("a3.cep", ("gn1", t.gamma_neg_1), ("gp1", t.gamma_pos_1));
}

// save to bin
template <typename Ar>
void serialize(Ar& ar, A5::SubProof const& t) {
  ar& YAS_OBJECT_NVP("a3.sp", ("z", t.z));
}

// load from bin
template <typename Ar>
void serialize(Ar& ar, A5::SubProof& t) {
  ar& YAS_OBJECT_NVP("a3.sp", ("z", t.z));
}

// save to bin
template <typename Ar>
void serialize(Ar& ar, A5::Proof const& t) {
  ar& YAS_OBJECT_NVP("a3.rp", ("c", t.com_ext_pub), ("p", t.sub_proof));
}

// load from bin
template <typename Ar>
void serialize(Ar& ar, A5::Proof& t) {
  ar& YAS_OBJECT_NVP("a3.rp", ("c", t.com_ext_pub), ("p", t.sub_proof));
}

bool A5::Test(int64_t n) {
  Tick tick(__FN__, std::to_string(n));

  std::vector<Fr> x(n);
  FrRand(x.data(), n);
  std::vector<Fr> a(n, 0);
  FrRand(a.data(), n);

  h256_t seed = misc::RandH256();

  G1 gy = pc::PcU();
  int64_t gx_offset = 30, gy_offset = 40;
  
  GetRefG1 get_gx = [gx_offset](int64_t i) -> G1 const& {
    return pc::PcG()[gx_offset + i];
  };
  GetRefG1 get_gy = [gy_offset](int64_t i) -> G1 const& {
    return pc::PcG()[gy_offset + i];
  };

  std::vector<G1> g(x.size());
  auto parallel_f = [&get_gx, &get_gy, &g](int64_t i){
      g[i] = get_gx(i) + get_gy(i);
  };
  parallel::For(x.size(), parallel_f);

  GetRefG1 get_g = [&g](int64_t i) -> G1 const& {
      return g[i];
  };

  auto y = InnerProduct(x, a);
  ProveInput prove_input("test", x, a, y, get_g, gy); //z = x * a

  CommitmentPub com_pub;
  ComputeCom(com_pub, prove_input);

  Proof proof;
  Prove(proof, seed, prove_input, com_pub);

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

  VerifyInput verify_input("test", a, y, com_pub, get_g, gy);
  bool success = Verify(proof, seed, verify_input);
  std::cout << __FILE__ << " " << __FN__ << ": " << success << "\n\n\n\n\n\n";
  return success;
}
}  // namespace hyrax
