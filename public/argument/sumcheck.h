#pragma once

#include "./details.h"

namespace argument {
struct SumCheck{
  struct ProveInput {
    std::vector<Fr> const& a;
    std::vector<Fr> const& b;
    Fr const& c;
    G1 const& gc;

    ProveInput(std::vector<Fr> const& a,
               std::vector<Fr> const& b, 
               Fr const& c, G1 const& gc)
        : a(a),
          b(b),
          c(c),
          gc(gc){
    }

    int64_t n() const { return (int64_t)a.size(); }

    std::string to_string() const {
      return std::to_string(n());
    }
  };

  struct CommitmentSec {
    Fr r_com_c;

    CommitmentSec(){
    }

    CommitmentSec(Fr const& r_com_c)
        : r_com_c(r_com_c){}
  };

  struct ProveOutput {
    std::vector<Fr> e;
    Fr a, b, c, r_com_c;
  };


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

  static void UpdateWitness(std::vector<Fr> & a, std::vector<Fr> & b, 
                            Fr &c, Fr &r_com_c, Fr const& t0, Fr const& r_com_t0,
                            Fr const& t2, Fr const& r_com_t2, Fr const& e, size_t half){
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

    Fr ee = e * e;
    c = t0 + c * e + t2 * ee;
    r_com_c = r_com_t0 + r_com_c * e + r_com_t2 * ee;
  }

  static void CheckWitness(ProveInput const& input){
    assert(input.a.size() == input.b.size() && !input.b.empty());
    assert(input.c == InnerProduct(input.a, input.b));
  }

  static void Prove(size_t round, size_t n,
                    std::vector<G1> & com_t0,
                    std::vector<G1> & com_t2, std::vector<Fr> & e, h256_t &seed,
                    std::vector<Fr> & a, std::vector<Fr> & b, Fr & c, Fr & r_com_c, G1 const& gc){
    Tick tick(__FN__, std::to_string(n));
    assert(InnerProduct(a, b) == c);

    e.reserve(e.size() + round); //随机数
    com_t0.reserve(com_t0.size() + round);
    com_t2.reserve(com_t2.size() + round);
    
    for (int64_t loop = 0, half=n/2; loop < round; ++loop, half>>=1) {
      Fr t0, r_com_t0, t2, r_com_t2;
      std::array<parallel::VoidTask, 2> tasks;
      tasks[0] = [&a, &b, &com_t0, &gc, &t0, &r_com_t0, &half]() {
        r_com_t0 = FrRand();
        t0 = InnerProduct(a.data(), b.data() + half, b.size() - half);
        com_t0.push_back(pc::ComputeCom(gc, t0, r_com_t0));
      };
      tasks[1] = [&a, &b, &com_t2, &gc, &t2, &r_com_t2, &half]() {
        r_com_t2 = FrRand();
        t2 = InnerProduct(a.data() + half, b.data(), b.size() - half);
        com_t2.push_back(pc::ComputeCom(gc, t2, r_com_t2));
      };
      parallel::Invoke(tasks);

      UpdateSeed(seed, com_t0.back(), com_t2.back());
      e.push_back(H256ToFr(seed));

      UpdateWitness(a, b, c, r_com_c, t0, r_com_t0, t2, r_com_t2, e.back(), half);
    }
  } 

  static void Prove(ProveOutput & output,
                    std::vector<G1> & com_t0,
                    std::vector<G1> & com_t2, h256_t &seed,
                    ProveInput const& input, CommitmentSec const& com_sec){
    Tick tick(__FN__, input.to_string());
    size_t n = input.n();
    int64_t round = (int64_t)misc::Log2UB(n);

    auto a = input.a; //向量
    auto b = input.b; //向量
    auto c = input.c; //y = <x, a>
    auto r_com_c = com_sec.r_com_c;
    auto const& gc = input.gc;
    auto & e = output.e;

    e.resize(round);
    com_t0.resize(round);
    com_t2.resize(round);

    for (int64_t loop = 0, mid = 1 << (round-1); loop < round; ++loop, mid >>= 1) {
      Fr t0, r_com_t0, t2, r_com_t2;
      std::array<parallel::VoidTask, 2> tasks;
      tasks[0] = [&a, &b, &com_t0, &gc, &t0, &r_com_t0, &mid, &loop]() {
        r_com_t0 = FrRand();
        t0 = InnerProduct(a.data(), b.data() + mid, b.size() - mid);
        com_t0[loop] = pc::ComputeCom(gc, t0, r_com_t0);
      };
      tasks[1] = [&a, &b, &com_t2, &gc, &t2, &r_com_t2, &mid, &loop]() {
        r_com_t2 = FrRand();
        t2 = InnerProduct(a.data() + mid, b.data(), b.size() - mid);
        com_t2[loop] = pc::ComputeCom(gc, t2, r_com_t2);
      };
      parallel::Invoke(tasks);

      UpdateSeed(seed, com_t0[loop], com_t2[loop]);
      e[loop] = H256ToFr(seed);

      UpdateWitness(a, b, e[loop], mid);

      Fr ee = e[loop] * e[loop];
      c = t0 + c * e[loop] + t2 * ee;
      r_com_c = r_com_t0 + r_com_c * e[loop] + r_com_t2 * ee;
    }

    assert(a.size() == 1);
    assert(b.size() == 1);

    output.a = a[0];
    output.b = b[0];
    output.c = c;
    output.r_com_c = r_com_c;
  }

  static void Verify(std::vector<G1> const& com_t0,
                     std::vector<G1> const& com_t2, h256_t &seed,
                     G1 & com_c, std::vector<Fr> & e){
    Tick tick(__FN__, std::to_string(com_t0.size()));

    int64_t round = com_t0.size();

    e.resize(round);

    for (int64_t loop = 0; loop < round; ++loop) {
      UpdateSeed(seed, com_t0[loop], com_t2[loop]);
      e[loop] = H256ToFr(seed);
      Fr ee = e[loop] * e[loop];
      com_c = com_t0[loop] + com_c * e[loop] + com_t2[loop] * ee;
    }
  }
};
}