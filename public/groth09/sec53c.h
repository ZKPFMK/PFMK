// #pragma once

// #include <map>
// #include <memory>

// #include "groth09/details.h"
// #include "groth09/sec51b.h"
// #include "groth09/sec51c.h"
// #include "utils/fst.h"

// // t: public vector<Fr>, size = n
// // x, y: secret matric<Fr>, size = m*n
// // z: secret Fr
// // open: com(gx,x1), com(gy,y1), com(gx,x2), com(gy,y2) ... com(gz,z)
// // prove: z = <x1,y1 o t> + <x2,y2 o t>...
// // proof size: 
// // prove cost: 
// // verify cost: mulexp(n)
// // base on Sec51

// namespace groth09 {

// struct Sec53c {
//   struct CommitmentPub {
//     std::vector<G1> a;  // a.size = m
//     std::vector<G1> b;  // b.size = m
//     G1 c;
//     int64_t m() const { return a.size(); }
//   };

//   struct CommitmentSec {
//     std::vector<Fr> r;  // r.size = m
//     std::vector<Fr> s;  // s.size = m
//     Fr t;
//   };

//   struct VerifyInput {
//     VerifyInput(std::vector<size_t> const& mn, std::vector<Fr> const& t,
//                 CommitmentPub&& com_pub, GetRefG1 const& get_gx,
//                 GetRefG1 const& get_gy, G1 const& gz)
//         : mn(mn),
//           t(t),
//           com_pub(std::move(com_pub)),
//           get_gx(get_gx),
//           get_gy(get_gy),
//           gz(gz) {
//       Check();
//     }
//     void SortAndAlign() { PermuteAndAlign(GetSortOrder(mn), com_pub); }
//     int64_t m() const { return com_pub.m(); }
//     int64_t n() const { return t.size(); }
//     std::string to_string() const {
//       return std::to_string(m()) + "*" + std::to_string(n());
//     }

//     std::vector<size_t> const& mn;
//     std::vector<Fr> const& t;  // size = n
//     CommitmentPub com_pub;
//     GetRefG1 const& get_gx;
//     GetRefG1 const& get_gy;
//     G1 const& gz;

//    private:
//     void Check() {
//       CHECK(com_pub.a.size() == mn.size() && com_pub.b.size() == mn.size(), "");

//       auto max_n = *std::max_element(mn.begin(), mn.end());
//       CHECK(t.size() == max_n, "");
//     }
//   };

//   struct ProveInput {
//     std::vector<std::vector<Fr>> x;
//     std::vector<std::vector<Fr>> y;
//     std::vector<Fr> const& t;
//     Fr z;
//     GetRefG1 const& get_g;

//     int64_t m() const { return x.size(); }
//     int64_t n() const { return t.size(); }
//     std::string to_string() const {
//       return std::to_string(m()) + "*" + std::to_string(n());
//     }

//     ProveInput(std::vector<std::vector<Fr>> const& x,
//                std::vector<std::vector<Fr>> const& y,
//                std::vector<Fr> const& t, Fr const& z,
//                GetRefG1 const& get_g)
//         : x(x),
//           y(y),
//           t(t),
//           z(z),
//           get_g(get_g)
//         {
//       Check();
//     }

//     void Update(Fr const& sigma_xy1, Fr const& sigma_xy2, Fr const& e,
//                 Fr const& ee) {
//       Tick tick(__FN__, to_string());
//       auto m2 = misc::Pow2UB(m()) >> 1;

//       {
//         std::vector<std::vector<Fr>> x2(m2);
//         std::vector<std::vector<Fr>> y2(m2);

//         auto pf1 = [this, &x2, &y2, &e](int64_t i) {
//           int64_t j = i + x2.size();
//           if(j >= m()){
//             x2[i] = x[i] * e;
//             y2[i] = y[i];
//           }else{
//             x2[i] = x[i] * e + x[j];
//             y2[i] = y[i] + y[j] * e;
//           }
//         };
//         parallel::For(m2, pf1);
//         x2.swap(x);
//         y2.swap(y);
//         z = sigma_xy1 + z * e + sigma_xy2 * ee;
//       }
//     }

//    private:
//     void Check() {
//       CHECK(!x.empty(), "");

//       CHECK(x.size() == y.size(), "");

//       size_t max_n = 0;
//       for (int64_t i = 0; i < m(); ++i) {
//         CHECK(x[i].size() == x[0].size() && y[i].size() == x[0].size(), "");
//       }

//       if(DEBUG_CHECK){
//         Fr check_z = FrZero();
//         for (int64_t i = 0; i < m(); ++i) {
//           check_z += InnerProduct(x[i], HadamardProduct(y[i], t));
//         }
//         CHECK(z == check_z, "");
//       }
//     }
//   };

//   struct CommitmentExtPub {
//     // 5.3 Recursive
//     std::vector<G1> cl;  // size = log(m)
//     std::vector<G1> cu;  // size = log(m)
//     bool CheckFormat(int64_t check_m) const {
//       if (cl.size() != cu.size()) return false;
//       return m() == check_m;
//     }
//     int64_t m() const { return 1LL << cl.size(); }
//     bool operator==(CommitmentExtPub const& right) const {
//       return cl == right.cl && cu == right.cu;
//     }

//     bool operator!=(CommitmentExtPub const& right) const {
//       return !(*this == right);
//     }
//     template <typename Ar>
//     void serialize(Ar& ar) const {
//       ar& YAS_OBJECT_NVP("53b.cep", ("cl", cl), ("cu", cu));
//     }
//     template <typename Ar>
//     void serialize(Ar& ar) {
//       ar& YAS_OBJECT_NVP("53b.cep", ("cl", cl), ("cu", cu));
//     }
//   };

//   struct Proof {
//     CommitmentExtPub com_ext_pub;    // 2*log(m) G1
//     typename Sec51::Proof proof_51;  // 4 G1, 2n+3 Fr

//     bool CheckFormat(int64_t check_m) const {
//       return com_ext_pub.CheckFormat(check_m) && proof_51.CheckFormat();
//     }
//     bool operator==(Proof const& right) const {
//       return com_ext_pub == right.com_ext_pub && proof_51 == right.proof_51;
//     }

//     bool operator!=(Proof const& right) const { return !(*this == right); }

//     template <typename Ar>
//     void serialize(Ar& ar) const {
//       ar& YAS_OBJECT_NVP("53.pf", ("c", com_ext_pub), ("r", proof_51));
//     }
//     template <typename Ar>
//     void serialize(Ar& ar) {
//       ar& YAS_OBJECT_NVP("53.pf", ("c", com_ext_pub), ("r", proof_51));
//     }
//   };

//   static void ComputeCom(ProveInput const& input, CommitmentPub* com_pub,
//                          CommitmentSec const& com_sec) {
//     Tick tick(__FN__, input.to_string());
//     auto const m = input.m();
//     // auto const n = input.n();

//     com_pub->a.resize(m);
//     com_pub->b.resize(m);

//     auto parallel_f = [&input, &com_pub, &com_sec](int64_t i) {
//       std::array<parallel::VoidTask, 2> tasks{nullptr};
//       tasks[0] = [&com_pub, &com_sec, &input, i]() {
//         com_pub->a[i] = pc::ComputeCom(input.get_g, input.x[i], com_sec.r[i]);
//       };
//       tasks[1] = [&com_pub, &com_sec, &input, i]() {
//         com_pub->b[i] = pc::ComputeCom(input.get_g, input.y[i], com_sec.s[i]);
//       };
//       parallel::Invoke(tasks);
//     };
//     parallel::For(m, parallel_f);

//     com_pub->c = pc::ComputeCom(input.get_g(0), input.z, com_sec.t);
//   }

//   static void ComputeCom(ProveInput const& input, CommitmentPub* com_pub,
//                          CommitmentSec* com_sec) {
//     Tick tick(__FN__, input.to_string());

//     auto const m = input.m();
//     com_sec->r.resize(m);
//     FrRand(com_sec->r.data(), m);

//     com_sec->s.resize(m);
//     FrRand(com_sec->s.data(), m);

//     com_sec->t = FrRand();

//     ComputeCom(input, com_pub, *com_sec);
//   }

//   static void ProveFinal(Proof& proof, h256_t const& seed,
//                          ProveInput const& input, CommitmentPub const& com_pub,
//                          CommitmentSec const& com_sec) {
//     Tick tick(__FN__, input.to_string());
//     // DCHECK(input.m() == 1, "");

//     // typename Sec51::ProveInput input_51(input.x[0], input.y[0], input.t,
//     //                                     input.yt[0], input.z, input.get_gx,
//     //                                     input.get_gy, input.gz);

//     // typename Sec51::CommitmentPub com_pub_51(com_pub.a[0], com_pub.b[0],
//     //                                          com_pub.c);
//     // typename Sec51::CommitmentSec com_sec_51(com_sec.r[0], com_sec.s[0],
//     //                                          com_sec.t);
//     // Sec51::Prove(proof.proof_51, seed, input_51, com_pub_51, com_sec_51);
//   }

//   static void ComputeSigmaXY(ProveInput const& input, Fr* sigma_xy1,
//                              Fr* sigma_xy2) {
//     Tick tick(__FN__, input.to_string());
//     auto m = input.m();
//     auto n = input.n();
//     auto m2 = misc::Pow2UB(input.m()) >> 1;
//     std::vector<std::vector<Fr>> xy1(m2, std::vector<Fr>(n, FrZero()));
//     std::vector<std::vector<Fr>> xy2(m2, std::vector<Fr>(n, FrZero()));
//     auto parallel_f = [&input, &xy1, &xy2](int64_t i) {
//       int64_t j = i + xy1.size();
//       if(j < input.m()){
//         xy1[i] = HadamardProduct(input.x[j], input.y[i]);
//         xy2[i] = HadamardProduct(input.x[i], input.y[j]);
//       }
//     };
//     parallel::For(m2, parallel_f);

//     std::vector<Fr> xyt1(m, FrZero());
//     std::vector<Fr> xyt2(m, FrZero());
//     MatrixVectorMul(xy1, input.t, xyt1);
//     MatrixVectorMul(xy2, input.t, xyt2);

//     *sigma_xy1 = parallel::Accumulate(xyt1.begin(), xyt1.end(), FrZero());
//     *sigma_xy2 = parallel::Accumulate(xyt2.begin(), xyt2.end(), FrZero());
//   }

//   static void UpdateCom(CommitmentPub& com_pub, CommitmentSec& com_sec,
//                         Fr const& tl, Fr const& tu, G1 const& cl, G1 const& cu,
//                         Fr const& e, Fr const& ee) {
//     Tick tick(__FN__);
//     CommitmentPub com_pub2;
//     CommitmentSec com_sec2;
//     auto m2 = misc::Pow2UB(com_pub.a.size()) >> 1;
//     com_pub2.a.resize(m2);
//     com_pub2.b.resize(m2);
//     com_sec2.r.resize(m2);
//     com_sec2.s.resize(m2);

//     auto parallel_f = [&com_pub, &com_sec, &com_pub2, &com_sec2,
//                        &e](int64_t i) {
//       auto& a2 = com_pub2.a;
//       auto const& a = com_pub.a;

//       auto& r2 = com_sec2.r;
//       auto const& r = com_sec.r;

//       auto& b2 = com_pub2.b;
//       auto const& b = com_pub.b;

//       auto& s2 = com_sec2.s;
//       auto const& s = com_sec.s;
      
//       int64_t j = i + a2.size();

//       if(j > a2.size()){
//         a2[i] = a2[i] * e;
//         r2[i] = r[i] * e;

//         b2[i] = b[i];
//         s2[i] = s[i];
//       }else{
//         a2[i] = a[i] * e + a[j];
//         r2[i] = r[i] * e + r[j];

//         b2[i] = b[i] + b[j] * e;
//         s2[i] = s[i] + s[j] * e;
//       }
//     };
//     parallel::For((int64_t)m2, parallel_f);

//     com_pub2.c = cl + com_pub.c * e + cu * ee;
//     com_sec2.t = tl + com_sec.t * e + tu * ee;
//     com_pub = std::move(com_pub2);
//     com_sec = std::move(com_sec2);
//   }

//   static Fr ComputeChallenge(h256_t const& seed, CommitmentPub const& com_pub,
//                              G1 const& cl, G1 const& cu) {
//     // Tick tick(__FN__);
//     CryptoPP::Keccak_256 hash;
//     h256_t digest;
//     HashUpdate(hash, seed);
//     HashUpdate(hash, cl);
//     HashUpdate(hash, cu);
//     HashUpdate(hash, com_pub.a);
//     HashUpdate(hash, com_pub.b);
//     HashUpdate(hash, com_pub.c);
//     hash.Final(digest.data());
//     return H256ToFr(digest);
//   }

//   static void ProveRecursive(Proof& proof, h256_t& seed, ProveInput& input,
//                              CommitmentPub& com_pub, CommitmentSec& com_sec) {
//     Tick tick(__FN__, input.to_string());

//     Fr sigma_xy1, sigma_xy2;
//     ComputeSigmaXY(input, &sigma_xy1, &sigma_xy2);

//     // compute cl, cu
//     Fr tl = FrRand();
//     Fr tu = FrRand();
//     G1 cl = pc::ComputeCom(input.get_g(0), sigma_xy1, tl);
//     G1 cu = pc::ComputeCom(input.get_g(0), sigma_xy2, tu);
//     proof.com_ext_pub.cl.push_back(cl);
//     proof.com_ext_pub.cu.push_back(cu);

//     // challenge
//     Fr e = ComputeChallenge(seed, com_pub, cl, cu);
//     Fr ee = e * e;
//     seed = FrToBin(e);

//     input.Update(sigma_xy1, sigma_xy2, e, ee);

//     UpdateCom(com_pub, com_sec, tl, tu, cl, cu, e, ee);
//     // debug check com_pub2 and com_sec2
// #ifdef _DEBUG
//     CommitmentPub check_com_pub;
//     ComputeCom(input, &check_com_pub, com_sec);
//     assert(check_com_pub.a == com_pub.a);
//     assert(check_com_pub.b == com_pub.b);
//     assert(check_com_pub.c == com_pub.c);
// #endif
//   }

//   static void Prove(Proof& proof, h256_t seed, ProveInput const& _input,
//                     CommitmentPub const& _com_pub, CommitmentSec const& _com_sec) {
//     Tick tick(__FN__, _input.to_string());

//     ProveInput input = _input;
//     CommitmentPub com_pub = _com_pub;
//     CommitmentSec com_sec = _com_sec;

//     if(DEBUG_CHECK){
//       for(int i=0; i<input.m(); i++){
//         assert(pc::ComputeCom(input.get_g, input.x[i], com_sec.r[i]) == com_pub.a[i]);
//         assert(pc::ComputeCom(input.get_g, input.y[i], com_sec.s[i]) == com_pub.b[i]);
//       }
//       assert(pc::ComputeCom(input.get_g(0), input.z, com_sec.t) == com_pub.c);
//     }

//     while (input.m() > 1) {
//       ProveRecursive(proof, seed, input, com_pub, com_sec);
//     }
//     return ProveFinal(proof, seed, input, com_pub, com_sec);
//   }

//   static bool Verify(Proof const& proof, h256_t seed, VerifyInput&& input) {
//     Tick tick(__FN__, input.to_string());

//     input.SortAndAlign();

//     if (!proof.CheckFormat(input.m())) {
//       assert(false);
//       return false;
//     }

//     CommitmentPub& com_pub = input.com_pub;

//     for (size_t loop = 0; loop < proof.com_ext_pub.cl.size(); ++loop) {
//       // challenge
//       auto const& cl = proof.com_ext_pub.cl[loop];
//       auto const& cu = proof.com_ext_pub.cu[loop];
//       Fr e = ComputeChallenge(seed, com_pub, cl, cu);
//       Fr ee = e * e;
//       seed = FrToBin(e);

//       std::vector<G1> a2(com_pub.m() / 2);
//       std::vector<G1> b2(com_pub.m() / 2);
//       G1 c2;

//       auto m2 = com_pub.m() / 2;
//       auto parallel_f = [&com_pub, &a2, &b2, &e](int64_t i) {
//         auto const& a = com_pub.a;
//         a2[i] = a[2 * i] + a[2 * i + 1] * e;

//         auto const& b = com_pub.b;
//         b2[i] = b[2 * i] * e + b[2 * i + 1];
//       };
//       parallel::For(m2, parallel_f, m2 < 1024);

//       c2 = cl * ee + com_pub.c * e + cu;

//       com_pub.a = std::move(a2);
//       com_pub.b = std::move(b2);
//       com_pub.c = std::move(c2);
//     }

//     assert(com_pub.m() == 1);

//     typename Sec51::CommitmentPub com_pub_51(com_pub.a[0], com_pub.b[0],
//                                              com_pub.c);
//     typename Sec51::VerifyInput verifier_input_51(
//         input.t, com_pub_51, input.get_gx, input.get_gy, input.gz);
//     return Sec51::Verify(proof.proof_51, seed, verifier_input_51);
//   }

//  private:
//   static std::vector<size_t> GetSortOrder(std::vector<size_t> const& mn) {
//     std::vector<size_t> order(mn.size());
//     for (size_t i = 0; i < order.size(); ++i) {
//       order[i] = i;
//     }

//     std::stable_sort(order.begin(), order.end(),
//                      [&mn](size_t a, size_t b) { return mn[a] > mn[b]; });

//     return order;
//   }

//   static std::vector<size_t> GetSortOrder(
//       std::vector<std::vector<Fr>> const& data) {
//     std::vector<size_t> mn(data.size());
//     for (size_t i = 0; i < mn.size(); ++i) {
//       mn[i] = data[i].size();
//     }
//     return GetSortOrder(mn);
//   }

//   template <typename T>
//   static void Permute(std::vector<size_t> const& order, std::vector<T>& v) {
//     CHECK(order.size() == v.size(), "");

//     std::vector<T> v2(v.size());
//     for (size_t i = 0; i < order.size(); ++i) {
//       v2[i] = std::move(v[order[i]]);
//     }
//     v.swap(v2);
//   }

//   static void PermuteAndAlign(std::vector<size_t> const& order,
//                               CommitmentPub& v) {
//     Permute(order, v.a);
//     Permute(order, v.b);
//     int64_t old_m = v.a.size();
//     int64_t new_m = (int64_t)misc::Pow2UB(old_m);
//     if (new_m > old_m) {
//       v.a.resize(new_m, G1Zero());
//       v.b.resize(new_m, G1Zero());
//     }
//   }

//   static void PermuteAndAlign(std::vector<size_t> const& order,
//                               CommitmentSec& v) {
//     Permute(order, v.r);
//     Permute(order, v.s);
//     int64_t old_m = v.r.size();
//     int64_t new_m = (int64_t)misc::Pow2UB(old_m);
//     if (new_m > old_m) {
//       v.r.resize(new_m, FrZero());
//       v.s.resize(new_m, FrZero());
//     }
//   }

//   static void PermuteAndAlign(std::vector<size_t> const& order,
//                               std::vector<std::vector<Fr>>& v) {
//     Permute(order, v);
//     int64_t old_m = v.size();
//     int64_t new_m = (int64_t)misc::Pow2UB(old_m);
//     if (new_m > old_m) {
//       v.resize(new_m);
//     }
//   }

//  public:
//   static bool Test(int64_t m, int64_t n);
// };

// bool Sec53c::Test(int64_t m, int64_t n) {
//   Tick tick(__FN__);
//   std::cout << "m=" << m << ", n=" << n << "\n";

//   std::vector<std::vector<Fr>> x(m);
//   for (auto& i : x) {
//     i.resize(n);
//     FrRand(i.data(), n);
//   }

//   std::vector<std::vector<Fr>> y(m);
//   for (auto& i : y) {
//     i.resize(n);
//     FrRand(i.data(), n);
//   }

//   std::vector<Fr> t(n);
//   FrRand(t.data(), t.size());

//   Fr z = FrZero();
//   for (int64_t i = 0; i < m; ++i) {
//     z += InnerProduct(x[i], HadamardProduct(y[i], t));
//   }

//   h256_t seed = misc::RandH256();

//   int64_t g_offset = 220;
//   GetRefG1 get_g = [g_offset](int64_t i) -> G1 const& {
//     return pc::PcG()[g_offset + i];
//   };


//   ProveInput prove_input(x, y, t, z, get_g);
//   CommitmentPub com_pub;
//   CommitmentSec com_sec;
//   ComputeCom(prove_input, &com_pub, &com_sec);

//   Proof proof;
//   auto copy_com_pub = com_pub;
//   Prove(proof, seed, prove_input, com_pub, com_sec);

// #ifndef DISABLE_SERIALIZE_CHECK
//   // serialize to buffer
//   yas::mem_ostream os;
//   yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
//   oa.serialize(proof);
//   std::cout << "proof size: " << os.get_shared_buffer().size << "\n";
//   // serialize from buffer
//   yas::mem_istream is(os.get_intrusive_buffer());
//   yas::binary_iarchive<yas::mem_istream, YasBinF()> ia(is);
//   Proof proof2;
//   ia.serialize(proof2);
//   if (proof != proof2) {
//     assert(false);
//     std::cout << "oops, serialize check failed\n";
//     return false;
//   }

// #endif

//   VerifyInput verify_input(mn, t, std::move(copy_com_pub), get_gx, get_gy,
//                            pc::PcU());
//   bool success = Verify(proof, seed, std::move(verify_input));
//   std::cout << __FILE__ << " " << __FN__ << ": " << success << "\n\n\n\n\n\n";
//   return success;
// }
// }  // namespace groth09