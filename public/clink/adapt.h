#pragma once

#include "argument/argument.h"

// item:
// x: secret vectors
// a: open vectors
// z: open scalar
// open com(x[i])
// prove sum(<x[i],a[i]>)==z

// batch prove several above items

namespace clink {
struct AdaptProveItem {
  std::vector<std::unique_ptr<argument::A4::ProveInput>> in;
  std::vector<std::unique_ptr<argument::A4::CommitmentSec>> sec;

  AdaptProveItem(size_t m){
    in.resize(m);
    sec.resize(m);
  }

  size_t size() const{
    return in.size();
  }
};

struct AdaptVerifyItem {
  std::vector<std::unique_ptr<argument::A4::VerifyInput>> in;

  AdaptVerifyItem(size_t m){
    in.resize(m);
  }

  size_t size() const{
    return in.size();
  }
};

inline h256_t AdaptItemDigest(std::vector<G1> const& cx,
                              std::vector<std::vector<Fr>> const& a,
                              Fr const& z) {
  h256_t digest;
  CryptoPP::Keccak_256 hash;
  for (auto const& i : cx) {
    HashUpdate(hash, i);
  }
  for (auto const& i : a) {
    for (auto const& j : i) {
      HashUpdate(hash, j);
    }
  }
  HashUpdate(hash, z);
  hash.Final(digest.data());
  return digest;
}

inline void AdaptComputeFst(h256_t const& seed, std::vector<Fr>& e) {
  std::string salt = "vgg16 adapt " + std::to_string(e.size());
  ComputeFst(seed, salt, e);
}

inline void AdaptCheck(AdaptProveItem const& prove_item, AdaptVerifyItem const& verify_item){
  assert(prove_item.size() == verify_item.size());
  for(size_t i=0; i<prove_item.size(); i++){
    argument::A4::CheckWitness(*prove_item.in[i], verify_item.in[i]->com_pub, *prove_item.sec[i]);
  }
}

inline void AdaptProve(h256_t seed, AdaptProveItem const& item,
                       argument::A4::Proof& proof) {
  Tick tick(__FN__);
  if (item.size() == 0) return;

  if(DEBUG_CHECK){
    std::cout << "check witness!!!\n";
    for (size_t i=0; i<item.size(); i++) {
      argument::A4::CheckInput(*item.in[i]);
    }
  }

  std::vector<Fr> e(item.size());
  AdaptComputeFst(seed, e);
  
  Fr c = 0;
  std::vector<std::vector<Fr>> a;
  std::vector<std::vector<Fr>> b;

  Fr r_com_c = 0;
  std::vector<Fr> r_com_a;
  for(size_t i=0; i<item.size(); i++){
    a.reserve(a.size() + item.in[i]->a.size());
    a.insert(a.end(), item.in[i]->a.begin(), item.in[i]->a.end());
   
    r_com_a.reserve(a.size() + item.in[i]->a.size());
    r_com_a.insert(r_com_a.end(), item.sec[i]->r_com_a.begin(), item.sec[i]->r_com_a.end());

    std::vector<std::vector<Fr>> d = MatrixMul(item.in[i]->b, e[i]);
    
    b.reserve(b.size() + d.size());
    b.insert(b.end(), d.begin(),d.end());

    c += item.in[i]->c * e[i];
    r_com_c += item.sec[i]->r_com_c * e[i];
  }
    
  argument::A4::ProveInput input(a, b, c, pc::kGetRefG1, pc::kGetRefG1(0));
  argument::A4::CommitmentSec com_sec(r_com_a, r_com_c);
  argument::A4::Prove(proof, seed, input, com_sec);

}

inline bool AdaptVerify(h256_t seed, AdaptVerifyItem const& item,
                        argument::A4::Proof const& proof) {
    Tick tick(__FN__);
  if (item.size() == 0) return false;

  std::vector<Fr> e(item.size());
  AdaptComputeFst(seed, e);
  
  G1 com_c = G1Zero();
  std::vector<G1> com_a;
  std::vector<std::vector<Fr>> b;
  
  for(size_t i=0; i<item.size(); i++){

    std::vector<std::vector<Fr>> d = MatrixMul(item.in[i]->b, e[i]);
    b.reserve(b.size() + d.size());
    b.insert(b.end(), d.begin(),d.end());

    com_a.insert(com_a.end(), item.in[i]->com_pub.com_a.begin(), item.in[i]->com_pub.com_a.end());
    com_c += item.in[i]->com_pub.com_c * e[i];
  }
    
  argument::A4::CommitmentPub com_pub(com_a, com_c);
  argument::A4::VerifyInput input(b, com_pub, pc::kGetRefG1, pc::kGetRefG1(0));
  return argument::A4::Verify(proof, seed, input);
}

}  // namespace clink
