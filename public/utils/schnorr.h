#pragma once

#include "ecc/ecc.h"

namespace schnorr {
struct Sig {
  G1 r;
  Fr s;
  Fr k;

  template <typename Ar>
  void serialize(Ar& ar) const {
    ar& YAS_OBJECT_NVP("Sig.p", ("r", r), ("s", s), ("k", k));
  }
  template <typename Ar>
  void serialize(Ar& ar) {
    ar& YAS_OBJECT_NVP("Sig.p", ("r", r), ("s", s), ("k", k));
  }
};

inline void Sign(G1 const& g, Fr const& sk, std::string const& data, Sig* sig) {
  Tick tick(__FN__);
  sig->k = FrRand();
  sig->r = g * sig->k;
  Fr e = StrHashToFr(sig->r.x.getStr() + data);
  sig->s = sig->k + sk * e;
}

inline void Sign(G1 const& g, Fr const& sk, std::string const& data, Sig* sig1, Sig* sig2) {
  Tick tick(__FN__);
  sig2->r = sig1->r;
  sig2->k = sig1->k;
  Fr e = StrHashToFr(sig2->r.x.getStr() + data);
  sig2->s = sig2->k + sk * e;
}

inline bool Verify(G1 const& g, G1 const& pk, std::string const& data,
                   Sig const& sig) {
  Fr e = StrHashToFr(sig.r.x.getStr() + data);
  return sig.r + pk * e == g * sig.s;  // two times ecc exp
}

Fr extract(G1 const& g, G1 const& pk, Sig const* sig1, Sig const* sig2, std::string const& data1, std::string const& data2) {
  Tick tick(__FN__);
  if(sig1->r != sig2->r){
    std::cout << "r should be same!" << std::endl;
    return 0;
  }
  if(!Verify(g, pk, data1, *sig1) || !Verify(g, pk, data2, *sig2)){
    std::cout << "invalid sig!" << std::endl;
    return 0;
  }
  Fr e1 = StrHashToFr(sig1->r.x.getStr() + data1);
  Fr e2 = StrHashToFr(sig1->r.x.getStr() + data2);
  return (sig1->s - sig2->s) / (e1 - e2);
}

}  // namespace schnorr
